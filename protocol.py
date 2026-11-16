"""
protocol.py - Message framing, the list of trusted peers, and the
authenticated handshake.

Every message on the TCP connection is a frame:
    4 bytes length (big-endian) | 1 byte type | body

Handshake (C = peer that sends files, S = peer that receives):

  1. C -> S  HELLO   {name_C, public key C, nonce_C (32 random bytes)}
  2. S -> C  HELLO   {name_S, public key S, nonce_S}
     Both sides check the other's key fingerprint against trusted peers.
  3. C: picks a random 256-bit secret K
        ek  = RSA-OAEP(public key S, K)        only S can open it
        T   = SHA-256(hello_C | hello_S | ek)  transcript of the handshake
        C -> S  KEYX {ek, sig_C = RSA-PSS(private key C, "C" | T)}
  4. S: verifies sig_C with C's key (C is authentic, and T contains the
        fresh nonce_S, so an old recorded handshake cannot be replayed),
        opens K, and replies
        S -> C  KEYX_OK {sig_S = RSA-PSS(private key S, "S" | T),
                         confirm = AES-GCM(key, "KEY-CONFIRM")}
  5. C: verifies sig_S (S is authentic) and decrypts confirm (S really
        holds K). Both use key = HKDF(K, salt = T) from now on.
"""

import hashlib
import json
import os
import socket
import struct

import crypto_utils as cu

HELLO, KEYX, KEYX_OK, FILE_META, CHUNK, FILE_END, RESULT, BYE, ERROR = range(1, 10)
MAX_FRAME = 1 << 20          # 1 MB: refuse bigger frames (memory protection)
TO_RECEIVER, TO_SENDER = 1, 2


class ProtocolError(Exception):
    pass


class TrustError(ProtocolError):
    pass


# ---------------------------------------------------------------- framing
def send_frame(sock, msg_type, body):
    sock.sendall(struct.pack("!IB", len(body) + 1, msg_type) + body)


def _recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise ProtocolError("connection closed by peer")
        data += part
    return bytes(data)


def recv_frame(sock, expected=None):
    (length,) = struct.unpack("!I", _recv_exact(sock, 4))
    if not 1 <= length <= MAX_FRAME:
        raise ProtocolError(f"bad frame length {length}")
    body = _recv_exact(sock, length)
    msg_type, body = body[0], body[1:]
    if msg_type == ERROR:
        raise ProtocolError("peer reported: " + body.decode(errors="replace"))
    if expected is not None and msg_type != expected:
        raise ProtocolError(f"expected message type {expected}, got {msg_type}")
    return msg_type, body


def send_json(sock, msg_type, obj):
    send_frame(sock, msg_type, json.dumps(obj).encode())


# ------------------------------------------------------------ trusted peers
class TrustStore:
    """known_peers.json: {peer name: fingerprint}. Like SSH's known_hosts:
    the first time a peer is seen its fingerprint is confirmed by the user;
    later, a different key under the same name is refused (possible MITM)."""

    def __init__(self, path, accept_new=None):
        self.path = path
        self.accept_new = accept_new          # function(name, fp) -> bool
        self.peers = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.peers = json.load(f)

    def add(self, name, fp):
        self.peers[name] = fp
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.peers, f, indent=2)

    def check(self, name, public_key):
        fp = cu.fingerprint(public_key)
        known = self.peers.get(name)
        if known == fp:
            return fp
        if known is not None:
            raise TrustError(f"KEY CHANGED for '{name}': expected {known}, "
                             f"got {fp}. Possible man-in-the-middle - "
                             "connection refused.")
        if self.accept_new and self.accept_new(name, fp):
            self.add(name, fp)
            return fp
        raise TrustError(f"unknown peer '{name}' ({fp}) not accepted")


# ---------------------------------------------------------------- handshake
class Session:
    def __init__(self, peer_name, peer_fp, key, i_am_sender):
        self.peer_name, self.peer_fp = peer_name, peer_fp
        out_dir, in_dir = (TO_RECEIVER, TO_SENDER) if i_am_sender else (TO_SENDER, TO_RECEIVER)
        self.tx = cu.Channel(key, out_dir)     # messages I send
        self.rx = cu.Channel(key, in_dir)      # messages I receive


def _hello(name, identity):
    return json.dumps({"name": name, "public_key": cu.public_pem(identity.public_key()).decode(),
                       "nonce": os.urandom(32).hex()}).encode()


def _parse_hello(body):
    try:
        h = json.loads(body)
        return h["name"], cu.load_public_pem(h["public_key"].encode())
    except (ValueError, KeyError, TypeError) as exc:
        raise ProtocolError(f"bad HELLO: {exc}") from exc


def client_handshake(sock, name, identity, trust):
    my_hello = _hello(name, identity)
    send_frame(sock, HELLO, my_hello)
    _, peer_hello = recv_frame(sock, HELLO)
    peer_name, peer_key = _parse_hello(peer_hello)
    peer_fp = trust.check(peer_name, peer_key)

    secret = cu.new_session_secret()
    ek = cu.rsa_wrap(peer_key, secret)
    t = hashlib.sha256(my_hello + peer_hello + ek).digest()
    sig = cu.rsa_sign(identity, b"C" + t)
    send_json(sock, KEYX, {"ek": ek.hex(), "sig": sig.hex()})

    _, body = recv_frame(sock, KEYX_OK)
    reply = json.loads(body)
    try:
        cu.rsa_verify(peer_key, bytes.fromhex(reply["sig"]), b"S" + t)
    except cu.InvalidSignature as exc:
        raise ProtocolError("receiver's handshake signature "
                            "is invalid") from exc
    key = cu.derive_file_key(secret, t)
    session = Session(peer_name, peer_fp, key, i_am_sender=True)
    confirm = bytes.fromhex(reply["confirm"])
    if session.rx.open(KEYX_OK, confirm) != b"KEY-CONFIRM":
        raise ProtocolError("key confirmation failed")
    return session


def server_handshake(sock, name, identity, trust):
    _, peer_hello = recv_frame(sock, HELLO)
    peer_name, peer_key = _parse_hello(peer_hello)
    my_hello = _hello(name, identity)
    send_frame(sock, HELLO, my_hello)
    peer_fp = trust.check(peer_name, peer_key)

    _, body = recv_frame(sock, KEYX)
    keyx = json.loads(body)
    ek = bytes.fromhex(keyx["ek"])
    t = hashlib.sha256(peer_hello + my_hello + ek).digest()
    try:
        cu.rsa_verify(peer_key, bytes.fromhex(keyx["sig"]), b"C" + t)
    except cu.InvalidSignature as exc:
        raise ProtocolError("sender's handshake signature is invalid "
                            "(forged or replayed handshake)") from exc
    secret = cu.rsa_unwrap(identity, ek)
    key = cu.derive_file_key(secret, t)
    session = Session(peer_name, peer_fp, key, i_am_sender=False)
    confirm = session.tx.seal(KEYX_OK, b"KEY-CONFIRM")
    sig = cu.rsa_sign(identity, b"S" + t)
    send_json(sock, KEYX_OK,
              {"sig": sig.hex(), "confirm": confirm.hex()})
    return session


def connect(host, port, timeout=10):
    return socket.create_connection((host, port), timeout=timeout)
