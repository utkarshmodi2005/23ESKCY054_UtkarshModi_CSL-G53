"""
transfer.py - Sending and receiving files over an authenticated session.

  FILE_META  encrypted {name, size, sha256, chunk_size}
  CHUNK      encrypted file data, 64 KB per message
  FILE_END   encrypted {chunks: count}
  RESULT     encrypted {ok, sha256, saved_as}   (receiver -> sender)

Every message is sealed with AES-256-GCM (crypto_utils.Channel), so a
single changed bit stops the transfer. After the last chunk the receiver
also compares the SHA-256 of the whole saved file with the sender's hash,
and keeps the file only if they are equal.
"""

import json
import os
import time

import crypto_utils as cu
from protocol import (BYE, CHUNK, ERROR, FILE_END, FILE_META, RESULT, ProtocolError,
                      recv_frame, send_frame)

CHUNK_SIZE = 64 * 1024


def _send(sock, session, msg_type, data):
    send_frame(sock, msg_type, session.tx.seal(msg_type, data))


def _recv(sock, session, expected=None):
    msg_type, body = recv_frame(sock)
    if expected is not None and msg_type != expected:
        raise ProtocolError(f"expected message type {expected}, got {msg_type}")
    try:
        return msg_type, session.rx.open(msg_type, body)
    except cu.InvalidTag as exc:
        raise ProtocolError("message failed AES-GCM authentication "
                            "(data was modified in transit)") from exc


# -------------------------------------------------------------------- send
def send_file(sock, session, path, progress=None):
    size = os.path.getsize(path)
    digest = cu.sha256_file(path)
    meta = {"name": os.path.basename(path), "size": size, "sha256": digest,
            "chunk_size": CHUNK_SIZE}
    _send(sock, session, FILE_META, json.dumps(meta).encode())
    sent = chunks = 0
    t0 = time.perf_counter()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(CHUNK_SIZE), b""):
                _send(sock, session, CHUNK, block)
                sent += len(block)
                chunks += 1
                if progress:
                    progress(sent, size)
        _send(sock, session, FILE_END, json.dumps({"chunks": chunks}).encode())
    except OSError:
        # The receiver closed the connection. If it sent a reason first,
        # recv_frame raises ProtocolError("peer reported: ...") with it.
        sock.settimeout(2)
        recv_frame(sock)
        raise
    _, body = _recv(sock, session, RESULT)
    result = json.loads(body)
    result.update(seconds=time.perf_counter() - t0, size=size, local_sha256=digest)
    return result


def say_bye(sock, session):
    _send(sock, session, BYE, b"")


# ----------------------------------------------------------------- receive
def safe_name(name, folder):
    """Never trust a file name from the network: keep only the last path
    part (blocks "../../etc/passwd" tricks); never overwrite a file."""
    name = name.replace("\\", "/")             # Windows-style paths too
    base = os.path.basename(name).strip() or "received_file"
    if base in (".", ".."):
        base = "received_file"
    stem, ext = os.path.splitext(base)
    candidate, n = base, 1
    while os.path.exists(os.path.join(folder, candidate)):
        candidate = f"{stem}({n}){ext}"
        n += 1
    return os.path.join(folder, candidate)


def receive_files(sock, session, folder, progress=None, log=print):
    """Receive files until the sender says BYE; return the results."""
    os.makedirs(folder, exist_ok=True)
    results = []
    while True:
        msg_type, body = _recv(sock, session)
        if msg_type == BYE:
            return results
        if msg_type != FILE_META:
            raise ProtocolError(f"unexpected message type {msg_type}")
        meta = json.loads(body)
        final_path = safe_name(meta["name"], folder)
        tmp_path = final_path + ".part"
        received = chunks = 0
        try:
            with open(tmp_path, "wb") as out:
                while True:
                    msg_type, data = _recv(sock, session)
                    if msg_type == FILE_END:
                        break
                    if msg_type != CHUNK:
                        raise ProtocolError(f"bad type {msg_type}")
                    received += len(data)
                    chunks += 1
                    if received > meta["size"]:
                        raise ProtocolError("more data than announced")
                    out.write(data)
                    if progress:
                        progress(received, meta["size"])
            end = json.loads(data)
            actual = cu.sha256_file(tmp_path)
            ok = (actual == meta["sha256"] and received == meta["size"]
                  and end.get("chunks") == chunks)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)        # never leave half a file
            raise
        if ok:
            os.replace(tmp_path, final_path)
        else:
            os.remove(tmp_path)
        saved = os.path.basename(final_path) if ok else None
        result = {"ok": ok, "name": meta["name"], "saved_as": saved,
                  "sha256": actual, "expected": meta["sha256"],
                  "size": received}
        _send(sock, session, RESULT, json.dumps(result).encode())
        verdict = "matches" if ok else "MISMATCH"
        where = f"saved as {saved}" if ok else "deleted"
        tag = "OK  " if ok else "FAIL"
        log(f"{tag} {meta['name']} ({received:,} bytes) "
            f"SHA-256 {verdict} -> {where}")
        results.append(result)


def send_error(sock, text):
    try:
        send_frame(sock, ERROR, text.encode()[:500])
    except OSError:
        pass
