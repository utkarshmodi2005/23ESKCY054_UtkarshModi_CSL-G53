"""
crypto_utils.py - All cryptographic building blocks used by the peers.

Project : Authenticated P2P File Sharing (RSA + AES + SHA-256)   [CSL-G53]
Author  : Utkarsh Modi (23ESKCY054)

  RSA-3072 identity keys      who a peer is (long-term, saved encrypted)
  RSA-OAEP (SHA-256)          wraps the random AES session key
  RSA-PSS  (SHA-256)          signs the handshake (mutual authentication)
  HKDF-SHA256                 derives the file key from the session key
  AES-256-GCM                 encrypts every message after the handshake
  SHA-256                     fingerprints keys, hashes whole files
"""

import hashlib
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RSA_BITS = 3072
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

__all__ = ["InvalidSignature", "InvalidTag"]


# ------------------------------------------------------------ identity keys
def new_identity():
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def save_identity(key, path, password):
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.BestAvailableEncryption(password.encode())))


def load_identity(path, password):
    with open(path, "rb") as f:
        try:
            return serialization.load_pem_private_key(f.read(), password.encode())
        except (ValueError, TypeError) as exc:
            raise ValueError("cannot unlock identity key: wrong password?") from exc


def public_pem(public_key):
    return public_key.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)


def load_public_pem(data):
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise ValueError("peer key must be RSA with at least 2048 bits")
    return key


def fingerprint(public_key):
    """First 128 bits of SHA-256 of the public key, e.g. 3F2A:91C0:..."""
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))


# ------------------------------------------------------------ RSA operations
def rsa_wrap(public_key, secret):
    return public_key.encrypt(secret, OAEP)


def rsa_unwrap(private_key, blob):
    return private_key.decrypt(blob, OAEP)


def rsa_sign(private_key, data):
    return private_key.sign(data, PSS, hashes.SHA256())


def rsa_verify(public_key, signature, data):
    """Raises InvalidSignature if the signature does not match."""
    public_key.verify(signature, data, PSS, hashes.SHA256())


# ------------------------------------------------------------ symmetric part
def new_session_secret():
    return os.urandom(32)                     # 256 random bits from the OS


def derive_file_key(secret, transcript_hash):
    """HKDF: turns the exchanged secret into the AES key, bound to this
    exact handshake (the transcript hash is the salt)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=transcript_hash,
                info=b"CSL-G53 file transfer key").derive(secret)


class Channel:
    """AES-256-GCM with a message counter as nonce.

    nonce = 4-byte direction id + 8-byte counter. The counter never
    repeats inside a session and every session has a new key, so a
    (key, nonce) pair is never reused - the one rule GCM must never
    break. The counter and message type are also authenticated (AAD),
    so messages cannot be reordered, replayed or swapped between types
    without detection."""

    def __init__(self, key, direction):
        self.aes = AESGCM(key)
        self.prefix = direction.to_bytes(4, "big")
        self.counter = 0

    def _nonce(self):
        self.counter += 1
        return self.prefix + self.counter.to_bytes(8, "big")

    def seal(self, msg_type, plaintext):
        nonce = self._nonce()
        aad = bytes([msg_type]) + nonce   # authenticated, not secret
        return self.aes.encrypt(nonce, plaintext, aad)

    def open(self, msg_type, ciphertext):
        """Raises InvalidTag if a single bit was changed."""
        nonce = self._nonce()
        aad = bytes([msg_type]) + nonce
        return self.aes.decrypt(nonce, ciphertext, aad)


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()
