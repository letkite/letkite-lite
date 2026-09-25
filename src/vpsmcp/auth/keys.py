"""RS256 signing key, JWKS, and scrypt password hashing."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class KeyStore:
    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = data_dir / "oauth_signing_key.pem"
        self.cookie_key_path = data_dir / "cookie.key"
        self._private = self._load_or_create()
        self._public = self._private.public_key()
        self.kid = self._compute_kid()
        self.cookie_key = self._load_or_create_cookie_key()

    def _load_or_create(self):
        if self.key_path.exists():
            return serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.key_path.write_bytes(pem)
        os.chmod(self.key_path, 0o600)
        return key

    def _load_or_create_cookie_key(self) -> bytes:
        if self.cookie_key_path.exists():
            return self.cookie_key_path.read_bytes()
        k = secrets.token_bytes(32)
        self.cookie_key_path.write_bytes(k)
        os.chmod(self.cookie_key_path, 0o600)
        return k

    @property
    def private_pem(self) -> str:
        return self._private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    @property
    def public_pem(self) -> str:
        return self._public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def _compute_kid(self) -> str:
        n = self._public.public_numbers()
        thumb = {"e": _b64u(n.e.to_bytes((n.e.bit_length() + 7) // 8, "big")),
                 "kty": "RSA",
                 "n": _b64u(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big"))}
        digest = hashlib.sha256(json.dumps(thumb, separators=(",", ":"), sort_keys=True).encode())
        return _b64u(digest.digest())[:16]

    def jwks(self) -> dict:
        n = self._public.public_numbers()
        return {"keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
            "n": _b64u(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")),
            "e": _b64u(n.e.to_bytes((n.e.bit_length() + 7) // 8, "big")),
        }]}


# ---------- admin password: scrypt, stdlib only ----------
_MAXMEM = 128 * 1024 * 1024  # OpenSSL default limit is too small

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1,
                        dklen=32, maxmem=_MAXMEM)
    return f"scrypt$32768$8$1${_b64u(salt)}${_b64u(dk)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, n, r, p, salt_b64, dk_b64 = encoded.split("$")
        if algo != "scrypt":
            return False
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        salt = base64.urlsafe_b64decode(pad(salt_b64))
        expect = base64.urlsafe_b64decode(pad(dk_b64))
        dk = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p),
                            dklen=len(expect), maxmem=_MAXMEM)
        return hmac.compare_digest(dk, expect)
    except Exception:  # noqa: BLE001
        return False
