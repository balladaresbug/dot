from __future__ import annotations
import hashlib
import secrets
from typing import Optional


class DotKeyDerivation:
    @staticmethod
    def derive_key(
        password: bytes,
        salt: Optional[bytes] = None,
        iterations: int = 310_000,
        key_len: int = 32,
    ) -> bytes:
        if salt is None:
            salt = secrets.token_bytes(16)
        if len(salt) != 16:
            raise ValueError("Salt must be exactly 16 bytes")

        key = hashlib.pbkdf2_hmac(
            "sha512",
            password,
            salt,
            iterations,
            key_len,
        )
        return salt + key

    @staticmethod
    def generate_key() -> bytes:
        return secrets.token_bytes(32)
