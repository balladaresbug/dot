from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Dict, Type

from .core import DotCipher
from .modes import (
    CipherMode,
    DotModeOfOperationECB,
    DotModeOfOperationCBC,
    DotModeOfOperationCTR,
    DotModeOfOperationGCM,
)
from .kdf import DotKeyDerivation


@dataclass
class DotEncryptionResult:
    ciphertext: bytes
    iv_nonce: Optional[bytes] = None
    tag: Optional[bytes] = None
    mode: str = "ECB"


class DotEncrypter:
    MODES: Dict[str, Type[CipherMode]] = {
        "ECB": DotModeOfOperationECB,
        "CBC": DotModeOfOperationCBC,
        "CTR": DotModeOfOperationCTR,
        "GCM": DotModeOfOperationGCM,
    }

    def __init__(self, key: Optional[bytes] = None, mode: str = "CBC"):
        self.key = key or DotKeyDerivation.generate_key()
        self.salt: Optional[bytes] = None
        self.mode_name = mode if mode in self.MODES else "CBC"
        self.cipher = DotCipher(self.key)
        self.mode: CipherMode = self.MODES[self.mode_name](self.cipher)

    @classmethod
    def from_password(cls, password: str, salt: Optional[bytes] = None, mode: str = "CBC"):
        derived = DotKeyDerivation.derive_key(password.encode(), salt)
        salt_bytes, key = derived[:16], derived[16:]
        inst = cls(key, mode)
        inst.salt = salt_bytes
        return inst

    def encrypt(self, plaintext: bytes, **kwargs) -> DotEncryptionResult:
        mode = self.mode_name

        if mode == "GCM":
            aad = kwargs.get("aad", b"")
            ct, tag, nonce = self.mode.encrypt(plaintext, aad)
            return DotEncryptionResult(ciphertext=ct, tag=tag, iv_nonce=nonce, mode=mode)

        if mode == "CTR":
            ct = self.mode.encrypt(plaintext)
            return DotEncryptionResult(ciphertext=ct, iv_nonce=self.mode.nonce, mode=mode)

        if mode == "CBC":
            ct = self.mode.encrypt(plaintext)
            return DotEncryptionResult(ciphertext=ct, iv_nonce=self.mode.iv, mode=mode)

        ct = self.mode.encrypt(plaintext)
        return DotEncryptionResult(ciphertext=ct, mode=mode)

    def decrypt(self, result: DotEncryptionResult, **kwargs) -> bytes:
        mode_class = self.MODES.get(result.mode, self.MODES["CBC"])

        if mode_class is DotModeOfOperationGCM:
            aad = kwargs.get("aad", b"")
            m = mode_class(self.cipher)
            return m.decrypt(result.ciphertext, result.tag, result.iv_nonce, aad)

        if mode_class is DotModeOfOperationCTR:
            m = mode_class(self.cipher, result.iv_nonce)
            return m.decrypt(result.ciphertext)

        if mode_class is DotModeOfOperationCBC:
            m = mode_class(self.cipher, result.iv_nonce)
            return m.decrypt(result.ciphertext)

        m = mode_class(self.cipher)
        return m.decrypt(result.ciphertext)

    def encrypt_file(self, input_path: str, output_path: str, **kwargs) -> None:
        with open(input_path, "rb") as f:
            plaintext = f.read()

        result = self.encrypt(plaintext, **kwargs)

        with open(output_path, "wb") as f:
            mode_b = self.mode_name.encode()
            f.write(struct.pack("B", len(mode_b)))
            f.write(mode_b)

            if result.iv_nonce:
                f.write(struct.pack(">H", len(result.iv_nonce)))
                f.write(result.iv_nonce)
            else:
                f.write(struct.pack(">H", 0))

            if result.tag:
                f.write(struct.pack(">H", len(result.tag)))
                f.write(result.tag)
            else:
                f.write(struct.pack(">H", 0))

            f.write(result.ciphertext)

    def decrypt_file(self, input_path: str, output_path: str, **kwargs) -> None:
        with open(input_path, "rb") as f:
            name_len_data = f.read(1)
            if not name_len_data:
                with open(output_path, "wb") as o:
                    o.write(b"")
                return

            name_len = struct.unpack("B", name_len_data)[0]
            mode = f.read(name_len).decode()

            iv_len = struct.unpack(">H", f.read(2))[0]
            iv_nonce = f.read(iv_len) if iv_len else None

            tag_len = struct.unpack(">H", f.read(2))[0]
            tag = f.read(tag_len) if tag_len else None

            ciphertext = f.read()

        result = DotEncryptionResult(
            ciphertext=ciphertext,
            iv_nonce=iv_nonce,
            tag=tag,
            mode=mode,
        )

        plaintext = self.decrypt(result, **kwargs)

        with open(output_path, "wb") as f:
            f.write(plaintext)
