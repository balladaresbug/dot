from __future__ import annotations
import struct, secrets, hashlib
from typing import Optional, Tuple
from .core import DotCipher
from .utils import rotl, rotr
from .utils import WORD_MASK

def _constant_time_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0

class CipherMode:
    def __init__(self, cipher: DotCipher):
        self.cipher = cipher
    def encrypt(self, plaintext: bytes):
        raise NotImplementedError
    def decrypt(self, ciphertext: bytes):
        raise NotImplementedError

class DotModeOfOperationECB(CipherMode):
    def encrypt(self, plaintext: bytes) -> bytes:
        bs = self.cipher.block_size
        pad = bs - (len(plaintext) % bs)
        p = plaintext + bytes([pad]) * pad
        out = bytearray()
        for i in range(0, len(p), bs):
            out.extend(self.cipher.encrypt_block(p[i:i+bs]))
        return bytes(out)
    def decrypt(self, ciphertext: bytes) -> bytes:
        bs = self.cipher.block_size
        if len(ciphertext) % bs:
            raise ValueError("Ciphertext is not aligned to the block size")
        out = bytearray()
        for i in range(0, len(ciphertext), bs):
            out.extend(self.cipher.decrypt_block(ciphertext[i:i+bs]))
        pad = out[-1]
        if pad == 0 or pad > bs:
            raise ValueError("Invalid padding")
        if any(b != pad for b in out[-pad:]):
            raise ValueError("Invalid padding")
        return bytes(out[:-pad])

class DotModeOfOperationCBC(CipherMode):
    def __init__(self, cipher: DotCipher, iv: Optional[bytes] = None):
        super().__init__(cipher)
        self.bs = cipher.block_size
        self.iv = iv or secrets.token_bytes(self.bs)
        if len(self.iv) != self.bs:
            raise ValueError("IV must match block size")
    def encrypt(self, plaintext: bytes) -> bytes:
        bs = self.bs
        pad = bs - (len(plaintext) % bs)
        p = plaintext + bytes([pad]) * pad
        prev = self.iv
        out = bytearray()
        for i in range(0, len(p), bs):
            x = bytes(a ^ b for a, b in zip(p[i:i+bs], prev))
            enc = self.cipher.encrypt_block(x)
            out.extend(enc)
            prev = enc
        return bytes(out)
    def decrypt(self, ciphertext: bytes, iv=None) -> bytes:
        prev = iv or self.iv
        bs = self.bs
        if len(prev) != bs:
            raise ValueError("IV must match block size")
        if len(ciphertext) % bs:
            raise ValueError("Ciphertext is not aligned to the block size")
        out = bytearray()
        for i in range(0, len(ciphertext), bs):
            dec = self.cipher.decrypt_block(ciphertext[i:i+bs])
            out.extend(bytes(a ^ b for a, b in zip(dec, prev)))
            prev = ciphertext[i:i+bs]
        pad = out[-1]
        if pad == 0 or pad > bs:
            raise ValueError("Invalid padding")
        if any(b != pad for b in out[-pad:]):
            raise ValueError("Invalid padding")
        return bytes(out[:-pad])

class DotModeOfOperationCTR(CipherMode):
    def __init__(self, cipher: DotCipher, nonce: Optional[bytes] = None):
        super().__init__(cipher)
        self.bs = cipher.block_size
        self.nonce_size = 12
        self.nonce = nonce
        if self.nonce is not None and len(self.nonce) != self.nonce_size:
            raise ValueError("Nonce must be 12 bytes for CTR mode")

    def _get_nonce(self) -> bytes:
        if self.nonce is None:
            self.nonce = secrets.token_bytes(self.nonce_size)
        return self.nonce

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        out = bytearray()
        ctr = 0
        while len(out) < length:
            block = nonce + struct.pack(">I", ctr)
            block = block.ljust(self.bs, b"\x00")
            ks = self.cipher.encrypt_block(block)
            out.extend(ks)
            ctr += 1
        return bytes(out[:length])
    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = self._get_nonce()
        ks = self._keystream(nonce, len(plaintext))
        return nonce + bytes(a ^ b for a, b in zip(plaintext, ks))
    def decrypt(self, ciphertext: bytes) -> bytes:
        prefix_available = len(ciphertext) >= self.nonce_size
        if self.nonce is None:
            if not prefix_available:
                raise ValueError("Ciphertext is too short to contain a nonce prefix")
            nonce = ciphertext[:self.nonce_size]
            data = ciphertext[self.nonce_size:]
        else:
            if prefix_available and ciphertext.startswith(self.nonce):
                data = ciphertext[self.nonce_size:]
            else:
                data = ciphertext
            nonce = self.nonce

        ks = self._keystream(nonce, len(data))
        return bytes(a ^ b for a, b in zip(data, ks))

class GF128:
    @staticmethod
    def multiply(x: int, y: int) -> int:
        r = 0
        for _ in range(128):
            if y & 1:
                r ^= x
            msb = x & (1 << 127)
            x = (x << 1) & ((1 << 128) - 1)
            if msb:
                x ^= 0xE1000000000000000000000000000000
            y >>= 1
        return r
    @staticmethod
    def to_int(b: bytes) -> int:
        return int.from_bytes(b, "big")
    @staticmethod
    def to_bytes(x: int) -> bytes:
        return x.to_bytes(16, "big")

class DotModeOfOperationGCM(CipherMode):
    def __init__(self, cipher: DotCipher):
        super().__init__(cipher)
        self.bs = cipher.block_size
        self.iv_size = 12

    def _auth_tag(self, nonce: bytes, H: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        ghash = self._ghash(H, aad, ciphertext)
        j0 = (nonce + struct.pack(">I", 1)).ljust(self.bs, b"\x00")
        s = self.cipher.encrypt_block(j0)[:16]
        return bytes(a ^ b for a, b in zip(ghash, s))

    def _ctr(self, nonce, data):
        out = bytearray()
        # Start the counter at 2 per GCM spec to avoid reusing the block that
        # is reserved for authentication tag masking (J0).
        ctr = 2
        pos = 0
        while pos < len(data):
            block = nonce + struct.pack(">I", ctr)
            block = block.ljust(self.bs, b"\x00")
            ks = self.cipher.encrypt_block(block)
            take = min(len(data)-pos, len(ks))
            for i in range(take):
                out.append(data[pos+i] ^ ks[i])
            pos += take
            ctr += 1
        return bytes(out)

    def _ghash(self, H, aad, ciphertext):
        h = GF128.to_int(H)
        y = 0

        def blk(proc):
            nonlocal y
            for i in range(0, len(proc), 16):
                block = proc[i:i+16].ljust(16, b"\x00")
                y ^= GF128.to_int(block)
                y = GF128.multiply(y, h)

        blk(aad)
        blk(ciphertext)
        lens = struct.pack(">QQ", len(aad)*8, len(ciphertext)*8)
        y ^= GF128.to_int(lens)
        y = GF128.multiply(y, h)
        return GF128.to_bytes(y)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
        nonce = secrets.token_bytes(self.iv_size)
        H = self.cipher.encrypt_block(b"\x00"*self.bs)[:16]
        ciphertext = self._ctr(nonce, plaintext)
        tag = self._auth_tag(nonce, H, aad, ciphertext)
        return ciphertext, tag, nonce

    def decrypt(self, ciphertext: bytes, tag: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        if len(nonce) != self.iv_size:
            raise ValueError("Nonce must be 12 bytes for GCM mode")
        if len(tag) != 16:
            raise ValueError("Authentication tag must be 16 bytes")
        H = self.cipher.encrypt_block(b"\x00"*self.bs)[:16]
        expected = self._auth_tag(nonce, H, aad, ciphertext)
        if not _constant_time_compare(expected, tag):
            raise ValueError("Authentication tag mismatch")
        return self._ctr(nonce, ciphertext)
