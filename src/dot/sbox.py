from __future__ import annotations
import hashlib
from typing import List, Tuple


class DynamicSBox:
    def __init__(self, key: bytes):
        self.key = key
        self.sbox, self.inv_sbox = self._gen()

    def _stream(self, seed: bytes, length: int) -> bytes:
        out = bytearray()
        st = seed
        while len(out) < length:
            st = hashlib.sha3_512(st).digest()
            out.extend(st)
        return bytes(out[:length])

    def _perm(self, base: List[int], rnd: bytes) -> List[int]:
        s = base[:]
        for i in range(255, 0, -1):
            j = rnd[i] ^ rnd[255 - i]
            j %= (i + 1)
            s[i], s[j] = s[j], s[i]
        return s

    def _scramble(self, s: List[int], rnd: bytes) -> List[int]:
        out = s[:]
        for i in range(256):
            k = rnd[i] + i
            out[i] = s[k % 256]
        return out

    def _shake_mix(self, key: bytes) -> bytes:
        shake = hashlib.shake_256()
        shake.update(key)
        return shake.digest(256)

    def _gen(self) -> Tuple[List[int], List[int]]:
        seed = hashlib.blake2b(self.key, digest_size=32).digest()
        rnd1 = self._stream(seed, 256)
        rnd2 = self._shake_mix(seed)
        base = list(range(256))
        p1 = self._perm(base, rnd1)
        p2 = self._perm(p1, rnd2)

        sbox = p2[:]
        inv = [0]*256
        for i, v in enumerate(sbox):
            inv[v] = i
        return sbox, inv

    def apply(self, data: int, bits: int = 64) -> int:
        out = 0
        for i in range(bits//8):
            b = (data >> (8*(7-i))) & 0xFF
            out = (out << 8) | self.sbox[b]
        return out

    def inverse(self, data: int, bits: int = 64) -> int:
        out = 0
        for i in range(bits//8):
            b = (data >> (8*(7-i))) & 0xFF
            out = (out << 8) | self.inv_sbox[b]
        return out
