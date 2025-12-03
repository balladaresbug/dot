from __future__ import annotations
import struct, hashlib
from .utils import rotl

MASK64 = 0xFFFFFFFFFFFFFFFF

class keyschedule:
    def __init__(self, master_key: bytes, rounds: int):
        self.rounds = rounds
        self.subkeys, self.rc = self._expand(master_key)

    def _expand(self, mk: bytes):
        k0, k1, k2, k3 = struct.unpack(">4Q", mk)

        seed = hashlib.blake2b(mk, digest_size=32).digest()
        prng = hashlib.sha3_256(seed).digest()

        rc = []
        subkeys = []

        for r in range(self.rounds + 1):

            subkeys.append([k0, k1, k2, k3])

            if r == self.rounds:
                break

            prng = hashlib.sha3_256(prng).digest()

            rc_r = struct.unpack(">Q", prng[:8])[0] ^ r
            rc.append(rc_r & MASK64)

            w0 = (k0 + rotl(k1, 17) + rc_r) & MASK64
            w1 = (k1 + rotl(k2, 41) + rc_r) & MASK64
            w2 = (k2 + rotl(k3, 23) + rc_r) & MASK64
            w3 = (k3 + rotl(w0, 31) + rc_r) & MASK64

            k0 = rotl(w2 ^ w1, 13)
            k1 = rotl(w3 ^ w2, 29)
            k2 = rotl(w0 ^ w3, 47)
            k3 = rotl(w1 ^ w0, 59)

            k0, k1, k2, k3 = k2, k0, k3, k1

        return subkeys, rc

    def get_round_key(self, r: int):
        return self.subkeys[r]
