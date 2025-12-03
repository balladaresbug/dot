from __future__ import annotations
import struct
from .utils import rotl, rotr
from .keyschedule import keyschedule
from .sbox import DynamicSBox

MASK64 = 0xFFFFFFFFFFFFFFFF


class DotCipher:
    def __init__(self, key: bytes, rounds: int = 36):
        self.key = key
        self.rounds = rounds
        self.block_size = 32
        self.sbox = DynamicSBox(key)
        self.ks = keyschedule(key, rounds)
        self.rc = self._rot_consts(key)

    def _rot_consts(self, key):
        k0, k1, k2, k3 = struct.unpack(">4Q", key)
        return [
            (k0 % 61) + 5,
            (k1 % 53) + 7,
            (k2 % 47) + 11,
            (k3 % 43) + 13,
        ]

    def _mix(self, x, y, r):
        x = (x + y) & MASK64
        y = rotl(y ^ x, r)
        return x, y

    def _unmix(self, x, y, r):
        y = rotr(y, r) ^ x
        x = (x - y) & MASK64
        return x, y

    def _sr(self, a, b, c, d):
        def rotb(v, n):
            t = [(v >> (8*(7-i))) & 0xFF for i in range(8)]
            t = t[n:] + t[:n]
            o = 0
            for i, bb in enumerate(t):
                o |= bb << (8*(7-i))
            return o
        return rotb(a,1), rotb(b,3), rotb(c,5), rotb(d,7)

    def _sr_inv(self, a, b, c, d):
        def unrotb(v, n):
            t = [(v >> (8*(7-i))) & 0xFF for i in range(8)]
            t = t[-n:] + t[:-n]
            o = 0
            for i, bb in enumerate(t):
                o |= bb << (8*(7-i))
            return o
        return unrotb(a,1), unrotb(b,3), unrotb(c,5), unrotb(d,7)

    def encrypt_block(self, block: bytes):
        a,b,c,d = struct.unpack(">4Q", block)
        rc0,rc1,rc2,rc3 = self.rc

        k0 = self.ks.get_round_key(0)
        a ^= k0[0]; b ^= k0[1]; c ^= k0[2]; d ^= k0[3]

        for r in range(1, self.rounds+1):
            a = self.sbox.apply(a)
            b = self.sbox.apply(b)
            c = self.sbox.apply(c)
            d = self.sbox.apply(d)

            a,b,c,d = self._sr(a,b,c,d)

            a,b = self._mix(a,b,rc0)
            c,d = self._mix(c,d,rc1)
            a,c = self._mix(a,c,rc2)
            b,d = self._mix(b,d,rc3)

            kr = self.ks.get_round_key(r)
            a ^= kr[0]; b ^= kr[1]; c ^= kr[2]; d ^= kr[3]

        return struct.pack(">4Q", a,b,c,d)

    def decrypt_block(self, block: bytes):
        a,b,c,d = struct.unpack(">4Q", block)
        rc0,rc1,rc2,rc3 = self.rc

        for r in reversed(range(1, self.rounds+1)):
            kr = self.ks.get_round_key(r)
            a ^= kr[0]; b ^= kr[1]; c ^= kr[2]; d ^= kr[3]

            b,d = self._unmix(b,d,rc3)
            a,c = self._unmix(a,c,rc2)
            c,d = self._unmix(c,d,rc1)
            a,b = self._unmix(a,b,rc0)

            a,b,c,d = self._sr_inv(a,b,c,d)

            a = self.sbox.inverse(a)
            b = self.sbox.inverse(b)
            c = self.sbox.inverse(c)
            d = self.sbox.inverse(d)

        k0 = self.ks.get_round_key(0)
        a ^= k0[0]; b ^= k0[1]; c ^= k0[2]; d ^= k0[3]

        return struct.pack(">4Q", a,b,c,d)
