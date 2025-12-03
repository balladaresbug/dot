from __future__ import annotations
from typing import Final

WORD_BITS: Final[int] = 64
WORD_MASK: Final[int] = (1 << WORD_BITS) - 1

def rotl(x: int, n: int, bits: int = WORD_BITS) -> int:
    n &= bits - 1
    return ((x & WORD_MASK) << n | (x & WORD_MASK) >> (bits - n)) & WORD_MASK

def rotr(x: int, n: int, bits: int = WORD_BITS) -> int:
    n &= bits - 1
    return ((x & WORD_MASK) >> n | (x & WORD_MASK) << (bits - n)) & WORD_MASK
