#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Lempel-Ziv-Stac (LZS) decompression used by ZynOS / RomPager router firmware.

Adapted from RouterSploit (Filippo Valsorda, GPL-3.0).
"""

import collections
from typing import Tuple, Union


class BitReader:
    """Extract bits from a byte stream one at a time."""

    def __init__(self, data_bytes: Union[bytes, bytearray]):
        self._bits = collections.deque()

        for byte in data_bytes:
            for n in range(8):
                self._bits.append(bool((byte >> (7 - n)) & 1))

    def getBit(self) -> bool:
        return self._bits.popleft()

    def getBits(self, num: int) -> int:
        res = 0
        for i in range(num):
            res += self.getBit() << num - 1 - i
        return res

    def getByte(self) -> int:
        return self.getBits(8)

    def __len__(self) -> int:
        return len(self._bits)


class RingList:
    """Fixed-size sliding window for LZS back-references."""

    def __init__(self, length: int):
        self.__data__ = collections.deque()
        self.__full__ = False
        self.__max__ = length

    def append(self, x: int) -> None:
        if self.__full__:
            self.__data__.popleft()
        self.__data__.append(x)
        if self.size() == self.__max__:
            self.__full__ = True

    def get(self):
        return self.__data__

    def size(self) -> int:
        return len(self.__data__)

    def maxsize(self) -> int:
        return self.__max__

    def __getitem__(self, n: int):
        if n >= self.size():
            return None
        return self.__data__[n]


def LZSDecompress(data: Union[bytes, bytearray], window: RingList = None) -> Tuple[str, RingList]:
    """
    Decompress an LZS chunk and return the plaintext plus the final dictionary window.
    """
    if window is None:
        window = RingList(2048)

    reader = BitReader(data)
    result = ""

    while True:
        bit = reader.getBit()
        if not bit:
            char = reader.getByte()
            result += chr(char)
            window.append(char)
        else:
            bit = reader.getBit()
            if bit:
                offset = reader.getBits(7)
                if offset == 0:
                    break
            else:
                offset = reader.getBits(11)

            lenField = reader.getBits(2)
            if lenField < 3:
                length = lenField + 2
            else:
                lenField <<= 2
                lenField += reader.getBits(2)
                if lenField < 15:
                    length = (lenField & 0x0F) + 5
                else:
                    lenCounter = 0
                    lenField = reader.getBits(4)
                    while lenField == 15:
                        lenField = reader.getBits(4)
                        lenCounter += 1
                    length = 15 * lenCounter + 8 + lenField

            for _ in range(length):
                char = window[-offset]
                result += chr(char)
                window.append(char)

    return result, window
