"""Empty-password PDF encryption (DRM-style) for static-analysis evasion.

Pure-Python RC4-128 implementation with optional ``pypdf`` acceleration for
structured documents. No system binaries (qpdf, ghostscript, etc.) are invoked.

Encrypts strings and streams with an empty user password so viewers open without
prompting while static tools (pdf-parser, naive grep/YARA) see ciphertext only.

Ref: Didier Stevens — https://blog.didierstevens.com/2008/04/29/pdf-let-me-count-the-ways/
"""

from __future__ import annotations

import hashlib
import io
import re
import secrets
import struct
from pathlib import Path
from typing import Optional, Tuple

_PADDING = (
    b"\x28\xbf\x4e\x5e\x4e\x75\x8a\x41\x64\x00\x4e\x56\xff\xfa\x01\x08"
    b"\x2e\x2e\x00\xb6\xd0\x68\x3e\x80\x2f\x0c\xa9\xfe\x64\x53\x69\x7a"
)

_P_FLAGS = -4
_REV = 3
_V = 2
_KEY_BITS = 128
_OWNER_PASSWORD = b"KittySploit"

_OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")
_HEX_STRING_RE = re.compile(rb"<([0-9A-Fa-f ]+)>")


def _padding(password: bytes) -> bytes:
    if not password:
        return _PADDING
    return (password + _PADDING)[:32]


def _rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out[n] = byte ^ s[(s[i] + s[j]) % 256]
    return bytes(out)


def _compute_o_value_key(owner_password: bytes, key_len: int) -> bytes:
    digest = hashlib.md5(_padding(owner_password)).digest()
    for _ in range(50):
        digest = hashlib.md5(digest).digest()
    return digest[:key_len]


def _compute_o_value(rc4_key: bytes, user_password: bytes) -> bytes:
    enc = _rc4(rc4_key, _padding(user_password))
    for i in range(1, 20):
        key = bytes(b ^ i for b in rc4_key)
        enc = _rc4(key, enc)
    return enc


def _compute_encryption_key(
    user_password: bytes,
    o_entry: bytes,
    p_flags: int,
    file_id: bytes,
    key_len: int,
) -> bytes:
    md5 = hashlib.md5(_padding(user_password))
    md5.update(o_entry)
    md5.update(struct.pack("<I", p_flags & 0xFFFFFFFF))
    md5.update(file_id)
    digest = md5.digest()
    for _ in range(50):
        digest = hashlib.md5(digest[:key_len]).digest()
    return digest[:key_len]


def _compute_u_value(key: bytes, file_id: bytes) -> bytes:
    md5 = hashlib.md5(_PADDING)
    md5.update(file_id)
    enc = _rc4(key, md5.digest())
    for i in range(1, 20):
        rc4_key = bytes(b ^ i for b in key)
        enc = _rc4(rc4_key, enc)
    return _padding(enc)


def _object_rc4_key(base_key: bytes, obj_num: int, gen_num: int, key_len: int) -> bytes:
    pack = struct.pack("<I", obj_num)[0:3] + struct.pack("<I", gen_num)[0:2]
    md5 = hashlib.md5(base_key[:key_len] + pack)
    return md5.digest()[: min(key_len + 5, 16)]


def _encrypt_bytes(base_key: bytes, obj_num: int, gen_num: int, key_len: int, data: bytes) -> bytes:
    if not data:
        return data
    rc4_key = _object_rc4_key(base_key, obj_num, gen_num, key_len)
    return _rc4(rc4_key, data)


def _hex_string(data: bytes) -> bytes:
    return b"<" + data.hex().encode() + b">"


def _read_literal_string(data: bytes, start: int) -> Optional[Tuple[bytes, int, int]]:
    if start >= len(data) or data[start] != 0x28:
        return None
    depth = 0
    i = start
    while i < len(data):
        c = data[i]
        if c == 0x5C:
            i += 2
            continue
        if c == 0x28:
            depth += 1
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                return data[start + 1 : i], start, i
        i += 1
    return None


def _encrypt_literal_strings(
    data: bytes, base_key: bytes, key_len: int, obj_num: int, gen_num: int
) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(data):
        if data[pos] == 0x28:
            parsed = _read_literal_string(data, pos)
            if parsed is None:
                out.append(data[pos])
                pos += 1
                continue
            inner, open_i, close_i = parsed
            encrypted = _encrypt_bytes(base_key, obj_num, gen_num, key_len, inner)
            out.extend(data[pos:open_i])
            if out and out[-1] not in (0x20, 0x09, 0x0A, 0x0D, 0x28):
                out.append(0x20)
            out.extend(_hex_string(encrypted))
            pos = close_i + 1
            continue
        out.append(data[pos])
        pos += 1
    return bytes(out)


def _encrypt_hex_strings(
    data: bytes, base_key: bytes, key_len: int, obj_num: int, gen_num: int
) -> bytes:
    out = bytearray()
    pos = 0
    for m in _HEX_STRING_RE.finditer(data):
        out.extend(data[pos : m.start()])
        raw_hex = m.group(1).replace(b" ", b"")
        if not raw_hex:
            out.extend(m.group(0))
            pos = m.end()
            continue
        if len(raw_hex) % 2:
            raw_hex = raw_hex[:-1]
        try:
            plain = bytes.fromhex(raw_hex.decode("ascii"))
        except ValueError:
            out.extend(m.group(0))
            pos = m.end()
            continue
        encrypted = _encrypt_bytes(base_key, obj_num, gen_num, key_len, plain)
        out.extend(_hex_string(encrypted))
        pos = m.end()
    out.extend(data[pos:])
    return bytes(out)


def _encrypt_streams(
    data: bytes, base_key: bytes, key_len: int, obj_num: int, gen_num: int
) -> bytes:
    marker = b"stream"
    end_marker = b"endstream"
    out = bytearray()
    pos = 0
    while pos < len(data):
        idx = data.find(marker, pos)
        if idx == -1:
            out.extend(data[pos:])
            break
        out.extend(data[pos:idx])
        i = idx + len(marker)
        while i < len(data) and data[i] in b" \t\r\n":
            i += 1
        content_start = i
        end_idx = data.find(end_marker, content_start)
        if end_idx == -1:
            out.extend(data[idx:])
            break
        raw = data[content_start:end_idx]
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n"):
            raw = raw[:-1]
        encrypted = _encrypt_bytes(base_key, obj_num, gen_num, key_len, raw)
        out.extend(data[idx:content_start])
        out.extend(encrypted)
        out.extend(b"\n")
        out.extend(end_marker)
        pos = end_idx + len(end_marker)
    return bytes(out)


def _encrypt_segment(
    data: bytes, base_key: bytes, key_len: int, obj_num: int, gen_num: int
) -> bytes:
    body = _encrypt_streams(data, base_key, key_len, obj_num, gen_num)
    body = _encrypt_literal_strings(body, base_key, key_len, obj_num, gen_num)
    return _encrypt_hex_strings(body, base_key, key_len, obj_num, gen_num)


def _encrypt_body_by_objects(data: bytes, base_key: bytes, key_len: int) -> bytes:
    matches = list(_OBJ_RE.finditer(data))
    if not matches:
        return _encrypt_segment(data, base_key, key_len, 0, 0)

    out = bytearray()
    pos = 0
    for m in matches:
        out.extend(_encrypt_segment(data[pos : m.start()], base_key, key_len, 0, 0))
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        end_idx = data.find(b"endobj", m.end())
        if end_idx == -1:
            out.extend(_encrypt_segment(data[m.start() :], base_key, key_len, obj_num, gen_num))
            return bytes(out)
        end_idx += len(b"endobj")
        out.extend(_encrypt_segment(data[m.start() : end_idx], base_key, key_len, obj_num, gen_num))
        pos = end_idx
    out.extend(_encrypt_segment(data[pos:], base_key, key_len, 0, 0))
    return bytes(out)


def _build_encrypt_dict(o_val: bytes, u_val: bytes) -> bytes:
    return (
        b"<< /Filter /Standard /V "
        + str(_V).encode()
        + b" /R "
        + str(_REV).encode()
        + b" /Length "
        + str(_KEY_BITS).encode()
        + b" /P "
        + str(_P_FLAGS).encode()
        + b" /O "
        + _hex_string(o_val)
        + b" /U "
        + _hex_string(u_val)
        + b" >>"
    )


def _next_free_object_id(data: bytes) -> int:
    highest = 0
    for m in _OBJ_RE.finditer(data):
        highest = max(highest, int(m.group(1)))
    return highest + 1


def _encrypt_native_pdf(data: bytes) -> bytes:
    """RC4-128 empty user password — stdlib only, no PDF parser dependency."""
    if b"/Encrypt" in data:
        return data

    file_id = secrets.token_bytes(16)
    key_len = _KEY_BITS // 8
    o_key = _compute_o_value_key(_OWNER_PASSWORD, key_len)
    o_val = _compute_o_value(o_key, b"")
    base_key = _compute_encryption_key(b"", o_val, _P_FLAGS, file_id, key_len)
    u_val = _compute_u_value(base_key, file_id)

    body = _encrypt_body_by_objects(data, base_key, key_len)
    encrypt_id = _next_free_object_id(body)
    encrypt_obj = (
        f"\n{encrypt_id} 0 obj\n".encode()
        + _build_encrypt_dict(o_val, u_val)
        + b"\nendobj\n"
    )

    trailer_idx = body.rfind(b"trailer")
    if trailer_idx == -1:
        body = body + encrypt_obj
        body = (
            body
            + b"\n/Encrypt "
            + str(encrypt_id).encode()
            + b" 0 R\n/ID [ "
            + _hex_string(file_id)
            + b" "
            + _hex_string(file_id)
            + b" ]\n"
        )
        return body

    body = body[:trailer_idx] + encrypt_obj + body[trailer_idx:]
    id_entry = b"/ID [ " + _hex_string(file_id) + b" " + _hex_string(file_id) + b" ]"
    trailer_close = body.rfind(b">>")
    if trailer_close == -1:
        return data
    trailer_inner = (
        b"/Encrypt "
        + str(encrypt_id).encode()
        + b" 0 R\n     "
        + id_entry
        + b"\n     "
    )
    return body[:trailer_close] + trailer_inner + body[trailer_close:]


def _encrypt_with_pypdf(data: bytes) -> Optional[bytes]:
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError:
        return None
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        writer = PdfWriter(clone_from=reader)
        writer.encrypt(
            user_password="",
            owner_password=_OWNER_PASSWORD.decode("ascii"),
            algorithm="RC4-128",
        )
        buf = io.BytesIO()
        writer.write(buf)
        return buf.getvalue()
    except Exception:
        return None


def encrypt_pdf_bytes(data: bytes) -> Tuple[bytes, str]:
    """Encrypt PDF bytes. Tries pypdf first, then native RC4-128."""
    if not data.startswith(b"%PDF"):
        return data, "skip"
    if b"/Encrypt" in data:
        return data, "skip"

    encrypted = _encrypt_with_pypdf(data)
    if encrypted is not None:
        return encrypted, "pypdf"

    return _encrypt_native_pdf(data), "native-rc4-128"


def encrypt_pdf_empty_password(filepath: Path) -> bool:
    """Apply empty-user-password encryption to a PDF file in place."""
    try:
        data = filepath.read_bytes()
    except OSError:
        return False
    encrypted, _backend = encrypt_pdf_bytes(data)
    if encrypted is data:
        return False
    try:
        filepath.write_bytes(encrypted)
    except OSError:
        return False
    return True
