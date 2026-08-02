#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Second-pass scrub: fix ICS agent blocks (protocol-specific caps, drop db_access spam)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "modules"

OT_ALL = ("ot_assets", "modbus_tcp", "s7comm", "dnp3_access", "dnp3_dest", "bacnet", "iec104", "opcua", "enip", "profinet")


def protocol_caps(rel: str) -> list[str]:
    n = rel.replace("\\", "/").lower()
    caps = ["ot_assets"]
    if "modbus" in n:
        caps.append("modbus_tcp")
    if "s7" in n or "siemens" in n:
        caps.append("s7comm")
    if "dnp3" in n:
        caps.append("dnp3_access")
    if "bacnet" in n:
        caps.append("bacnet")
    if "iec104" in n:
        caps.append("iec104")
    if "opcua" in n or "opc_ua" in n:
        caps.append("opcua")
    if "enip" in n or "ethernetip" in n:
        caps.append("enip")
    # generic ics gather without protocol → ot_assets only
    return list(dict.fromkeys(caps))


def scrub_ics(text: str, rel: str) -> tuple[str, bool]:
    want = protocol_caps(rel)
    changed = False

    # Fix capabilities_any = ['ot_assets', 'modbus_tcp', 's7comm', 'dnp3_access'] style lists
    def repl_any(m: re.Match) -> str:
        nonlocal changed
        inner = m.group(1)
        caps = re.findall(r"['\"]([a-z0-9_]+)['\"]", inner)
        filtered = [c for c in caps if c in want or c not in OT_ALL]
        # Prefer exact want for manage/gather ICS
        filtered = list(dict.fromkeys([*want, *[c for c in filtered if c not in OT_ALL]]))
        new_inner = ", ".join(repr(c) for c in filtered)
        if new_inner != ", ".join(repr(c) for c in caps):
            changed = True
        return m.group(0).split("[")[0] + "[" + new_inner + "]"

    new = re.sub(
        r"capabilities_any'\s*:\s*\[([^\]]*)\]",
        repl_any,
        text,
    )
    new = re.sub(
        r'capabilities_any"\s*:\s*\[([^\]]*)\]',
        repl_any,
        new,
    )

    # Remove db_access from ICS produces
    new2 = re.sub(
        r"[ \t]*\{['\"]capability['\"]\s*:\s*['\"]db_access['\"][^\}]*\}\s*,?\s*\n?",
        "",
        new,
    )
    if new2 != new:
        changed = True
        new = new2

    # Dedupe OT capability dict lines in produces — rebuild produces list content lightly
    # Remove duplicate consecutive same capability entries
    seen_caps: set[str] = set()

    def dedupe_cap_line(m: re.Match) -> str:
        nonlocal changed
        cap = m.group(1).lower()
        if cap in seen_caps and cap in OT_ALL:
            changed = True
            return ""
        # Drop OT caps not in want for this module
        if cap in OT_ALL and cap not in want:
            changed = True
            return ""
        seen_caps.add(cap)
        return m.group(0)

    new2 = re.sub(
        r"[ \t]*\{['\"]capability['\"]\s*:\s*['\"]([^'\"]+)['\"][^\}]*\}\s*,?\s*\n?",
        dedupe_cap_line,
        new,
    )
    if new2 != new:
        changed = True
        new = new2

    # Ensure each wanted cap appears once in produces_capabilities
    m = re.search(r"(['\"]produces_capabilities['\"]\s*:\s*\[)", new)
    if m:
        for cap in want:
            if f"'{cap}'" not in new and f'"{cap}"' not in new:
                insert = f"{{'capability': '{cap}', 'from_detail': ''}},\n                                   "
                new = new[: m.end()] + insert + new[m.end() :]
                changed = True

    new2 = re.sub(r",\s*,", ",", new)
    new2 = re.sub(r"\[\s*,", "[", new2)
    new2 = re.sub(r",\s*\]", "]", new2)
    if new2 != new:
        changed = True
        new = new2
    return new, changed


def main() -> int:
    dry = "--dry-run" in sys.argv
    n = 0
    for path in sorted((MODULES).rglob("*.py")):
        rel = str(path.relative_to(MODULES)).replace("\\", "/")
        if "/ics/" not in rel:
            continue
        text = path.read_text(encoding="utf-8")
        new, changed = scrub_ics(text, rel)
        if not changed:
            continue
        n += 1
        if dry:
            print("WOULD", rel)
        else:
            path.write_text(new, encoding="utf-8")
            print("fixed", rel)
    print(f"ics_fixed={n} dry={dry}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
