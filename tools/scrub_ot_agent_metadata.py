#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scrub spurious OT capability metadata from non-ICS module agent blocks.

Point 1 of IoT/OT hardening: keep s7comm/ot_assets/modbus/dnp3 only on
modules that actually produce or consume those capabilities.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "modules"

OT_CAPS = frozenset(
    {
        "s7comm",
        "ot_assets",
        "modbus_tcp",
        "dnp3_access",
        "dnp3_dest",
        "bacnet",
        "iec104",
        "opcua",
        "enip",
        "profinet",
        "s7",
    }
)

# Paths that are allowed to keep OT capabilities
_ICS_PATH_RE = re.compile(
    r"(^|[/\\])(ics|modbus|s7comm|s7_|bacnet|dnp3|iec104|opcua|enip|profinet|ot_)([/\\]|$)",
    re.I,
)


def _is_ics_module(rel: str) -> bool:
    norm = rel.replace("\\", "/").lower()
    if "/ics/" in norm or norm.startswith("ics/"):
        return True
    if "/listeners/ics/" in norm or "listeners/ics/" in norm:
        return True
    if "/auxiliary/scanner/ics/" in norm or "/scanner/ics/" in norm:
        return True
    if "/exploits/ics/" in norm:
        return True
    # Protocol-named modules outside ics/ folder (rare)
    return bool(_ICS_PATH_RE.search(norm))


def _cap_name(item) -> str | None:
    if isinstance(item, str):
        return item.strip().lower()
    if isinstance(item, dict):
        return str(item.get("capability") or "").strip().lower() or None
    return None


def _dedupe_caps(items: list) -> list:
    seen = set()
    out = []
    for item in items:
        name = _cap_name(item)
        if not name:
            continue
        if name in seen:
            continue
        seen.add(name)
        if isinstance(item, str):
            out.append(name)
        elif isinstance(item, dict):
            cleaned = {"capability": name}
            detail = item.get("from_detail")
            if detail:
                cleaned["from_detail"] = detail
            out.append(cleaned)
    return out


def _filter_ot(items: list, keep_ot: bool) -> list:
    out = []
    for item in items:
        name = _cap_name(item)
        if not name:
            continue
        if not keep_ot and name in OT_CAPS:
            continue
        out.append(item)
    return _dedupe_caps(out)


def _protocol_caps_for_ics(rel: str) -> list[str]:
    norm = rel.replace("\\", "/").lower()
    caps = ["ot_assets"]
    if "modbus" in norm:
        caps.append("modbus_tcp")
    if "s7" in norm or "siemens" in norm:
        caps.append("s7comm")
    if "dnp3" in norm:
        caps.append("dnp3_access")
    if "bacnet" in norm:
        caps.append("bacnet")
    if "iec104" in norm:
        caps.append("iec104")
    if "opcua" in norm or "opc_ua" in norm:
        caps.append("opcua")
    if "enip" in norm or "ethernetip" in norm:
        caps.append("enip")
    # Dedup preserve order
    seen = set()
    ordered = []
    for c in caps:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


def _scrub_agent_dict(agent: dict, rel: str) -> tuple[dict, bool]:
    """Return (new_agent, changed)."""
    keep_ot = _is_ics_module(rel)
    changed = False
    agent = dict(agent)

    # requires.capabilities_any
    requires = agent.get("requires")
    if isinstance(requires, dict):
        requires = dict(requires)
        for key in ("capabilities_any", "capabilities_all"):
            caps = requires.get(key)
            if isinstance(caps, list) and caps:
                filtered = [c for c in caps if keep_ot or str(c).lower() not in OT_CAPS]
                # Also dedupe
                filtered = list(dict.fromkeys(str(c) for c in filtered))
                if filtered != caps:
                    requires[key] = filtered
                    changed = True
        if keep_ot:
            # For ICS manage modules, ensure protocol requires exist
            if "/manage/" in rel.replace("\\", "/").lower():
                want = _protocol_caps_for_ics(rel)
                any_caps = list(requires.get("capabilities_any") or [])
                merged = list(dict.fromkeys([*any_caps, *want]))
                if merged != any_caps:
                    requires["capabilities_any"] = merged
                    changed = True
        agent["requires"] = requires

    chain = agent.get("chain")
    if isinstance(chain, dict):
        chain = dict(chain)
        for key in ("produces_capabilities", "consumes_capabilities"):
            caps = chain.get(key)
            if isinstance(caps, list) and caps:
                filtered = _filter_ot(caps, keep_ot=keep_ot)
                # Non-ICS: also drop spurious bare db_access spam unless mysql/postgres/mssql/mongodb/redis/ldap path
                if not keep_ot and key == "produces_capabilities":
                    norm = rel.replace("\\", "/").lower()
                    db_paths = (
                        "/mysql/",
                        "/postgresql/",
                        "/mssql/",
                        "/mongodb/",
                        "/redis/",
                        "/ldap/",
                        "/sqli",
                        "/sql_",
                    )
                    if not any(tok in norm for tok in db_paths):
                        filtered = [
                            c
                            for c in filtered
                            if _cap_name(c) != "db_access"
                        ]
                if filtered != _dedupe_caps(caps) or len(filtered) != len(caps):
                    # Compare meaningfully
                    if filtered != caps:
                        chain[key] = filtered
                        changed = True
                elif filtered != caps:
                    chain[key] = filtered
                    changed = True
        if keep_ot and "produces_capabilities" in chain:
            # Ensure ICS gather/identify produce protocol caps
            want = _protocol_caps_for_ics(rel)
            existing = chain.get("produces_capabilities") or []
            names = {_cap_name(c) for c in existing}
            for w in want:
                if w not in names:
                    existing.append(w)
                    changed = True
            chain["produces_capabilities"] = _dedupe_caps(existing)
        agent["chain"] = chain

    return agent, changed


def _find_agent_assign(tree: ast.AST) -> ast.Dict | None:
    """Find __info__ = { ... 'agent': {..} } agent dict node."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__info__":
                if isinstance(node.value, ast.Dict):
                    return _get_key_dict(node.value, "agent")
    return None


def _get_key_dict(d: ast.Dict, key: str) -> ast.Dict | None:
    for k, v in zip(d.keys, d.values):
        if isinstance(k, ast.Constant) and k.value == key and isinstance(v, ast.Dict):
            return v
        if isinstance(k, ast.Str) and k.s == key and isinstance(v, ast.Dict):  # py<3.8
            return v
    return None


def _literal_eval_safe(node: ast.AST):
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _format_agent_block(agent: dict, indent: str = "        ") -> str:
    """Format a compact agent block matching common module style."""
    # Use repr-like but with single quotes via a small custom formatter
    return _py_repr(agent, indent=indent, level=0)


def _py_repr(obj, indent: str, level: int) -> str:
    pad = indent + ("    " * level)
    pad_in = indent + ("    " * (level + 1))
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        lines = ["{"]
        items = list(obj.items())
        for i, (k, v) in enumerate(items):
            comma = "," if i < len(items) - 1 else ","
            lines.append(f"{pad_in}{repr(k)}: {_py_repr(v, indent, level + 1)}{comma}")
        lines.append(f"{pad}}}")
        return "\n".join(lines)
    if isinstance(obj, list):
        if not obj:
            return "[]"
        # short lists of strings/dicts on one line if small
        if all(isinstance(x, str) for x in obj) and len(obj) <= 6:
            inner = ", ".join(repr(x) for x in obj)
            return f"[{inner}]"
        lines = ["["]
        for i, x in enumerate(obj):
            comma = "," if i < len(obj) - 1 else ","
            lines.append(f"{pad_in}{_py_repr(x, indent, level + 1)}{comma}")
        lines.append(f"{pad}]")
        return "\n".join(lines)
    return repr(obj)


def scrub_source(text: str, rel: str) -> tuple[str, bool]:
    """Regex-based scrub of agent.chain produces/consumes and requires caps.

    More reliable than full AST rewrite for messy formatting.
    """
    if "'agent'" not in text and '"agent"' not in text:
        return text, False
    if not any(c in text for c in OT_CAPS) and "db_access" not in text:
        return text, False

    keep_ot = _is_ics_module(rel)
    changed = False

    # Scrub capability dict entries in produces/consumes lists
    def repl_cap_dict(m: re.Match) -> str:
        nonlocal changed
        cap = m.group(1).lower()
        if not keep_ot and cap in OT_CAPS:
            changed = True
            return ""
        return m.group(0)

    # Remove lines like: {'capability': 's7comm', 'from_detail': ''},
    new = re.sub(
        r"[ \t]*\{['\"]capability['\"]\s*:\s*['\"]([^'\"]+)['\"][^\}]*\}\s*,?\s*\n?",
        repl_cap_dict,
        text,
    )

    # Remove bare string caps in lists: 's7comm', or "ot_assets",
    def repl_bare(m: re.Match) -> str:
        nonlocal changed
        cap = m.group(1).lower()
        if not keep_ot and cap in OT_CAPS:
            changed = True
            return ""
        return m.group(0)

# Remove bare OT capability strings only when they are list items on their own
# (avoid matching inside {'capability': 'db_access', ...} dicts).
new = re.sub(
    r"(?m)^[ \t]*['\"](s7comm|ot_assets|modbus_tcp|dnp3_access|dnp3_dest|bacnet|iec104|opcua|enip|profinet|s7)['\"]\s*,?\s*$",
    lambda m: "" if (not keep_ot and m.group(1).lower() in OT_CAPS) else m.group(0),
    new,
)

    # Non-ICS: collapse repeated db_access produces spam — keep at most one if DB path, else none
    norm = rel.replace("\\", "/").lower()
    db_paths = (
        "/mysql/",
        "/postgresql/",
        "/mssql/",
        "/mongodb/",
        "/redis/",
        "/ldap/",
        "/sqli",
        "/sql_",
    )
    is_db = any(tok in norm for tok in db_paths)

    if not keep_ot:
        # Count db_access capability dict lines in file
        db_pat = re.compile(
            r"[ \t]*\{['\"]capability['\"]\s*:\s*['\"]db_access['\"][^\}]*\}\s*,?\s*\n?"
        )
        matches = list(db_pat.finditer(new))
        if matches:
            if not is_db:
                new2 = db_pat.sub("", new)
                if new2 != new:
                    changed = True
                    new = new2
            elif len(matches) > 1:
                # keep first only
                def keep_first(m, counter=[0]):
                    nonlocal changed
                    counter[0] += 1
                    if counter[0] == 1:
                        return m.group(0)
                    changed = True
                    return ""

                new = db_pat.sub(keep_first, new)

        # bare 'db_access' strings on their own line only
        bare_db = re.compile(r"(?m)^[ \t]*['\"]db_access['\"]\s*,?\s*$")
        bare_matches = list(bare_db.finditer(new))
        if bare_matches and not is_db:
            new2 = bare_db.sub("", new)
            if new2 != new:
                changed = True
                new = new2
        elif len(bare_matches) > 1 and is_db:
            def keep_first_bare(m, counter=[0]):
                nonlocal changed
                counter[0] += 1
                if counter[0] == 1:
                    return m.group(0)
                changed = True
                return ""

            new = bare_db.sub(keep_first_bare, new)

    # Clean trailing double commas / empty slots left by removals
    new2 = re.sub(r",\s*,", ",", new)
    new2 = re.sub(r"\[\s*,", "[", new2)
    new2 = re.sub(r",\s*\]", "]", new2)
    if new2 != new:
        changed = True
        new = new2

    # ICS: inject protocol produces if missing (lightweight — only if chain block exists)
    if keep_ot and "'chain'" in new or (keep_ot and '"chain"' in new):
        want = _protocol_caps_for_ics(rel)
        for cap in want:
            if f"'{cap}'" not in new and f'"{cap}"' not in new:
                # Insert into produces_capabilities list if present
                m = re.search(
                    r"(['\"]produces_capabilities['\"]\s*:\s*\[)",
                    new,
                )
                if m:
                    insert = f"{{'capability': '{cap}', 'from_detail': ''}},\n                                   "
                    new = new[: m.end()] + insert + new[m.end() :]
                    changed = True

    return new, changed


def main() -> int:
    dry = "--dry-run" in sys.argv
    files = sorted(MODULES.rglob("*.py"))
    touched = 0
    skipped_ics_ok = 0
    for path in files:
        if path.name == "__init__.py":
            continue
        rel = str(path.relative_to(MODULES)).replace("\\", "/")
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        new, changed = scrub_source(text, rel)
        if not changed:
            continue
        touched += 1
        if dry:
            print(f"WOULD scrub: {rel}")
        else:
            path.write_text(new, encoding="utf-8")
            print(f"scrubbed: {rel}")
        if _is_ics_module(rel):
            skipped_ics_ok += 1
    print(f"\nDone. files_changed={touched} (ics_touched={skipped_ics_ok}) dry={dry}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
