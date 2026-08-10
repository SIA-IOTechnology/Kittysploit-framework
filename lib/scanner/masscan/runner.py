# -*- coding: utf-8 -*-
"""Run the masscan binary and capture JSON on stdout (no intermediate file required)."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Sequence, Union


def resolve_masscan_cli() -> Optional[str]:
    """Return absolute path to masscan, or None if not installed."""
    return shutil.which("masscan")


def masscan_available() -> Dict[str, Any]:
    cli = resolve_masscan_cli()
    return {
        "available": bool(cli),
        "cli": cli,
        "install_hint": "apt install masscan  # or: brew install masscan",
    }


def run_masscan(
    targets: Union[str, Sequence[str]],
    *,
    ports: str = "1-1024",
    rate: int = 1000,
    arguments: str = "",
    timeout_sec: int = 600,
    masscan_bin: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute masscan with ``-oJ -`` and return stdout JSON + metadata."""
    target_list = _normalize_targets(targets)
    if not target_list:
        return {
            "ok": False,
            "json": "",
            "stderr": "",
            "returncode": -1,
            "cmd": [],
            "error": "no targets",
        }

    extra_tokens: List[str] = []
    extra = (arguments or "").strip()
    if extra:
        blocked = {"-oJ", "-oX", "-oL", "-oG", "-oB", "-oD", "-oN", "-oA"}
        try:
            tokens = shlex.split(extra)
        except ValueError as exc:
            return {
                "ok": False,
                "json": "",
                "stderr": "",
                "returncode": -1,
                "cmd": [],
                "error": f"invalid arguments: {exc}",
            }
        for tok in tokens:
            if tok in blocked or tok.startswith("-oJ") or tok.startswith("-oX"):
                return {
                    "ok": False,
                    "json": "",
                    "stderr": "",
                    "returncode": -1,
                    "cmd": [],
                    "error": (
                        f"argument {tok!r} is not allowed — JSON is captured on stdout "
                        "via -oJ -"
                    ),
                }
            # Avoid duplicate -p / --rate when set via dedicated options
            if tok in ("-p", "--ports", "--rate"):
                return {
                    "ok": False,
                    "json": "",
                    "stderr": "",
                    "returncode": -1,
                    "cmd": [],
                    "error": f"use the dedicated option instead of {tok!r} in arguments",
                }
        extra_tokens = tokens

    cli = masscan_bin or resolve_masscan_cli()
    if not cli:
        return {
            "ok": False,
            "json": "",
            "stderr": "",
            "returncode": -1,
            "cmd": [],
            "error": "masscan not found on PATH",
        }

    ports = (ports or "").strip() or "1-1024"
    cmd: List[str] = [cli, "-oJ", "-", "-p", ports, "--rate", str(max(1, int(rate or 1000)))]
    if extra_tokens:
        cmd.extend(extra_tokens)
    cmd.extend(target_list)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(30, int(timeout_sec or 600)),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "json": "",
            "stderr": "",
            "returncode": -1,
            "cmd": cmd,
            "error": f"masscan timed out after {timeout_sec}s",
        }
    except FileNotFoundError:
        return {
            "ok": False,
            "json": "",
            "stderr": "",
            "returncode": -1,
            "cmd": cmd,
            "error": "masscan not found on PATH",
        }
    except OSError as exc:
        return {
            "ok": False,
            "json": "",
            "stderr": "",
            "returncode": -1,
            "cmd": cmd,
            "error": str(exc),
        }

    out = proc.stdout or ""
    err = (proc.stderr or "").strip()
    # masscan may return non-zero on partial permission issues but still emit JSON
    has_data = bool(out.strip()) and ("{" in out or "[" in out)
    ok = has_data or proc.returncode == 0
    error = None
    if not has_data:
        ok = False
        error = err or f"masscan exited with code {proc.returncode} (no JSON on stdout)"
        if "permission" in err.lower() or "PERM" in err or proc.returncode == 1:
            error += " — masscan often needs root/capabilities for raw SYN scans"

    return {
        "ok": ok,
        "json": out,
        "stderr": err,
        "returncode": proc.returncode,
        "cmd": cmd,
        "error": error,
    }


def _normalize_targets(targets: Union[str, Sequence[str]]) -> List[str]:
    if isinstance(targets, str):
        raw = targets.replace(";", ",")
        return [p.strip() for p in raw.split(",") if p.strip()]
    out: List[str] = []
    for item in targets or []:
        value = str(item or "").strip()
        if value:
            out.append(value)
    return out
