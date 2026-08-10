# -*- coding: utf-8 -*-
"""Run the nmap binary and capture XML on stdout (no intermediate file required)."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Sequence, Union


def resolve_nmap_cli() -> Optional[str]:
    """Return absolute path to nmap, or None if not installed."""
    return shutil.which("nmap")


def nmap_available() -> Dict[str, Any]:
    cli = resolve_nmap_cli()
    return {
        "available": bool(cli),
        "cli": cli,
        "install_hint": "apt install nmap  # or: brew install nmap",
    }


def run_nmap(
    targets: Union[str, Sequence[str]],
    *,
    ports: str = "",
    arguments: str = "-sV",
    timeout_sec: int = 600,
    nmap_bin: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute nmap with ``-oX -`` and return stdout XML + metadata.

    Returns::
        {
            "ok": bool,
            "xml": str,
            "stderr": str,
            "returncode": int,
            "cmd": list[str],
            "error": str | None,
        }
    """
    cli = nmap_bin or resolve_nmap_cli()
    if not cli:
        return {
            "ok": False,
            "xml": "",
            "stderr": "",
            "returncode": -1,
            "cmd": [],
            "error": "nmap not found on PATH",
        }

    target_list = _normalize_targets(targets)
    if not target_list:
        return {
            "ok": False,
            "xml": "",
            "stderr": "",
            "returncode": -1,
            "cmd": [],
            "error": "no targets",
        }

    cmd: List[str] = [cli, "-oX", "-"]
    ports = (ports or "").strip()
    if ports:
        cmd.extend(["-p", ports])

    extra = (arguments or "").strip()
    if extra:
        # Reject output-file flags that would divert XML away from stdout
        blocked = {"-oX", "-oN", "-oG", "-oA", "-oS"}
        try:
            tokens = shlex.split(extra)
        except ValueError as exc:
            return {
                "ok": False,
                "xml": "",
                "stderr": "",
                "returncode": -1,
                "cmd": [],
                "error": f"invalid arguments: {exc}",
            }
        for tok in tokens:
            if tok in blocked or tok.startswith("-oX") or tok.startswith("-oA"):
                return {
                    "ok": False,
                    "xml": "",
                    "stderr": "",
                    "returncode": -1,
                    "cmd": [],
                    "error": (
                        f"argument {tok!r} is not allowed — XML is captured on stdout "
                        "via -oX -"
                    ),
                }
        cmd.extend(tokens)

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
            "xml": "",
            "stderr": "",
            "returncode": -1,
            "cmd": cmd,
            "error": f"nmap timed out after {timeout_sec}s",
        }
    except FileNotFoundError:
        return {
            "ok": False,
            "xml": "",
            "stderr": "",
            "returncode": -1,
            "cmd": cmd,
            "error": "nmap not found on PATH",
        }
    except OSError as exc:
        return {
            "ok": False,
            "xml": "",
            "stderr": "",
            "returncode": -1,
            "cmd": cmd,
            "error": str(exc),
        }

    xml_out = proc.stdout or ""
    err = (proc.stderr or "").strip()
    ok = proc.returncode == 0 and "<nmaprun" in xml_out
    error = None
    if not ok:
        if proc.returncode != 0:
            error = err or f"nmap exited with code {proc.returncode}"
        elif "<nmaprun" not in xml_out:
            error = "nmap produced no XML on stdout"

    return {
        "ok": ok,
        "xml": xml_out,
        "stderr": err,
        "returncode": proc.returncode,
        "cmd": cmd,
        "error": error,
    }


def _normalize_targets(targets: Union[str, Sequence[str]]) -> List[str]:
    if isinstance(targets, str):
        raw = targets.replace(";", ",")
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        return parts
    out: List[str] = []
    for item in targets or []:
        value = str(item or "").strip()
        if value:
            out.append(value)
    return out
