#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Run BloodHound.py / bloodhound-ce-python and return a zip for Attack Graph import.

Works from Linux (and Windows) against a reachable Domain Controller — no SharpHound.exe.
Preferred default collection is ``DCOnly`` (LDAP from the DC; no member-host fan-out).
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Serialize Cosmic / module collects that share the same overlay writer path.
_collect_lock = threading.Lock()


# Prefer CE-compatible CLI when present (BloodHound Community Edition schema).
_CANDIDATE_CLIS = (
    "bloodhound-ce-python",
    "bloodhound-python",
    "bloodhound",
)

_VALID_COLLECTIONS = frozenset(
    {
        "default",
        "all",
        "dconly",
        "group",
        "localadmin",
        "session",
        "loggedon",
        "trusts",
        "acl",
        "container",
        "objectprops",
        "rdp",
        "dcom",
        "psremote",
    }
)


def resolve_bloodhound_cli() -> Optional[str]:
    """Return absolute path to a BloodHound.py CLI, or None if not installed."""
    for name in _CANDIDATE_CLIS:
        path = shutil.which(name)
        if path:
            return path
    # Fallback: python -m bloodhound (classic package)
    try:
        import bloodhound  # noqa: F401

        return "python-module:bloodhound"
    except Exception:
        return None


def bloodhound_python_available() -> Dict[str, Any]:
    cli = resolve_bloodhound_cli()
    return {
        "available": bool(cli),
        "cli": cli,
        "install_hint": (
            "pip install bloodhound  # CLI: bloodhound-python\n"
            "# or CE build: pip install bloodhound-ce  # CLI: bloodhound-ce-python"
        ),
        "default_collection": "DCOnly",
        "collections": sorted(_VALID_COLLECTIONS),
    }


def _normalize_collection(value: str) -> str:
    raw = (value or "DCOnly").strip()
    if not raw:
        raw = "DCOnly"
    parts = []
    for piece in raw.replace(";", ",").split(","):
        p = piece.strip()
        if not p:
            continue
        key = p.lower()
        if key not in _VALID_COLLECTIONS:
            raise ValueError(
                f"Unknown collection method: {p!r}. "
                f"Use one of: {', '.join(sorted(_VALID_COLLECTIONS))}"
            )
        # Preserve BloodHound.py casing conventions
        if key == "dconly":
            parts.append("DCOnly")
        elif key == "all":
            parts.append("All")
        elif key == "default":
            parts.append("Default")
        elif key == "objectprops":
            parts.append("ObjectProps")
        elif key == "localadmin":
            parts.append("LocalAdmin")
        elif key == "psremote":
            parts.append("PSRemote")
        else:
            parts.append(p[:1].upper() + p[1:].lower() if len(p) > 1 else p.upper())
    return ",".join(parts) if parts else "DCOnly"


def _find_zip(workdir: Path) -> Optional[Path]:
    zips = sorted(workdir.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    return zips[0] if zips else None


def _zip_json_outputs(workdir: Path, zip_path: Path) -> Optional[Path]:
    jsons = list(workdir.glob("*.json"))
    if not jsons:
        return None
    import zipfile

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for jf in jsons:
            zf.write(jf, arcname=jf.name)
    return zip_path if zip_path.is_file() else None


def _cleanup_owned(owned_tmpdir: Optional[str]) -> None:
    if not owned_tmpdir:
        return
    try:
        shutil.rmtree(owned_tmpdir, ignore_errors=True)
    except Exception:
        pass


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Best-effort terminate bloodhound-python and children after timeout."""
    if proc.poll() is not None:
        return
    try:
        if hasattr(os, "killpg") and proc.pid:
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            if hasattr(os, "killpg") and proc.pid:
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            pass


def run_bloodhound_python(
    *,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    nameserver: str = "",
    domain_controller: str = "",
    collection: str = "DCOnly",
    auth_method: str = "auto",
    use_ldaps: bool = False,
    zip_output: bool = True,
    workers: int = 10,
    timeout_sec: int = 900,
    output_dir: Optional[str] = None,
    keep_workdir: bool = False,
) -> Dict[str, Any]:
    """
    Execute BloodHound.py collection and return ``{success, zip_path, ...}``.

    ``hashes`` is Impacket-style ``LMHASH:NTHASH`` (or ``:NTHASH``).
    """
    domain = str(domain or "").strip()
    username = str(username or "").strip()
    if not domain:
        return {"success": False, "error": "domain is required"}
    if not username:
        return {"success": False, "error": "username is required"}
    if not password and not hashes:
        return {"success": False, "error": "password or hashes is required"}

    cli = resolve_bloodhound_cli()
    if not cli:
        info = bloodhound_python_available()
        return {
            "success": False,
            "error": "bloodhound-python is not installed",
            "install_hint": info["install_hint"],
        }

    try:
        collection_norm = _normalize_collection(collection)
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    if output_dir:
        workdir = Path(output_dir).expanduser().resolve()
        workdir.mkdir(parents=True, exist_ok=True)
        owned_tmpdir = None
    else:
        owned_tmpdir = tempfile.mkdtemp(prefix="ks_bhpy_")
        workdir = Path(owned_tmpdir)

    prefix = f"ks_{int(time.time())}_"
    cmd: List[str]
    if cli.startswith("python-module:"):
        cmd = [os.environ.get("PYTHON", "python3"), "-m", "bloodhound"]
    else:
        cmd = [cli]

    cmd.extend(
        [
            "-u",
            username,
            "-d",
            domain,
            "-c",
            collection_norm,
            "-op",
            prefix,
            "-w",
            str(max(1, int(workers or 10))),
        ]
    )
    if zip_output:
        cmd.append("--zip")
    if password:
        cmd.extend(["-p", password])
    if hashes:
        cmd.extend(["--hashes", hashes])
    if nameserver:
        cmd.extend(["-ns", str(nameserver).strip()])
    if domain_controller:
        cmd.extend(["-dc", str(domain_controller).strip()])
    if auth_method and auth_method != "auto":
        cmd.extend(["--auth-method", auth_method])
    if use_ldaps:
        cmd.append("--use-ldaps")

    # Redact secrets in returned command preview
    preview: List[str] = []
    skip_next = False
    for i, part in enumerate(cmd):
        if skip_next:
            skip_next = False
            continue
        if part in {"-p", "--hashes"}:
            preview.extend([part, "***"])
            skip_next = True
            continue
        preview.append(part)

    popen_kwargs: Dict[str, Any] = {
        "cwd": str(workdir),
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "env": {**os.environ, "PYTHONUNBUFFERED": "1"},
    }
    # New session so we can kill the whole process group on timeout (Unix).
    if hasattr(os, "setsid"):
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
    except FileNotFoundError:
        _cleanup_owned(owned_tmpdir if not keep_workdir else None)
        return {
            "success": False,
            "error": f"CLI not found: {cli}",
            "install_hint": bloodhound_python_available()["install_hint"],
        }

    timeout = max(30, int(timeout_sec or 900))
    try:
        stdout_raw, stderr_raw = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_tree(proc)
        try:
            stdout_raw, stderr_raw = proc.communicate(timeout=3)
        except Exception:
            stdout_raw, stderr_raw = "", ""
        if not keep_workdir:
            _cleanup_owned(owned_tmpdir)
        return {
            "success": False,
            "error": f"bloodhound-python timed out after {timeout}s (process killed)",
            "workdir": None if not keep_workdir else str(workdir),
            "command": preview,
            "stdout": (stdout_raw or "")[-4000:],
            "stderr": (stderr_raw or "")[-4000:],
        }

    stdout = (stdout_raw or "")[-8000:]
    stderr = (stderr_raw or "")[-8000:]
    zip_path = _find_zip(workdir)
    if not zip_path and zip_output:
        # Some builds ignore --zip; pack JSON ourselves
        zip_path = _zip_json_outputs(workdir, workdir / f"{prefix}BloodHound.zip")

    if proc.returncode != 0 and not zip_path:
        if not keep_workdir:
            _cleanup_owned(owned_tmpdir)
        return {
            "success": False,
            "error": f"bloodhound-python exited {proc.returncode}",
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "workdir": None if not keep_workdir else str(workdir),
            "command": preview,
        }

    if not zip_path:
        jsons = list(workdir.glob("*.json"))
        if not jsons:
            if not keep_workdir:
                _cleanup_owned(owned_tmpdir)
            return {
                "success": False,
                "error": "No BloodHound zip/json produced",
                "stdout": stdout,
                "stderr": stderr,
                "workdir": None if not keep_workdir else str(workdir),
                "command": preview,
            }
        # Persist a zip so Cosmic can import without pinning the temp dir
        persist_dir = Path(os.path.expanduser("~/.kittysploit/bloodhound_collect"))
        persist_dir.mkdir(parents=True, exist_ok=True)
        final_zip = persist_dir / f"{prefix}BloodHound.zip"
        packed = _zip_json_outputs(workdir, final_zip)
        if not keep_workdir:
            _cleanup_owned(owned_tmpdir)
            owned_tmpdir = None
        if packed:
            return {
                "success": True,
                "zip_path": str(final_zip),
                "export_path": str(final_zip),
                "json_files": [p.name for p in jsons],
                "collection": collection_norm,
                "domain": domain,
                "cli": cli,
                "stdout": stdout,
                "stderr": stderr,
                "command": preview,
                "workdir": None,
                "owned_tmpdir": None,
            }
        return {
            "success": True,
            "zip_path": None,
            "export_path": str(workdir),
            "json_files": [p.name for p in jsons],
            "collection": collection_norm,
            "domain": domain,
            "cli": cli,
            "stdout": stdout,
            "stderr": stderr,
            "command": preview,
            "workdir": str(workdir),
            "owned_tmpdir": owned_tmpdir if not keep_workdir else None,
        }

    # Persist zip outside owned tmp if we will delete workdir
    final_zip = zip_path
    if owned_tmpdir and not keep_workdir:
        persist_dir = Path(os.path.expanduser("~/.kittysploit/bloodhound_collect"))
        persist_dir.mkdir(parents=True, exist_ok=True)
        final_zip = persist_dir / zip_path.name
        shutil.copy2(zip_path, final_zip)
        _cleanup_owned(owned_tmpdir)
        owned_tmpdir = None

    return {
        "success": True,
        "zip_path": str(final_zip),
        "export_path": str(final_zip),
        "collection": collection_norm,
        "domain": domain,
        "cli": cli,
        "stdout": stdout,
        "stderr": stderr,
        "command": preview,
        "workdir": str(workdir) if keep_workdir or not owned_tmpdir else None,
        "owned_tmpdir": owned_tmpdir,
    }


def collect_and_merge_kb(
    framework: Any,
    *,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    nameserver: str = "",
    domain_controller: str = "",
    collection: str = "DCOnly",
    replace: bool = True,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Run BloodHound.py then merge into agent knowledge_base attack_graph."""
    from lib.protocols.ldap.ad_graph_import import merge_bloodhound_into_kb

    result = run_bloodhound_python(
        domain=domain,
        username=username,
        password=password,
        hashes=hashes,
        nameserver=nameserver,
        domain_controller=domain_controller,
        collection=collection,
        **kwargs,
    )
    if not result.get("success"):
        return result

    export_path = result.get("export_path") or result.get("zip_path")
    if not export_path:
        return {**result, "success": False, "error": "No export path after collection"}

    kb: Dict[str, Any] = {}
    if framework and hasattr(framework, "agent_state"):
        state = getattr(framework, "agent_state", None)
        if state and isinstance(getattr(state, "knowledge_base", None), dict):
            kb = state.knowledge_base
    added = merge_bloodhound_into_kb(
        kb, str(export_path), domain=domain, replace=bool(replace)
    )
    return {
        **result,
        "imported": True,
        "import_mode": "agent_kb",
        "nodes_added": added,
    }


__all__ = [
    "bloodhound_python_available",
    "resolve_bloodhound_cli",
    "run_bloodhound_python",
    "collect_and_merge_kb",
    "_collect_lock",
]
