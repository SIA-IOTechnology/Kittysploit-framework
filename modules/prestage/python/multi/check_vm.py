#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "check_vm"

    __info__ = {
        "name": "Check VM / Sandbox (Python)",
        "description": "Exit early when common VM or sandbox indicators are detected",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "dependencies": [],
        "tags": ["evasion", "prestage", "offline", "python"],
    }

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        return """
import os
import sys

_vm_markers = (
    "vmware", "virtualbox", "vbox", "qemu", "xen", "hyper-v",
    "kvm", "parallels", "bochs", "innotek", "virtual",
)
_hit = False
try:
    import platform as _plat
    blob = " ".join(
        filter(None, [
            _plat.platform().lower(),
            _plat.machine().lower(),
            _plat.processor().lower(),
        ])
    )
    if any(m in blob for m in _vm_markers):
        _hit = True
except Exception:
    pass
if not _hit:
    for _path in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"):
        try:
            with open(_path, "r", encoding="utf-8", errors="ignore") as _f:
                _txt = _f.read().lower()
            if any(m in _txt for m in _vm_markers):
                _hit = True
                break
        except Exception:
            continue
if _hit:
    sys.exit(0)
""".strip()
