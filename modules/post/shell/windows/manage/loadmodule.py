#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Alias module: ``loadmodule`` → same as run_assembly."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_path = Path(__file__).with_name("run_assembly.py")
_spec = importlib.util.spec_from_file_location("_ks_run_assembly_impl", _path)
_impl = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_impl)


class Module(_impl.Module):
    __info__ = dict(_impl.Module.__info__)
    __info__["name"] = "Windows loadmodule (alias)"
    __info__["description"] = (
        "Alias of post/shell/windows/manage/run_assembly — "
        "set module=<catalog|path> then run."
    )
