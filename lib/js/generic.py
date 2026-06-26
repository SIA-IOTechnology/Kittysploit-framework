#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from core.utils.paths import read_core_text


def load_js_library(filename: str) -> str:
    """Load a JS library from core/browser_static/libs/."""
    return read_core_text("browser_static", "libs", filename)


def load_generic_lib() -> str:
    return load_js_library("generic.v1.js")


def js_string(value: str) -> str:
    """Return a JS-safe quoted string using JSON encoding."""
    return json.dumps(value if value is not None else "")


def wrap_iife(body: str, use_strict: bool = True) -> str:
    strict_line = "'use strict';" if use_strict else ""
    return f"(function(){{\n{strict_line}\n{body}\n}})();"


def bundle_with_generic_lib(script: str) -> str:
    """
    Prepend the shared JS library to a script.
    The library is plain JS, then the script runs as last statement.
    """
    lib = load_generic_lib()
    return f"{lib}\n\n{script}"
