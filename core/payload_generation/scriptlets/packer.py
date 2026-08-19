#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Pack offline pre-stage scriptlets ahead of generated payload code."""

from __future__ import annotations

from typing import List, Optional

from .registry import Scriptlet, resolve_scriptlet_names


_WRAPPER = '''
def __kitty_prestage_{idx}__():
    try:
{body}
    except Exception:
        pass

__kitty_prestage_{idx}__()
try:
    del __kitty_prestage_{idx}__
except Exception:
    pass
'''


def _indent(code: str, spaces: int = 8) -> str:
    prefix = " " * spaces
    lines = (code or "").splitlines()
    if not lines:
        return prefix + "pass"
    return "\n".join(prefix + line if line.strip() else line for line in lines)


def build_prestage_block(scriptlets: List[Scriptlet]) -> str:
    """Return Python source executed before the main payload body."""
    if not scriptlets:
        return ""
    blocks: List[str] = []
    for idx, scriptlet in enumerate(scriptlets):
        blocks.append(
            _WRAPPER.format(idx=idx, body=_indent(scriptlet.code)).strip()
        )
    return "\n\n".join(blocks) + "\n\n"


_ZIG_WRAPPER = '''
fn __kitty_prestage_{idx}__() void {{
{body}
}}

__kitty_prestage_{idx}__();
'''


HELPER_MARKER = "// @kitty_helpers"
BODY_MARKER = "// @kitty_body"


def _split_zig_prestage_code(code: str) -> tuple[str, str]:
    text = str(code or "").strip()
    if HELPER_MARKER in text and BODY_MARKER in text:
        _, rest = text.split(HELPER_MARKER, 1)
        helpers, body = rest.split(BODY_MARKER, 1)
        return helpers.strip(), body.strip()
    return "", text


def build_zig_prestage_block(scriptlets: List[Scriptlet]) -> tuple[str, str]:
    """Return (helpers, main_prestage_block) for Zig templates."""
    if not scriptlets:
        return "", ""
    helper_blocks: List[str] = []
    body_blocks: List[str] = []
    for idx, scriptlet in enumerate(scriptlets):
        helpers, body = _split_zig_prestage_code(scriptlet.code or "")
        if helpers:
            helper_blocks.append(helpers)
        if not body:
            continue
        body_blocks.append(_ZIG_WRAPPER.format(idx=idx, body=body).strip())
    helpers_out = "\n\n".join(helper_blocks).strip()
    body_out = ("\n\n".join(body_blocks) + "\n") if body_blocks else ""
    return helpers_out, body_out


def wrap_zig_source(
    main_source: str,
    scriptlet_names: Optional[List[str]] = None,
    *,
    platform: str = "all",
    framework=None,
    context: Optional[dict] = None,
) -> str:
    """Inject resolved prestage modules into a Zig implant source template."""
    names = [n.strip() for n in (scriptlet_names or []) if str(n).strip()]
    if not names:
        return main_source
    scriptlets = resolve_scriptlet_names(
        names,
        platform=platform,
        language="zig",
        framework=framework,
        context=context,
    )
    helpers, prestage = build_zig_prestage_block(scriptlets)
    out = main_source
    if helpers and "__PRESTAGE_HELPERS__" in out:
        out = out.replace("__PRESTAGE_HELPERS__", helpers + "\n")
    elif helpers:
        out = helpers + "\n\n" + out
    if prestage and "__PRESTAGE__" in out:
        out = out.replace("__PRESTAGE__", prestage)
    elif prestage:
        out = prestage + out
    return out


def build_zig_prestage_block_legacy(scriptlets: List[Scriptlet]) -> str:
    _, body = build_zig_prestage_block(scriptlets)
    return body


def wrap_powershell_script(
    main_script: str,
    scriptlet_names: Optional[List[str]] = None,
    *,
    platform: str = "all",
    framework=None,
    context: Optional[dict] = None,
) -> str:
    """Prepend resolved prestage modules to a PowerShell implant script."""
    names = [n.strip() for n in (scriptlet_names or []) if str(n).strip()]
    if not names:
        return main_script
    scriptlets = resolve_scriptlet_names(
        names,
        platform=platform,
        language="powershell",
        framework=framework,
        context=context,
    )
    prestage = build_powershell_prestage_block(scriptlets)
    return prestage + (main_script or "")


def build_powershell_prestage_block(scriptlets: List[Scriptlet]) -> str:
    """Return PowerShell executed before the main payload body."""
    if not scriptlets:
        return ""
    blocks: List[str] = []
    for idx, scriptlet in enumerate(scriptlets):
        body = (scriptlet.code or "").strip()
        if not body:
            continue
        blocks.append(
            f"function __kitty_prestage_{idx}__ {{\n{body}\n}}\ntry {{ __kitty_prestage_{idx}__ }} catch {{}}\n"
        )
    return "\n".join(blocks) + ("\n" if blocks else "")


def wrap_python_script(
    main_script: str,
    scriptlet_names: Optional[List[str]] = None,
    *,
    platform: str = "all",
    framework=None,
    context: Optional[dict] = None,
) -> str:
    """Prepend resolved prestage modules to a Python implant script."""
    names = [n.strip() for n in (scriptlet_names or []) if str(n).strip()]
    if not names:
        return main_script
    scriptlets = resolve_scriptlet_names(
        names,
        platform=platform,
        language="python",
        framework=framework,
        context=context,
    )
    prestage = build_prestage_block(scriptlets)
    return prestage + (main_script or "")
