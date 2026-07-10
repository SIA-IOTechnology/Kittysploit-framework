"""Acrobat anti-emulation guards for PDF JavaScript (corkami tricks).

Detects real Adobe Reader before running callback payloads. Naive sandboxes
and non-Acrobat engines typically fail the zoomType or global-variable probes.

Ref: https://github.com/corkami/docs/blob/master/PDF/PDF.md#anti-emulators
"""

from __future__ import annotations

# PDF.js / browser-context payloads must not be wrapped (no Acrobat ``app`` object).
_BROWSER_API_HINTS = (b"fetch(", b"XMLHttpRequest", b"new Image", b"WebSocket")

# Already guarded.
_SKIP_HINTS = (
    b"zoomType",
    b"_ksg=",
)


def _acrobat_guard_js() -> bytes:
    """Return a compact guard prefix (latin-1 bytes, no trailing semicolon)."""
    return (
        b"if(typeof app=='undefined')return;"
        b"try{"
        b"var _zt=event.target.zoomType;"
        b"if(!_zt||(_zt!='FitPage'&&(!_zt.toString||_zt.toString()!='FitPage')))return;"
        b"_ksg=0;var _ksl=0;_ksg='k';"
        b"if(_ksl!==0||typeof _ksg=='string')return;"
        b"}catch(e){return;}"
    )


def wrap_js_anti_emulation(js_content: bytes) -> bytes:
    """Prepend corkami-style anti-emulation checks to Acrobat JS."""
    if not js_content or len(js_content) < 8:
        return js_content
    if any(hint in js_content for hint in _BROWSER_API_HINTS):
        return js_content
    if any(hint in js_content for hint in _SKIP_HINTS):
        return js_content
    return _acrobat_guard_js() + js_content


def apply_anti_emulation(data: bytes, rewrite_js_blocks) -> bytes:
    """Wrap every /JS (...) block in ``data`` with anti-emulation guards."""
    return rewrite_js_blocks(data, wrap_js_anti_emulation)
