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


def exploit_debug_bootstrap(title: str, subtitle: str = "", enabled: bool = True) -> str:
    """JS snippet to open the in-page visual exploit debugger."""
    return (
        f"KS.debug.init({{title: {js_string(title)}, "
        f"subtitle: {js_string(subtitle)}, enabled: {'true' if enabled else 'false'}}});"
    )


def exploit_debug_helpers() -> str:
    """Shared klog/finish helpers for browser exploit scripts."""
    return """
function klog(msg, type) {
  if (window.KS && KS.debug) {
    KS.debug.log(msg, type || 'info');
  } else if (typeof console !== 'undefined' && console.log) {
    console.log(msg);
  }
}
function finish(ok, stage, message, extra) {
  if (window.KS && KS.debug) {
    return KS.debug.finish(ok, stage, message, extra || {});
  }
  return JSON.stringify({ ok: !!ok, stage: stage || 'unknown', message: message || '', sessionExpected: !!ok });
}
"""


def maglev_optimizer_helpers() -> str:
    """Try d8-style Maglev intrinsics when Chrome is launched with --allow-natives-syntax."""
    return """
var KS_MAGLEV_LAST_ERROR = '';
function ksMaglevLastError() {
  return KS_MAGLEV_LAST_ERROR;
}
function ksMaglevNativeAvailable(fn) {
  try {
    if (typeof fn !== 'function') {
      throw new Error('Maglev target function unavailable');
    }
    eval('%PrepareFunctionForOptimization(fn)');
    KS_MAGLEV_LAST_ERROR = '';
    return true;
  } catch (e) {
    KS_MAGLEV_LAST_ERROR = String(e && e.message ? e.message : e);
    return false;
  }
}
function ksOptimizeMaglevBlah(fn) {
  try {
    if (typeof fn !== 'function') {
      throw new Error('Maglev target function unavailable');
    }
    eval('%OptimizeMaglevOnNextCall(fn)');
    KS_MAGLEV_LAST_ERROR = '';
    return true;
  } catch (e) {
    KS_MAGLEV_LAST_ERROR = String(e && e.message ? e.message : e);
    return false;
  }
}
function ksNativeEval(expr) {
  try {
    return String(eval(expr));
  } catch (e) {
    return 'ERR:' + String(e && e.message ? e.message : e);
  }
}
function ksMaglevStatus(fn) {
  if (typeof fn !== 'function') {
    return 'target unavailable';
  }
  try {
    globalThis.__ksMaglevStatusTarget = fn;
  } catch (e) {}
  var parts = [];
  var status = ksNativeEval('%GetOptimizationStatus(__ksMaglevStatusTarget)');
  if (status && status.indexOf('ERR:') !== 0) {
    parts.push('status=' + status);
  }
  var maglevved = ksNativeEval('%IsMaglevved(__ksMaglevStatusTarget)');
  if (maglevved && maglevved.indexOf('ERR:') !== 0) {
    parts.push('is_maglevved=' + maglevved);
  }
  var activeMaglev = ksNativeEval('%ActiveTierIsMaglev(__ksMaglevStatusTarget)');
  if (activeMaglev && activeMaglev.indexOf('ERR:') !== 0) {
    parts.push('active_tier_maglev=' + activeMaglev);
  }
  if (parts.length) {
    return parts.join(' ');
  }
  return 'status unavailable (' + status + ')';
}
"""


def bundle_visual_debug_only(title: str, subtitle: str = "", enabled: bool = True) -> str:
    """Small JS payload that only opens the in-page visual debugger."""
    boot = exploit_debug_bootstrap(title, subtitle, enabled)
    script = f"(function(){{ {boot} return true; }})();"
    return bundle_with_generic_lib(script)


def wrap_visual_exploit_script(
    exploit_body: str,
    debug_boot: str,
    debug_helpers: str,
    paint_delay_ms: int = 100,
) -> str:
    """
    Wrap exploit logic in a Promise so the debug overlay can paint before
    long synchronous V8 work blocks the browser main thread.
    """
    indented = "\n".join(
        ("                " + line) if line.strip() else line for line in exploit_body.splitlines()
    )
    return f"""
(function() {{
    {debug_boot}
    {debug_helpers}
    return new Promise(function(resolve) {{
        setTimeout(function() {{
            try {{
{indented}
            }} catch (e) {{
                klog(String(e && e.stack ? e.stack : e), "error");
                resolve(finish(false, "exception", String(e)));
            }}
        }}, {paint_delay_ms});
    }});
}})();
"""
