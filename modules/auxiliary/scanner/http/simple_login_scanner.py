#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Simple Login Scanner',
        'description': 'Simple scanner that detects login forms on a web page',
        'author': 'KittySploit Team',
        'modules': ['auxiliary/scanner/http/login/admin_login_bruteforce'],
        'tags': ['web', 'scanner', 'login', 'auth'],
    }

    path = OptString("/", "Path to test", required=False)

    def check(self):
        try:
            response = self.http_request(method="GET", path="/", allow_redirects=True)
            return bool(response)
        except Exception:
            return False

    def _normalize_path(self, value):
        value = (value or "").strip()
        if not value:
            return "/"
        if not value.startswith("/"):
            value = f"/{value}"
        return value

    def _looks_like_login(self, html):
        if not html:
            return False, []

        content = html.lower()
        indicators = []

        if re.search(r'<input[^>]+type=["\']?password["\']?', content, re.IGNORECASE):
            indicators.append("password_field")
        if re.search(r'<input[^>]+type=["\']?email["\']?', content, re.IGNORECASE):
            indicators.append("email_field")
        if re.search(r'<input[^>]+name=["\']?(username|user|login|email)["\']?', content, re.IGNORECASE):
            indicators.append("user_field")
        if re.search(r'(login|log in|sign in|connexion|admin)', content, re.IGNORECASE):
            indicators.append("login_keywords")
        if re.search(r'<form', content, re.IGNORECASE):
            indicators.append("form_tag")

        is_login = "password_field" in indicators and ("user_field" in indicators or "email_field" in indicators)
        return is_login, indicators

    def run(self):
        test_path = self._normalize_path(self.path)
        print_status("Starting simple login scanner...")
        print_info(f"Target: {self.target}")
        print_info(f"Path: {test_path}")
        print_info("")

        try:
            response = self.http_request(method="GET", path=test_path, allow_redirects=True)
        except Exception as e:
            print_error(f"Request error: {e}")
            self.vulnerability_info = {
                'reason': f"Request failed on {test_path}",
                'severity': 'Info'
            }
            return False

        if not response:
            print_error("No response received.")
            self.vulnerability_info = {
                'reason': "No HTTP response",
                'severity': 'Info'
            }
            return False

        is_login, indicators = self._looks_like_login(response.text or "")
        indicator_text = ", ".join(indicators) if indicators else "none"

        effective_path = self.response_effective_path(test_path, response)

        if is_login:
            redir = f" (redirect from {test_path})" if effective_path != test_path else ""
            print_success(f"Login page detected on {effective_path}{redir} (HTTP {response.status_code})")
            print_info(f"Indicators: {indicator_text}")
            self.vulnerability_info = {
                'reason': f"Login page detected on {effective_path}",
                'severity': 'Info',
                'status_code': response.status_code,
                'login_path': effective_path,
            }
            return True

        print_warning(f"No login page detected on {test_path} (HTTP {response.status_code})")
        print_info(f"Indicators: {indicator_text}")
        self.vulnerability_info = {
            'reason': f"No login page detected on {test_path}",
            'severity': 'Info',
            'status_code': response.status_code
        }
        return False
