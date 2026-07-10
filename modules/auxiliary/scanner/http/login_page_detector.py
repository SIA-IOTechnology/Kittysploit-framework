#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.module_result import finalize_http_scanner_run, target_base_url
import re


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Login Page Detector',
        'description': 'Detects whether a target exposes login pages (admin/login, email+password, username+password)',
        'author': 'KittySploit Team',
        'modules': ['auxiliary/scanner/http/login/admin_login_bruteforce'],
        'tags': ['web', 'scanner', 'login', 'auth', 'admin'],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints', 'params'],
        'chain': {
            'produces_capabilities': ['credentials'],
            'suggested_followups': ['auxiliary/scanner/http/login/admin_login_bruteforce'],
        },
    },
    }

    scan_common_paths = OptBool(True, "Scan common login paths", required=False)
    custom_paths = OptString("", "Extra paths to scan (comma separated)", required=False)
    max_paths = OptInteger(20, "Maximum number of paths to test", required=False, advanced=True)
    min_score = OptInteger(4, "Minimum score required to classify as login page", required=False, advanced=True)

    COMMON_LOGIN_PATHS = [
        '/',
        '/login',
        '/signin',
        '/sign-in',
        '/auth/login',
        '/account/login',
        '/admin',
        '/admin/login',
        '/administrator',
        '/user/login',
        '/members/login',
        '/portal/login',
        '/wp-login.php',
        '/wp-admin',
        '/backend/login',
    ]

    POSITIVE_PATTERNS = {
        'password_input': (r'<input[^>]+type=["\']?password["\']?', 3),
        'email_input': (r'<input[^>]+type=["\']?email["\']?', 2),
        'username_name': (r'<input[^>]+name=["\']?(username|user|login|email)["\']?', 2),
        'login_form_action': (r'<form[^>]+action=["\'][^"\']*(login|signin|auth|session)[^"\']*["\']', 2),
        'login_text': (r'(sign in|signin|log in|login|connexion|se connecter)', 1),
        'admin_text': (r'(admin(istrator)?|backoffice|dashboard)', 1),
        'submit_button': (r'<button[^>]*>([^<]*(sign in|log in|login|connexion)[^<]*)</button>', 1),
        'csrf_token': (r'(csrf|authenticity_token|_token)', 1),
    }

    NEGATIVE_PATTERNS = {
        'register_only': (r'(create account|sign up|register)', 1),
        'reset_only': (r'(forgot password|reset password)', 1),
    }

    ERROR_DECOY_PATTERNS = {
        "http_error_title": r"<title[^>]*>\s*(?:4\d{2}|5\d{2}|error|not found|access denied|forbidden|service unavailable)[^<]*</title>",
        "traceback": r"(traceback|exception|stack trace|fatal error|uncaught)",
        "maintenance": r"(maintenance mode|temporarily unavailable|service unavailable)",
        "waf_block": r"(request blocked|access denied|forbidden|incident id|captcha|cloudflare|akamai|imperva)",
        "missing_resource": r"(page not found|404|resource not found|cannot be found)",
    }

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

    def _build_paths(self):
        paths = []

        if self.scan_common_paths:
            paths.extend(self.COMMON_LOGIN_PATHS)

        if self.custom_paths:
            for item in self.custom_paths.split(","):
                normalized = self._normalize_path(item)
                if normalized:
                    paths.append(normalized)

        # Keep order while removing duplicates.
        unique_paths = list(dict.fromkeys(paths))

        if self.max_paths > 0:
            unique_paths = unique_paths[:self.max_paths]

        return unique_paths

    def _analyze_login_markers(self, html):
        if not html:
            return 0, []

        content = html.lower()
        score = 0
        indicators = []

        for indicator_name, (pattern, weight) in self.POSITIVE_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                score += weight
                indicators.append(indicator_name)

        # Optional penalty for pages that look like registration/reset only.
        for _, (pattern, weight) in self.NEGATIVE_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                score -= weight

        # If there is no password field, reduce confidence heavily.
        if 'password_input' not in indicators:
            score -= 2

        if score < 0:
            score = 0

        return score, indicators

    def _confidence_from_score(self, score):
        if score >= 7:
            return "High"
        if score >= self.min_score:
            return "Medium"
        return "Low"

    def _error_decoy_markers(self, html, status_code):
        markers = []
        content = (html or "").lower()
        if int(status_code or 0) >= 400:
            markers.append(f"http_{int(status_code)}")
        for key, pattern in self.ERROR_DECOY_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                markers.append(key)
        return markers

    def _detect_on_path(self, path):
        try:
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                return None

            # 401/403 can still indicate protected login resources.
            if response.status_code not in [200, 401, 403]:
                return None

            score, indicators = self._analyze_login_markers(response.text or "")
            decoy_markers = self._error_decoy_markers(response.text or "", response.status_code)
            is_login_page = (
                score >= self.min_score
                and 'password_input' in indicators
                and not decoy_markers
            )

            effective_path = self.response_effective_path(path, response)

            return {
                'path': effective_path,
                'requested_path': path,
                'status': response.status_code,
                'score': score,
                'confidence': self._confidence_from_score(score),
                'indicators': indicators,
                'decoy_markers': decoy_markers,
                'login_error_decoy': bool(decoy_markers),
                'is_login_page': is_login_page,
                'title': self._extract_title(response.text or "")
            }
        except Exception as e:
            print_debug(f"Path detection failed for {path}: {e}")
            return None

    def _extract_title(self, html):
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if not match:
            return ""
        title = re.sub(r'\s+', ' ', match.group(1)).strip()
        return title[:80]

    def run(self):
        paths = self._build_paths()
        detections = []
        suspicious_pages = []
        self.login_paths = []

        print_status("Starting login page detection...")
        print_info(f"Target: {self.target}")
        print_info(f"Paths to test: {len(paths)}")
        print_info("")

        if not paths:
            print_error("No paths to scan. Enable scan_common_paths or set custom_paths.")
            self.vulnerability_info = {
                'reason': 'No paths to scan',
                'severity': 'Info'
            }
            return False

        seen_effective = set()
        for path in paths:
            print_status(f"Checking: {path}")
            result = self._detect_on_path(path)
            if not result:
                continue

            if result['is_login_page']:
                eff = result.get("path") or path
                if eff in seen_effective:
                    print_info(f"Skipping duplicate final URL (already seen {eff})")
                    continue
                seen_effective.add(eff)
                detections.append(result)
                shown = result["path"]
                req = result.get("requested_path", path)
                redirect_note = f" (redirect from {req})" if shown != req else ""
                print_success(
                    f"Login page detected on {shown}{redirect_note} "
                    f"(status={result['status']}, score={result['score']}, confidence={result['confidence']})"
                )
            elif result.get("login_error_decoy") and result.get("score", 0) >= max(2, int(self.min_score) - 1):
                suspicious_pages.append(result)
                print_warning(
                    f"Suspicious login-like decoy/error page on {result['path']} "
                    f"(status={result['status']}, score={result['score']}, decoy={','.join(result.get('decoy_markers', [])[:3])})"
                )
            else:
                print_info(
                    f"No login marker match on {path} "
                    f"(status={result['status']}, score={result['score']})"
                )

        print_info("")

        if detections:
            table_data = []
            for entry in detections:
                indicator_preview = ", ".join(entry['indicators'][:4])
                table_data.append([
                    entry['path'],
                    entry['status'],
                    entry['score'],
                    entry['confidence'],
                    indicator_preview
                ])

            print_success(f"Detected {len(detections)} login page(s).")
            print_table(['Path', 'HTTP', 'Score', 'Confidence', 'Indicators'], table_data)
            self.login_paths = [entry["path"] for entry in detections if entry.get("path")]

            return finalize_http_scanner_run(
                self,
                detections,
                title="Login page detected",
                severity="info",
                reason=f"Detected {len(detections)} login page(s)",
                category="recon",
                findings_key="login_pages",
                dedupe_keys=("path",),
                hit_mapper=lambda entry: {
                    "path": entry.get("path"),
                    "method": "GET",
                    "request_url": target_base_url(self, path=str(entry.get("path") or "/")),
                    "status_code": entry.get("status"),
                    "type": "login_page",
                    "evidence_snippet": ", ".join(entry.get("indicators") or []),
                },
                vulnerability_info_extra={
                    "paths": ", ".join(d["path"] for d in detections[:5]),
                    "login_path": detections[0]["path"],
                    "login_error_decoy": False,
                    "suspicious_login_pages": [],
                },
            )

        if suspicious_pages:
            table_data = []
            for entry in suspicious_pages[:8]:
                table_data.append([
                    entry["path"],
                    entry["status"],
                    entry["score"],
                    ", ".join(entry.get("decoy_markers", [])[:3]) or "-",
                ])
            print_warning(f"Detected {len(suspicious_pages)} suspicious login-like error/decoy page(s).")
            print_table(['Path', 'HTTP', 'Score', 'Decoy Markers'], table_data)
            return finalize_http_scanner_run(
                self,
                suspicious_pages,
                title="Suspicious login-like page",
                severity="low",
                reason=f"Suspicious login-like decoy/error page(s): {len(suspicious_pages)}",
                category="recon",
                findings_key="suspicious_login_pages",
                dedupe_keys=("path",),
                hit_mapper=lambda entry: {
                    "path": entry.get("path"),
                    "method": "GET",
                    "request_url": target_base_url(self, path=str(entry.get("path") or "/")),
                    "status_code": entry.get("status"),
                    "type": "login_decoy",
                    "evidence_snippet": ", ".join(entry.get("decoy_markers") or []),
                },
                vulnerability_info_extra={
                    "login_error_decoy": True,
                    "suspicious_login_pages": [row.get("path", "") for row in suspicious_pages[:10]],
                    "paths": ", ".join(row.get("path", "") for row in suspicious_pages[:5]),
                },
            )

        print_warning("No login page detected with current heuristics.")
        self.vulnerability_info = {
            'reason': 'No login page detected',
            'severity': 'Info'
        }
        return self.module_result(success=True)
