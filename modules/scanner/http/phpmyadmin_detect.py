#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'phpMyAdmin detection',
        'description': 'Detects if phpMyAdmin is installed on the target.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'phpmyadmin', 'mysql', 'panel'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.2,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/phpmyadmin_setup_detect'],
            },
        },
    }

    def _absolute_url(self, path: str) -> str:
        host = str(getattr(self, "target", None) or getattr(self, "rhost", None) or "").strip()
        if hasattr(host, "value"):
            host = str(host.value or "").strip()
        port = getattr(self, "port", None) or getattr(self, "rport", None)
        port_v = getattr(port, "value", port) if port is not None else None
        ssl = getattr(self, "ssl", None)
        ssl_v = getattr(ssl, "value", ssl) if ssl is not None else None
        scheme = "https" if ssl_v in (True, "true", "True", 1, "1") else "http"
        try:
            port_i = int(port_v) if port_v not in (None, "") else (443 if scheme == "https" else 80)
        except (TypeError, ValueError):
            port_i = 443 if scheme == "https" else 80
        path_s = path if str(path).startswith("/") else f"/{path}"
        if host.startswith("http://") or host.startswith("https://"):
            return host.rstrip("/") + path_s
        return f"{scheme}://{host}:{port_i}{path_s}"

    def run(self):
        paths = (
            "/phpmyadmin",
            "/phpmyadmin/",
            "/phpMyAdmin",
            "/phpMyAdmin/",
            "/phpMyAdmin/index.php",
            "/pma/",
            "/pma/index.php",
            "/mysql/",
            "/db/",
            "/sql/",
        )
        markers = (
            "phpmyadmin",
            "pmahomme",
            "pma_username",
            "pma_password",
            "db_structure.php",
            "navigation.php",
        )
        for path in paths:
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            hit = any(marker in body for marker in markers)
            loc = str(r.headers.get("Location") or "").lower()
            if not hit and ("phpmyadmin" in loc or "/pma" in loc):
                hit = True
            if not hit:
                continue

            final_url = str(getattr(r, "url", "") or "").strip() or self._absolute_url(path)
            self.report_finding(
                "phpMyAdmin panel exposed",
                severity="info",
                evidence={
                    "url": final_url,
                    "status_code": int(getattr(r, "status_code", 0) or 0) or None,
                    "path": path,
                    # Filled automatically when running: scanner ... --screenshots
                    # "screenshot": "output/evidence/.../phpmyadmin.png",
                },
                impact={
                    "summary": "A database administration interface is reachable without prior discovery friction.",
                    "business_risk": "Increased attack surface for credential stuffing and DB compromise",
                },
                remediation={
                    "summary": "Restrict access to phpMyAdmin.",
                    "actions": [
                        "Bind phpMyAdmin to internal networks only",
                        "Enforce strong authentication and MFA",
                        "Add IP allow-listing / VPN requirement",
                        "Remove unused phpMyAdmin installs"],
                },
            )
            return True
        return False
