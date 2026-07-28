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
        'tags': ['web', 'scanner', 'phpmyadmin', 'mysql'],
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
                    {'capability': 'admin_surface', 'from_detail': ''},
                    {'capability': 'db_access', 'from_detail': ''},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/phpmyadmin_setup_detect'],
            },
        },
    }

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
            if any(marker in body for marker in markers):
                self.set_info(
                    severity="info",
                    reason="phpMyAdmin panel detected",
                    path=path,
                )
                return True
            loc = str(r.headers.get("Location") or "").lower()
            if "phpmyadmin" in loc or "/pma" in loc:
                self.set_info(
                    severity="info",
                    reason="phpMyAdmin redirect detected",
                    path=path,
                )
                return True
        return False
