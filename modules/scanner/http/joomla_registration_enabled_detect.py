#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Joomla user registration enabled, allowing anyone to create accounts on the site."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla - User Registration Enabled Detection',
        'description': 'Detected Joomla user registration enabled, allowing anyone to create accounts on the site. If not intentionally configured, this could lead to unauthorized access or spam account creation.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'joomla', 'misconfig', 'exposure'],
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
            'https://docs.joomla.org/J3.x:Users/en',
            'https://www.doctorjoomla.com/15-joomla/100-disable-user-registration',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?option=com_users&view=registration', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('jform[name]', 'jform[username]', 'jform[password1]', 'jform[email1]',)
        body_all = ('com_users', 'registration', '<form',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="Joomla - User Registration Enabled detected",
                path='/index.php?option=com_users&view=registration',
            )
            return True
        return False

