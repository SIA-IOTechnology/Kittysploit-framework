#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Weiphp panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Weiphp Panel - Detect',
        'description': 'Weiphp panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'weiphp'],
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
        },
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_l = body.lower()
        if '_blank">WeiPHP' not in body and '/weiphp.css?' not in body_l:
            return False
        self.set_info(
            severity='info',
            reason="Weiphp Panel detected",
            path='/index.php',
        )
        return True
