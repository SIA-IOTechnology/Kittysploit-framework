#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Detect Amazon-S3 Bucket."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Detect Amazon-S3 Bucket',
        'description': 'Detects Detect Amazon-S3 Bucket.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'aws', 's3', 'bucket', 'tech'],
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
    }

    def run(self):
        r = self.http_request(method="GET", path='/%c0', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_markers = ('amazons3',)
        body_word_hit = any(m in body for m in body_markers)
        body_regexes = ('(?:InvalidURI|InvalidArgument|NoSuchBucket)',)
        body_re_hit = any(re.search(rx, body, re.I) for rx in body_regexes)
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        header_markers = ('x-amz-id', 'x-amz-request-id',)
        if body_re_hit:
            self.set_info(
                severity='info',
                reason="Detect Amazon-S3 Bucket detected",
                path='/%c0',
            )
            return True
        return False

