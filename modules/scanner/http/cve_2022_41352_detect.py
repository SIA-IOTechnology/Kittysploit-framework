#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered in Zimbra Collaboration (ZCS) 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zimbra Collaboration - Unrestricted File Upload Detection',
        'description': 'An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15 and 9.0. An attacker can upload arbitrary files through amavis via a cpio loophole (extraction to /opt/zimbra/jetty/webapps/zimbra/public) that can lead to incorrect access to any other user accounts. Zimbra recommends pax over cpio. Also, pax is in the prerequisites of Zimbra on Ubuntu; however, pax is no longer part of a default Red Hat installation after RHEL 6 (or CentOS 6). Once pax is installed, amavis automatically prefers it over cpio.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'zimbra', 'kev', 'file-upload', 'passive', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.secpod.com/blog/unpatched-rce-bug-in-zimbra-collaboration-suite-exploited-in-wild/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-41352',
        ],
        'cve': 'CVE-2022-41352',
    }

    def run(self):
        path = '/js/zimbraMail/share/model/ZmSettings.js'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('Zimbra Collaboration Suite Web Client', '8.8.15', '9.0',)
        ctype_any = ('application/x-javascript',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='critical',
                reason='Zimbra Collaboration - Unrestricted File Upload detected',
                path=path,
            )
            return True
        return False

