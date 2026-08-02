#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache NiFi 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache NiFi - Information Disclosure Detection',
        'description': 'Apache NiFi 1.10.0 through 2.0.0 are missing fine-grained authorization checking for Parameter Contexts, referenced Controller Services, and referenced Parameter Providers, when creating new Process Groups. Creating a new Process Group can include binding to a Parameter Context, but in cases where the Process Group did not reference any Parameter values, the framework did not check user authorization for the bound Parameter Context. Missing authorization for a bound Parameter Context enabled clients to download non-sensitive Parameter values after creating the Process Group.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'nifi', 'exposure', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                    }],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://lists.apache.org/thread/cjc8fns5kjsho0s7vonlnojokyfx47wn',
            'http://www.openwall.com/lists/oss-security/2024/12/28/1',
            'https://github.com/absholi7ly/CVE-2024-56512-Apache-NiFi-Exploit/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-56512'],
        'cve': 'CVE-2024-56512',
    }

    def run(self):
        for path in ('/nifi-api/flow/process-groups/root', '/nifi-api/controller/config'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('application/json',)
            body_all = ('processGroupFlow', 'breadcrumb', 'maxTimerDrivenThreadCount', 'maxEventDrivenThreadCount',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Apache NiFi - Information Disclosure detected",
                    path=path,
                )
                return True
        return False

