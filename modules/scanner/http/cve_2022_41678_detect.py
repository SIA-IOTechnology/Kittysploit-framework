#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Once an user is authenticated on Jolokia, he can potentially trigger arbitrary code execution."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache ActiveMQ < 5.16.5/5.17.3 - Remote Code Execution Detection',
        'description': 'Once an user is authenticated on Jolokia, he can potentially trigger arbitrary code execution. In details, in ActiveMQ configurations, jetty allows org.jolokia.http.AgentServlet to handler request to /api/jolokia org.jolokia.http.HttpRequestHandler#handlePostRequest is able to create JmxRequest through JSONObject. And calls to org.jolokia.http.HttpRequestHandler#executeRequest. Into deeper calling stacks, org.jolokia.handler.ExecHandler#doHandleRequest can be invoked through refection. This could lead to RCE through via various mbeans. One example is unrestricted deserialization in jdk.management.jfr.FlightRecorderMXBeanImpl which exists on Java version above 11. 1 Call newRecording. 2 Call setConfiguration. And a webshell data hides in it. 3 Call startRecording. 4 Call copyTo method. The webshell will be written to a .jsp file. The mitigation is to restrict (by default) the actions authorized on Jolokia, or disable Jolokia. A more restrictive Jolokia configuration has been defined in default ActiveMQ distribution. We encourage users to upgrade to ActiveMQ distributions version including updated Jolokia configuration: 5.16.6, 5.17.4, 5.18.0, 6.0.0.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'activemq', 'rce', 'jolokia', 'authenticated'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2022-41678',
            'https://activemq.apache.org/security-advisories.data/CVE-2022-41678-announcement.txt',
            'https://l3yx.github.io/2023/11/29/Apache-ActiveMQ-Jolokia-%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E-CVE-2022-41678-%E5%88%86%E6%9E%90/',
        ],
        'cve': 'CVE-2022-41678',
    }

    def run(self):
        path = '/api/jolokia/list/org.apache.logging.log4j2'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Authorization': 'Basic YWRtaW46YWRtaW4=', 'Origin': '{{RootURL}}'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('org.apache.logging.log4j2',)
        body_all = ('setConfigText', 'getConfigText',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(severity='high', reason='Apache ActiveMQ < 5.16.5/5.17.3 - Remote Code Execution detected', path=path)
            return True
        return False

