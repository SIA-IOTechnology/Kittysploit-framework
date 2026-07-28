#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAP Solution Manager (SolMan) running version 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAP Solution Manager 7.2 - Remote Command Execution Detection',
        'description': 'SAP Solution Manager (SolMan) running version 7.2 has a remote command execution vulnerability within the SAP EEM servlet (tc~smd~agent~application~eem). The vulnerability occurs due to missing authentication checks when submitting SOAP requests to the /EemAdminService/EemAdmin page to get information about connected SMDAgents, send HTTP request (SSRF), and execute OS commands on connected SMDAgent.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2020', 'cve', 'sap', 'solman', 'rce', 'kev', 'vkev', 'vuln'],
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
            'https://launchpad.support.sap.com/#/notes/2890213',
            'https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=540935305',
            'https://i.blackhat.com/USA-20/Wednesday/us-20-Artuso-An-Unauthenticated-Journey-To-Root-Pwning-Your-Companys-Enterprise-Software-Servers-wp.pdf',
            'https://github.com/chipik/SAP_EEM_CVE-2020-6207',
            'https://www.rapid7.com/db/modules/auxiliary/admin/sap/cve_2020_6207_solman_rce/',
        ],
        'cve': 'CVE-2020-6207',
    }

    def run(self):
        path = '/EemAdminService/EemAdmin'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'SOAPAction': '""', 'Content-Type': 'text/xml; charset=UTF-8', 'Connection': 'close'}, data='<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:adm="http://sap.com/smd/eem/admin/"><soapenv:Header/><soapenv:Body><adm:getAllAgentInfo/></soapenv:Body></soapenv:Envelope>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = (':Envelope', ':Body', ':getAllAgentInfoResponse',)
        header_any = ('text/xml', 'SAP NetWeaver Application Server',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='SAP Solution Manager 7.2 - Remote Command Execution detected', path=path)
            return True
        return False

