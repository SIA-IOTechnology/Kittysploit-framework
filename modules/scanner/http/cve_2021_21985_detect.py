#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in t."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VMware vSphere Client (HTML5) - Remote Code Execution Detection',
        'description': 'The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'packetstorm', 'rce', 'vsphere', 'vmware', 'kev', 'vkev', 'vuln'],
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
            'https://www.vmware.com/security/advisories/VMSA-2021-0010.html',
            'https://github.com/alt3kx/CVE-2021-21985_PoC',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21985',
            'http://packetstormsecurity.com/files/162812/VMware-Security-Advisory-2021-0010.html',
            'https://github.com/onSec-fr/CVE-2021-21985-Checker',
        ],
        'cve': 'CVE-2021-21985',
    }

    def run(self):
        path = '/ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.capability.VsanCapabilityProvider/getClusterCapabilityData'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': '*/*', 'Content-Type': 'application/json'}, data='{"methodInput":[{"type":"ClusterComputeResource","value": null,"serverGuid": null}]}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('{"result":{"isDisconnected":',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='VMware vSphere Client (HTML5) - Remote Code Execution detected', path=path)
            return True
        return False

