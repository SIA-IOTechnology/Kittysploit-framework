#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The blockchain RPC endpoint exposes the txpool_content method, which returns all pending (unmined) transaction."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Blockchain RPC - txpool_content Exposed Detection',
        'description': 'The blockchain RPC endpoint exposes the txpool_content method, which returns all pending (unmined) transactions in the mempool including sender addresses, transaction data, gas prices, and values. This enables frontrunning attacks, sandwich attacks, and other MEV (Maximal Extractable Value) exploitation against users.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfig', 'blockchain', 'rpc', 'txpool', 'mev', 'web3'],
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
            'https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-txpool',
            'https://ethereum.org/en/developers/docs/mev/',
        ],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"jsonrpc"', '"result"', '"pending"', '"queued"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Blockchain RPC - txpool_content Exposed detected', path=path)
            return True
        return False

