#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The blockchain RPC endpoint has debug-level tracing methods enabled (debug_traceTransaction, debug_traceBlockB."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Blockchain RPC Debug Trace Methods - Exposure Detection',
        'description': 'The blockchain RPC endpoint has debug-level tracing methods enabled (debug_traceTransaction, debug_traceBlockByNumber, trace_block, trace_filter). These methods return complete EVM execution traces including opcodes, stack values, and memory contents, enabling smart contract reverse engineering and targeted attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfig', 'blockchain', 'rpc', 'debug', 'trace', 'web3'],
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
            'https://geth.ethereum.org/docs/developers/dapp-developer/native',
            'https://github.com/ledgerwatch/erigon',
        ],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"jsonrpc":"2.0","method":"debug_traceTransaction","params":[],"id":1}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('does not exist', 'not available', 'not found', 'not supported',)
        body_all = ('"jsonrpc"', '"error"', 'missing value for required argument',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(severity='medium', reason='Blockchain RPC Debug Trace Methods - Exposure detected', path=path)
            return True
        return False

