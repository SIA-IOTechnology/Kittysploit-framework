#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection PFCP (UDP 8805) - 5G N4 interface (SMF-UPF)."""

import socket
from kittysploit import *
from core.framework.option import OptPort
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


def _pfcp_probe_udp(host: str, port: int, timeout: float = 2.0) -> bool:
    """Send minimal PFCP Heartbeat Request; return True if response received."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        # PFCP header: version 1, S=0, message type 60 (Heartbeat Request), length 4
        probe = bytes([0x20, 0x3C, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
        s.sendto(probe, (host, port))
        data, _ = s.recvfrom(4096)
        s.close()
        return len(data) >= 8
    except (socket.timeout, OSError):
        return False


class Module(Scanner, Tcp_scanner_client):

    __info__ = {
        "name": "PFCP UDP detection",
        "description": "Detects PFCP port 8805 (5G N4 - SMF/UPF control plane).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["telecom", "scanner", "5g", "pfcp", "3gpp", "n4", "upf", "smf"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
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
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(8805, "PFCP port (8805)", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        port = self._port()
        if port in (80, 443, 3868, 2152):
            port = 8805
        if _pfcp_probe_udp(host, port, self._timeout()):
            self.set_info(severity="medium", reason="PFCP port 8805 responsive (5G N4)")
            return True
        return False
