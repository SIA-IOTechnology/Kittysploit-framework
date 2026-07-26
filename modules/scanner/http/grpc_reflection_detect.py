#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect gRPC services and server reflection exposure."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.grpc.detectors import GRPC_AVAILABLE, probe_grpc


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "gRPC Reflection Detection",
        "description": "Detects gRPC endpoints and enumerates services when server reflection is enabled.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["grpc", "api", "scanner", "reflection", "rpc"],
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(50051, "gRPC TCP port", True)
    ssl = OptBool(False, "Use TLS for gRPC channel", required=False, advanced=True)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False

        result = probe_grpc(
            host,
            self._port(),
            timeout=self._timeout(),
            use_ssl=bool(self.ssl),
        )
        if not result.detected:
            print_info(result.error or "gRPC not detected")
            return False

        if result.reflection_enabled:
            services = result.services or []
            self.set_info(
                severity="medium",
                reason=f"gRPC reflection enabled — {len(services)} service(s)",
                services=services[:30],
            )
            print_warning(f"gRPC reflection enabled: {', '.join(services[:10])}")
            return True

        if result.heuristic_only:
            self.set_info(
                severity="info",
                reason=result.error or "gRPC port open; reflection not confirmed",
            )
            print_info(result.error or "gRPC port open")
            if not GRPC_AVAILABLE:
                print_info("Install grpcio and grpcio-reflection for full reflection probe")
            return False
        return False
