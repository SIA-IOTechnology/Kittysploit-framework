#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect RabbitMQ AMQP service on TCP 5672."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.rabbitmq.detectors import probe_rabbitmq_amqp


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "RabbitMQ AMQP Detection",
        "description": "Detects RabbitMQ AMQP 0-9-1 protocol on port 5672.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "metadata": {"max-request": 1, "product": "rabbitmq", "vendor": "vmware"},
        "tags": ["rabbitmq", "amqp", "scanner", "discovery", "messaging"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 1,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals'],
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

    port = OptPort(5672, "RabbitMQ AMQP port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_rabbitmq_amqp(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        self.set_info(
            severity="info",
            reason="RabbitMQ AMQP service detected",
            banner=str(info.get("banner") or ""),
        )
        return True
