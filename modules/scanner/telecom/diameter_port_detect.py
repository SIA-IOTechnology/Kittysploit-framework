#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection port Diameter (3GPP LTE/5G - authentification, abonnés)."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):

    __info__ = {
        "name": "Diameter port detection",
        "description": "Detects open Diameter port (3868) - 3GPP LTE/5G S6a/S6d, authentication.",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["telecom", "scanner", "5g", "lte", "diameter", "3gpp", "mobile"],
    }

    def _likely_diameter_not_misconfigured_http(self, host: str, port: int) -> bool:
        """
        Seul un port TCP ouvert ne suffit pas (3868 peut servir à autre chose).
        On exclut les réponses HTTP/HTML/SSH/TLS évidentes, et on accepte un en-tête Diameter (v1).
        """
        timeout = min(float(self._timeout()), 5.0)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            # Beaucoup de faux positifs : service HTTP ou autre sur 3868
            s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            try:
                data = s.recv(8192)
            except socket.timeout:
                data = b""
            finally:
                s.close()
        except Exception:
            return False

        if not data:
            # Pas de bannière texte : possible Diameter en attente de CER — on ne conclut pas (trop de FP)
            return False

        head = data[:1200]
        u = head.upper()
        if head.startswith(b"HTTP/") or b"HTTP/1." in head[:24]:
            return False
        if b"<HTML" in u or b"<!DOCTYPE" in u or b"<HEAD" in u:
            return False
        if head.startswith(b"SSH-"):
            return False
        # TLS record
        if head[0:1] == b"\x16":
            return False
        # Diameter : version 1, longueur sur 3 octets (RFC 6733)
        if len(head) >= 4 and head[0] == 1:
            mlen = (head[1] << 16) | (head[2] << 8) | head[3]
            if 20 <= mlen <= 65536:
                return True
        return False

    def run(self):
        if not self._host():
            return False
        if not self.is_tcp_open():
            return False
        h = self._host()
        p = self._port()
        if self._likely_diameter_not_misconfigured_http(h, p):
            self.set_info(severity="medium", reason="Diameter port 3868 open (3GPP control plane)")
            return True
        return False
