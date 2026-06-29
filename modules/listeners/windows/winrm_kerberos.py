#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from kittysploit import *

try:
    from pypsrp.client import Client
    PYPSRP_AVAILABLE = True
except Exception:
    Client = None
    PYPSRP_AVAILABLE = False


class Module(Listener):
    __info__ = {
        "name": "WinRM Kerberos Client",
        "description": "Creates a WinRM session over HTTP/HTTPS using Kerberos tickets from KRB5CCNAME.",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": "winrm",
        "protocol": "winrm",
        "dependencies": ["pypsrp", "requests-kerberos"],
    }

    rhost = OptString("dc.example.local", "Target WinRM host", True)
    rport = OptPort(5986, "Target WinRM port", True)
    username = OptString("", "Optional username hint for session metadata", False)
    kccache = OptString("", "Optional KRB5CCNAME ccache path", False)
    ssl = OptBool(True, "Use HTTPS transport", False)
    cert_validation = OptBool(False, "Validate server TLS certificate", False)
    test_command = OptString("whoami", "Command used to verify the WinRM session", False)

    def run(self):
        if not PYPSRP_AVAILABLE:
            print_error("pypsrp is not installed. Install pypsrp and requests-kerberos to use this listener.")
            return False

        if self.kccache:
            os.environ["KRB5CCNAME"] = str(self.kccache)

        try:
            print_status(f"Connecting to WinRM {self.rhost}:{self.rport} with Kerberos")
            client = Client(
                str(self.rhost),
                port=int(self.rport),
                ssl=bool(self.ssl),
                auth="kerberos",
                cert_validation=bool(self.cert_validation),
            )
            command = str(self.test_command or "whoami")
            stdout, stderr, rc = client.execute_cmd(command)
            if rc != 0:
                print_warning(f"WinRM command returned {rc}")
                if stderr:
                    print_info(stderr)
            else:
                print_success("WinRM Kerberos session verified")
                if stdout:
                    print_info(stdout.strip())
            return (
                client,
                str(self.rhost),
                int(self.rport),
                {
                    "username": str(self.username or ""),
                    "ssl": bool(self.ssl),
                    "kccache": str(self.kccache or ""),
                    "auth": "kerberos",
                },
            )
        except Exception as e:
            print_error(f"WinRM Kerberos connection failed: {e}")
            return False

    def shutdown(self):
        return True

