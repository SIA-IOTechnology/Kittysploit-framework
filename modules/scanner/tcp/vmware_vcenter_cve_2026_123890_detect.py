#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-123890 — VMware vmdir rpc_srp_verifier (TCP 2012) surface detect."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.protocols.tcp.vcenter_vmdird import Vcenter_vmdird


class Module(Scanner, Tcp_scanner_client, Vcenter_vmdird):
    __info__ = {
        "name": "VMware vCenter vmdir CVE-2026-123890 detect",
        "description": (
            "DCE/RPC bind to rpc_srp_verifier on TCP 2012 (vmdird). "
            "Flags hosts exposing the pre-auth SRP verifier interface."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-123890"],
        "references": [
            "https://github.com/vmware-archive/lightwave",
        ],
        "tags": ["vmware", "vcenter", "vmdir", "dce-rpc", "cve-2026-123890"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/scanner/tcp/vmware_vcenter_vmdir_key_probe",
                    "exploits/multi/tcp/vmware_vcenter_cve_2026_123890_vmdir_disclosure",
                ],
            },
        },
    }

    port = OptPort(2012, "vmdird DCE/RPC port", required=False)
    check_dbcp = OptBool(False, "Also negotiate vmdirdbcp context", advanced=True)

    def run(self):
        if not self.is_tcp_open():
            return False
        result = self.vmdird_probe(include_dbcp=bool(self.check_dbcp))
        if not result.get("ok") or not result.get("srp_accepted"):
            if result.get("error"):
                print_status(result["error"])
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-123890",
            reason="rpc_srp_verifier bind accepted",
            sec_addr=result.get("sec_addr"),
            dbcp_accepted=result.get("dbcp_accepted"),
        )
        return True