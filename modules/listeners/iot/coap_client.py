#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CoAP bind listener — opens an interactive CoAP session toward a device."""

from kittysploit import *
from lib.protocols.coap.client import COAP_PORT, COAPS_PORT, CoapClient, dtls_support


class Module(Listener):
    __info__ = {
        "name": "CoAP Client",
        "description": (
            "Connects to a CoAP/CoAPS UDP endpoint, probes .well-known/core, and creates "
            "an interactive CoAP shell session (GET/POST/PUT/DELETE/Observe stream)."
        ),
        "author": "KittySploit Team",
        "version": "1.1.0",
        "handler": Handler.BIND,
        "session_type": SessionType.COAP,
        "protocol": "coap",
        "tags": ["iot", "coap", "coaps"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["coap_access", "ot_assets"],
                "suggested_followups": [
                    "post/coap/gather/resource_enum",
                    "post/coap/gather/observe_dump",
                    "post/coap/gather/config_dump",
                ],
            },
        },
    }

    rhost = OptString("127.0.0.1", "Target CoAP host", True)
    rport = OptPort(COAP_PORT, "CoAP UDP port (5684 for CoAPS)", True)
    dtls = OptBool(False, "Use DTLS/CoAPS (experimental; needs OpenSSL DTLS)", False)

    def run(self):
        host = str(self.rhost).strip()
        use_dtls = bool(self.dtls)
        port = int(self.rport)
        if use_dtls and port == COAP_PORT:
            port = COAPS_PORT
        timeout = float(self.timeout or 5)

        if use_dtls:
            support = dtls_support()
            print_status(
                f"CoAPS/DTLS requested — support={support['available']} "
                f"protocols={support['protocols'] or ['none']}"
            )
            if not support["available"]:
                print_error(support["note"])
                return False

        scheme = "coaps" if use_dtls else "coap"
        print_status(f"Probing {scheme}://{host}:{port}...")
        client = CoapClient(host, port, timeout, dtls=use_dtls)
        if not client.connect():
            print_error(client.last_error or f"CoAP probe failed for {host}:{port}")
            return False

        wk = client.last_well_known or ""
        if wk:
            print_success(f"CoAP .well-known/core ({len(wk)} bytes)")
            print_info(wk[:300] + ("..." if len(wk) > 300 else ""))
        else:
            print_warning("Connected socket ready but .well-known/core empty/timeout")

        additional_data = {
            "host": host,
            "port": port,
            "protocol": "coaps" if use_dtls else "coap",
            "dtls": use_dtls,
            "platform": "iot",
            "well_known": wk,
            "timeout": timeout,
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
