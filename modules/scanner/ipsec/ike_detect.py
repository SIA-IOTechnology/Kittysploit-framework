#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ipsec.ike import AUTH_NAMES, Ike


class Module(Scanner, Ike):

    __info__ = {
        "name": "IKEv1 / IPsec endpoint detection (ike-scan)",
        "description": (
            "Detects IKEv1 (ISAKMP) VPN endpoints on UDP 500/4500. Sends Main Mode and "
            "Aggressive Mode probes similar to ike-scan, parses SA transforms, vendor IDs "
            "(XAUTH, DPD, Cisco Unity), and reports whether Aggressive Mode PSK capture "
            "may be possible."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": [
            "https://github.com/royhills/ike-scan",
            "https://attack.mitre.org/techniques/T1046/",
            "RFC 2408",
            "RFC 2409",
        ],
        "modules": [
            "auxiliary/gather/ipsec/ike_psk_capture",
            "auxiliary/admin/ipsec/vpn_xauth_connect",
        ],
        "tags": [
            "ipsec",
            "ike",
            "vpn",
            "udp",
            "scanner",
            "isakmp",
            "ike-scan",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 4,
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
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    probe_aggressive = OptBool(
        True,
        "Also send an IKEv1 Aggressive Mode probe after Main Mode",
        required=False,
    )
    group_id = OptString(
        "kittysploit",
        "Group ID / identity string for the Aggressive Mode probe",
        required=False,
    )

    def run(self):
        host = self._ike_host()
        if not host:
            print_error("No target specified")
            return False

        port = self._ike_port()
        nat_t = self._ike_nat_t()
        print_info(f"IKE scan on {host}:{port}" + (" (NAT-T)" if nat_t else ""))

        main = self.ike_probe(exchange="main")
        if main.get("status") != "ok":
            reason = main.get("reason") or "No IKE response"
            print_status(reason)
            return False

        parsed = main.get("parsed") or {}
        print_success(f"Main Mode: {main.get('reason')}")

        aggressive_ok = False
        aggressive_summary = ""
        aggressive_hash = False
        if bool(self.probe_aggressive):
            aggr = self.ike_probe(
                exchange="aggressive",
                id_value=str(self.group_id or "kittysploit"),
            )
            if aggr.get("status") == "ok":
                aggressive_ok = True
                aggressive_summary = str(aggr.get("reason") or "")
                aggr_parsed = aggr.get("parsed") or {}
                aggressive_hash = bool(aggr_parsed.get("hash_r"))
                if aggressive_hash:
                    print_warning(
                        "Aggressive Mode returned HASH — offline PSK cracking may be possible"
                    )
                print_success(f"Aggressive Mode: {aggressive_summary}")
            else:
                print_status(aggr.get("reason") or "Aggressive Mode probe failed")

        transforms = parsed.get("transforms") or []
        auth_methods = sorted(
            {AUTH_NAMES.get(t.auth, str(t.auth)) for t in transforms if t.auth}
        )
        vendor_ids = list(parsed.get("vendor_ids") or [])
        supports_xauth = bool(parsed.get("supports_xauth"))

        severity = "medium"
        reason_parts = [f"IKEv1 endpoint on UDP {port}"]
        if transforms:
            reason_parts.append(transforms[0].label())
        if auth_methods:
            reason_parts.append("Auth=" + "/".join(auth_methods))
        if vendor_ids:
            reason_parts.append("VIDs=" + ", ".join(vendor_ids[:4]))
        if supports_xauth:
            reason_parts.append("XAUTH supported")
        if aggressive_ok and aggressive_hash:
            severity = "high"
            reason_parts.append("Aggressive Mode HASH returned")
        elif aggressive_ok:
            reason_parts.append("Aggressive Mode responsive")

        self.set_info(
            severity=severity,
            reason="; ".join(reason_parts),
            confidence="high",
            port=port,
            nat_t=nat_t,
            exchange_main=main.get("reason"),
            exchange_aggressive=aggressive_summary or None,
            auth_methods=auth_methods,
            vendor_ids=vendor_ids,
            xauth=supports_xauth,
        )

        if aggressive_ok:
            print_warning(
                "Use auxiliary/gather/ipsec/ike_psk_capture to export hashcat-compatible PSK material"
            )
        return True
