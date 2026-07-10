#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.profinet_dcp import dcp_identify


class Module(Auxiliary):
    __info__ = {
        "name": "PROFINET DCP Identify",
        "description": (
            "Layer-2 PROFINET DCP Identify broadcast on an Ethernet interface to discover "
            "Siemens and other Profinet devices (device name, IP, vendor)."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "siemens", "profinet", "dcp", "layer2", "discovery"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['endpoints', 'tech_hints', 'risk_signals'],
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
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

    interface = OptString("eth0", "Capture/transmit interface", True)
    timeout = OptFloat(3.0, "Seconds to listen for DCP responses", False)
    probes = OptInteger(2, "Number of Identify requests to send", False)

    def run(self):
        iface = str(self.interface or "").strip()
        if not iface:
            print_error("Interface is required")
            return False

        print_status(f"Sending PROFINET DCP Identify on {iface}...")
        try:
            devices = dcp_identify(iface, float(self.timeout or 3.0), int(self.probes or 2))
        except RuntimeError as exc:
            print_error(str(exc))
            return False
        except PermissionError:
            print_error(f"Permission denied on {iface} — run as root or grant CAP_NET_RAW")
            return False
        except OSError as exc:
            print_error(f"DCP capture failed on {iface}: {exc}")
            return False

        if not devices:
            print_warning("No PROFINET DCP responses received")
            return False

        print_success(f"Discovered {len(devices)} PROFINET device(s)")
        for device in devices:
            parts = [device.mac]
            if device.name:
                parts.append(device.name)
            if device.vendor:
                parts.append(device.vendor)
            if device.ip_address:
                parts.append(f"ip={device.ip_address}")
            print_info("  " + " | ".join(parts))
        return True
