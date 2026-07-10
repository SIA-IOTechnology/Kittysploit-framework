#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enumerate local/domain alias membership via SAMR (port 445, no LDAP / Impacket).
"""

from kittysploit import *
from lib.protocols.samr.samr_client import SamrClient
from lib.protocols.samr.samr_scanner_client import SamrScannerClient
from lib.protocols.samr.dcerpc import DceRpcError


class Module(Auxiliary, SamrScannerClient):
    __info__ = {
        "name": "SAMR group membership",
        "description": (
            "List local/domain alias membership through MS-SAMR on port 445 without LDAP or Impacket."
        ),
        "author": "KittySploit Team",
        "tags": ["ad", "samr", "smb", "enumeration", "groups", "membership"],
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
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    group = OptString("", "Limit to one alias/group name (empty = all aliases)", False)
    max_groups = OptInteger(64, "Maximum aliases to enumerate", False)
    max_members = OptInteger(128, "Maximum members per alias", False)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target host is required")
            return False

        user, password, dom = self._parse_credentials()
        group_filter = str(getattr(self.group, "value", "") or "").strip()
        max_groups = max(1, int(getattr(self.max_groups, "value", 64) or 64))
        max_members = max(1, int(getattr(self.max_members, "value", 128) or 128))

        print_info(f"SAMR group membership on {host}:{self._port()}")
        try:
            client = SamrClient(
                host=host,
                port=self._port(),
                username=user,
                password=password,
                domain=dom,
                remote_name=host,
                timeout=self._timeout(),
            )
            with client:
                memberships = client.enumerate_group_membership(
                    alias_name=group_filter,
                    max_aliases=max_groups,
                    max_members=max_members,
                )
        except DceRpcError as exc:
            print_error(str(exc))
            return False
        except Exception as exc:
            print_error(f"SAMR group enumeration failed: {exc}")
            return False

        if not memberships:
            print_warning("No alias membership returned")
            return False

        print_info("=" * 80)
        for item in memberships:
            print_status(f"{item.group_name} (RID {item.group_rid})")
            if not item.members:
                print_info("  (no members)")
                continue
            for member in item.members[:max_members]:
                print_info(f"  - {member}")
            if len(item.members) > max_members:
                print_info(f"  ... and {len(item.members) - max_members} more")

        print_success(f"Enumerated membership for {len(memberships)} alias(es)")
        return True
