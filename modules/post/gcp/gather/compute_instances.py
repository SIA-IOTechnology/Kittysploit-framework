#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Compute Instances",
        "description": "Enumerate Compute Engine instances in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "compute", "enumeration"],
    'agent': {
        'risk': '',
        'effects': ['api_request'],
        'expected_requests': 1,
        'reversible': True,
        'approval_required': False,
        'produces': ['risk_signals'],
        'cost': 1.5,
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    name_filter = OptString("", "Filter instances by name substring", False)
    show_network = OptBool(True, "Include network IP details", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating Compute Engine instances in {project_id}...")
            result = self._gcp_request("compute_instances")
            if not result.get("ok"):
                print_error(f"Compute API request failed: {result.get('raw', '')[:500]}")
                return False

            instances = self._flatten_compute_instances(result.get("body"))
            name_filter = str(self.name_filter or "").strip().lower()
            if name_filter:
                instances = [
                    item
                    for item in instances
                    if name_filter in str(item.get("name") or "").lower()
                ]

            print_info("=" * 80)
            if not instances:
                print_warning("No compute instances found")
                return self.module_result(success=True, data={"instances": []})

            rows = []
            for item in instances:
                name = item.get("name", "unknown")
                zone = str(item.get("zone") or "").rsplit("/", 1)[-1]
                status = item.get("status", "unknown")
                machine = str(item.get("machineType") or "").rsplit("/", 1)[-1]
                service_accounts = [
                    sa.get("email")
                    for sa in (item.get("serviceAccounts") or [])
                    if sa.get("email")
                ]
                row = {
                    "name": name,
                    "zone": zone,
                    "status": status,
                    "machineType": machine,
                    "serviceAccounts": service_accounts,
                }
                if self.show_network:
                    interfaces = item.get("networkInterfaces") or []
                    if interfaces:
                        row["networkIP"] = interfaces[0].get("networkIP")
                        access = (interfaces[0].get("accessConfigs") or [{}])[0]
                        row["natIP"] = access.get("natIP")
                rows.append(row)

                print_info(f"{name} [{status}] zone={zone} machine={machine}")
                if service_accounts:
                    print_info(f"  service accounts: {', '.join(service_accounts)}")
                if self.show_network and row.get("networkIP"):
                    ips = [row.get("networkIP")]
                    if row.get("natIP"):
                        ips.append(f"nat={row['natIP']}")
                    print_info(f"  network: {', '.join(filter(None, ips))}")

            print_success(f"Found {len(rows)} instance(s)")
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "instances": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "instances": rows})
        except Exception as exc:
            print_error(f"Compute instance enumeration failed: {exc}")
            return False
