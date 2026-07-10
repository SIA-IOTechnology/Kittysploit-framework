#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Cloud SQL Instances",
        "description": "Enumerate Cloud SQL instances in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "cloud-sql", "database", "enumeration"],
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
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating Cloud SQL instances in {project_id}...")
            result = self._gcp_request("sql_instances")
            if not result.get("ok"):
                print_error(f"Cloud SQL API request failed: {result.get('raw', '')[:500]}")
                return False

            instances = (result.get("body") or {}).get("items") or []
            name_filter = str(self.name_filter or "").strip().lower()
            rows = []
            for item in instances:
                name = item.get("name", "")
                if name_filter and name_filter not in name.lower():
                    continue
                ip_addresses = [
                    {"type": ip.get("type"), "ipAddress": ip.get("ipAddress")}
                    for ip in (item.get("ipAddresses") or [])
                ]
                rows.append(
                    {
                        "name": name,
                        "databaseVersion": item.get("databaseVersion"),
                        "region": item.get("region"),
                        "state": item.get("state"),
                        "connectionName": item.get("connectionName"),
                        "ipAddresses": ip_addresses,
                        "settings": {
                            "tier": (item.get("settings") or {}).get("tier"),
                            "backupConfiguration": (item.get("settings") or {}).get(
                                "backupConfiguration"
                            ),
                        },
                    }
                )

            print_info("=" * 80)
            if not rows:
                print_warning("No Cloud SQL instances found")
            else:
                for row in rows:
                    print_info(
                        f"{row['name']} [{row.get('state', 'unknown')}] "
                        f"version={row.get('databaseVersion')} region={row.get('region')}"
                    )
                    for ip in row.get("ipAddresses") or []:
                        print_info(f"  {ip.get('type', 'IP')}: {ip.get('ipAddress')}")
                print_success(f"Found {len(rows)} instance(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "instances": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "instances": rows})
        except Exception as exc:
            print_error(f"Cloud SQL enumeration failed: {exc}")
            return False
