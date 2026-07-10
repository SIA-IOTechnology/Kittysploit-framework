#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Cloud Functions",
        "description": "Enumerate Cloud Functions (Gen1 and Gen2) in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "cloud-functions", "enumeration"],
    'agent': {
        'risk': '',
        'effects': ['api_request'],
        'expected_requests': 2,
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
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    name_filter = OptString("", "Filter functions by name substring", False)
    include_gen1 = OptBool(True, "Include Cloud Functions Gen1", False)
    include_gen2 = OptBool(True, "Include Cloud Functions Gen2", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating Cloud Functions in {project_id}...")
            name_filter = str(self.name_filter or "").strip().lower()
            rows = []

            if self.include_gen1:
                rows.extend(self._collect_functions("functions_v1", "gen1", name_filter))
            if self.include_gen2:
                rows.extend(self._collect_functions("functions_v2", "gen2", name_filter))

            print_info("=" * 80)
            if not rows:
                print_warning("No Cloud Functions found")
            else:
                for row in rows:
                    print_info(f"{row['name']} [{row['generation']}] status={row.get('status')}")
                    if row.get("runtime"):
                        print_info(f"  runtime: {row['runtime']}")
                    if row.get("serviceAccountEmail"):
                        print_info(f"  serviceAccount: {row['serviceAccountEmail']}")
                    if row.get("httpsTrigger"):
                        print_info(f"  httpsTrigger: {row['httpsTrigger']}")
                print_success(f"Found {len(rows)} function(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "functions": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "functions": rows})
        except Exception as exc:
            print_error(f"Cloud Functions enumeration failed: {exc}")
            return False

    def _collect_functions(self, command, generation, name_filter):
        result = self._gcp_request(command)
        if not result.get("ok"):
            print_warning(f"{command} request failed: {result.get('raw', '')[:200]}")
            return []

        functions = (result.get("body") or {}).get("functions") or []
        rows = []
        for item in functions:
            resource = str(item.get("name") or "")
            short_name = resource.rsplit("/", 1)[-1]
            if name_filter and name_filter not in resource.lower():
                continue
            if generation == "gen1":
                row = {
                    "name": short_name,
                    "resource": resource,
                    "generation": generation,
                    "status": item.get("status"),
                    "runtime": item.get("runtime"),
                    "entryPoint": item.get("entryPoint"),
                    "serviceAccountEmail": item.get("serviceAccountEmail"),
                    "httpsTrigger": (item.get("httpsTrigger") or {}).get("url"),
                    "eventTrigger": item.get("eventTrigger"),
                }
            else:
                build_cfg = item.get("buildConfig") or {}
                service_cfg = item.get("serviceConfig") or {}
                row = {
                    "name": short_name,
                    "resource": resource,
                    "generation": generation,
                    "status": item.get("state"),
                    "runtime": build_cfg.get("runtime"),
                    "entryPoint": build_cfg.get("entryPoint"),
                    "serviceAccountEmail": service_cfg.get("serviceAccountEmail"),
                    "uri": service_cfg.get("uri"),
                    "ingressSettings": service_cfg.get("ingressSettings"),
                }
            rows.append(row)
        return rows
