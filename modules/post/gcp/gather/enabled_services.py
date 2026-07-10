#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Enabled Services",
        "description": "Enumerate enabled Google Cloud API services in the current project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "enumeration", "services"],
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

    name_filter = OptString("", "Filter services by name substring", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating enabled API services in {project_id}...")
            result = self._gcp_request("enabled_services")
            if not result.get("ok"):
                print_error(f"Service Usage API request failed: {result.get('raw', '')[:500]}")
                return False

            services = (result.get("body") or {}).get("services") or []
            name_filter = str(self.name_filter or "").strip().lower()
            rows = []
            for item in services:
                config = item.get("config") or {}
                name = config.get("name") or item.get("name") or "unknown"
                title = config.get("title") or ""
                if name_filter and name_filter not in name.lower() and name_filter not in title.lower():
                    continue
                rows.append(
                    {
                        "name": name,
                        "title": title,
                        "state": item.get("state"),
                    }
                )

            print_info("=" * 80)
            if not rows:
                print_warning("No enabled services found")
            else:
                for row in rows:
                    label = row["title"] or row["name"]
                    print_info(f"{label} [{row.get('state', 'unknown')}]")
                    if row["title"]:
                        print_info(f"  api: {row['name']}")
                print_success(f"Found {len(rows)} enabled service(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "services": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "services": rows})
        except Exception as exc:
            print_error(f"Enabled services gather failed: {exc}")
            return False
