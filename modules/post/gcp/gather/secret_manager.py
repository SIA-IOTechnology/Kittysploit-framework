#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Secret Manager",
        "description": "Enumerate Secret Manager secrets (metadata only) in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "secrets", "enumeration"],
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

    name_filter = OptString("", "Filter secrets by short name substring", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating Secret Manager secrets in {project_id}...")
            result = self._gcp_request("secrets")
            if not result.get("ok"):
                print_error(f"Secret Manager API request failed: {result.get('raw', '')[:500]}")
                return False

            secrets = (result.get("body") or {}).get("secrets") or []
            name_filter = str(self.name_filter or "").strip().lower()
            rows = []
            for item in secrets:
                resource = str(item.get("name") or "")
                short_name = resource.rsplit("/", 1)[-1]
                if name_filter and name_filter not in short_name.lower():
                    continue
                rows.append(
                    {
                        "name": short_name,
                        "resource": resource,
                        "createTime": item.get("createTime"),
                        "replication": item.get("replication"),
                        "labels": item.get("labels"),
                        "annotations": item.get("annotations"),
                    }
                )

            print_info("=" * 80)
            if not rows:
                print_warning("No secrets found")
            else:
                for row in rows:
                    print_info(f"{row['name']} created={row.get('createTime', 'unknown')}")
                print_success(f"Found {len(rows)} secret(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "secrets": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "secrets": rows})
        except Exception as exc:
            print_error(f"Secret Manager enumeration failed: {exc}")
            return False
