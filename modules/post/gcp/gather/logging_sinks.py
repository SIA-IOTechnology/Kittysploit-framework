#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Logging Sinks",
        "description": "Enumerate Cloud Logging sinks in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "logging", "enumeration"],
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

    name_filter = OptString("", "Filter sinks by name substring", False)
    max_sinks = OptInteger(100, "Maximum sinks to return", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating Cloud Logging sinks in {project_id}...")
            url = (
                f"https://logging.googleapis.com/v2/projects/{self._quote_project(project_id)}/sinks"
            )
            sinks = self._gcp_paginate_get(url, "sinks", max_items=int(self.max_sinks or 100))
            name_filter = str(self.name_filter or "").strip().lower()
            rows = []
            for item in sinks:
                resource = str(item.get("name") or "")
                short_name = resource.rsplit("/", 1)[-1]
                if name_filter and name_filter not in short_name.lower():
                    continue
                rows.append(
                    {
                        "name": short_name,
                        "resource": resource,
                        "destination": item.get("destination"),
                        "filter": item.get("filter"),
                        "disabled": item.get("disabled", False),
                        "writerIdentity": item.get("writerIdentity"),
                    }
                )

            print_info("=" * 80)
            if not rows:
                print_warning("No logging sinks found")
            else:
                for row in rows:
                    status = "disabled" if row.get("disabled") else "active"
                    print_info(f"{row['name']} [{status}]")
                    if row.get("destination"):
                        print_info(f"  destination: {row['destination']}")
                    if row.get("writerIdentity"):
                        print_info(f"  writerIdentity: {row['writerIdentity']}")
                print_success(f"Found {len(rows)} sink(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "sinks": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "sinks": rows})
        except Exception as exc:
            print_error(f"Logging sinks enumeration failed: {exc}")
            return False
