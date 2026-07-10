#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Firebase Hosting",
        "description": "Enumerate Firebase Hosting sites in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "firebase", "hosting", "enumeration"],
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

    name_filter = OptString("", "Filter sites by siteId or defaultUrl substring", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating Firebase Hosting sites in {project_id}...")
            result = self._gcp_request("firebase_sites")
            if not result.get("ok"):
                print_error(f"Firebase Hosting API request failed: {result.get('raw', '')[:500]}")
                return False

            sites = (result.get("body") or {}).get("sites") or []
            name_filter = str(self.name_filter or "").strip().lower()
            rows = []
            for item in sites:
                site_id = str(item.get("siteId") or "")
                default_url = str(item.get("defaultUrl") or "")
                if name_filter and name_filter not in site_id.lower() and name_filter not in default_url.lower():
                    continue
                rows.append(
                    {
                        "siteId": site_id,
                        "name": item.get("name"),
                        "defaultUrl": default_url,
                        "appId": item.get("appId"),
                        "type": item.get("type"),
                    }
                )

            print_info("=" * 80)
            if not rows:
                print_warning("No Firebase Hosting sites found")
            else:
                for row in rows:
                    print_info(f"{row['siteId']} url={row.get('defaultUrl', 'unknown')}")
                    if row.get("appId"):
                        print_info(f"  appId: {row['appId']}")
                print_success(f"Found {len(rows)} site(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "sites": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "sites": rows})
        except Exception as exc:
            print_error(f"Firebase Hosting enumeration failed: {exc}")
            return False
