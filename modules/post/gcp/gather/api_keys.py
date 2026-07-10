#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP API Keys",
        "description": "Enumerate API keys and their restrictions in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "api-keys", "enumeration"],
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
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    name_filter = OptString("", "Filter keys by display name or uid substring", False)
    unrestricted_only = OptBool(False, "Only show keys without restrictions", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating API keys in {project_id}...")
            result = self._gcp_request("api_keys")
            if not result.get("ok"):
                print_error(f"API Keys API request failed: {result.get('raw', '')[:500]}")
                return False

            keys = (result.get("body") or {}).get("keys") or []
            name_filter = str(self.name_filter or "").strip().lower()
            rows = []
            for item in keys:
                uid = str(item.get("uid") or "")
                display_name = str(item.get("displayName") or "")
                restrictions = item.get("restrictions") or {}
                if name_filter and name_filter not in uid.lower() and name_filter not in display_name.lower():
                    continue
                if self.unrestricted_only and restrictions:
                    continue
                rows.append(
                    {
                        "uid": uid,
                        "displayName": display_name,
                        "name": item.get("name"),
                        "createTime": item.get("createTime"),
                        "restrictions": restrictions,
                    }
                )

            print_info("=" * 80)
            if not rows:
                print_warning("No API keys found")
            else:
                for row in rows:
                    label = row.get("displayName") or row.get("uid")
                    restricted = "restricted" if row.get("restrictions") else "unrestricted"
                    print_info(f"{label} [{restricted}] uid={row.get('uid')}")
                print_success(f"Found {len(rows)} key(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "keys": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "keys": rows})
        except Exception as exc:
            print_error(f"API key enumeration failed: {exc}")
            return False
