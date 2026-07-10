#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Service Accounts",
        "description": "Enumerate IAM service accounts in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "iam", "service-account", "enumeration"],
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

    email_filter = OptString("", "Filter service accounts by email substring", False)
    include_disabled = OptBool(True, "Include disabled service accounts", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating service accounts in {project_id}...")
            result = self._gcp_request("service_accounts")
            if not result.get("ok"):
                print_error(f"IAM API request failed: {result.get('raw', '')[:500]}")
                return False

            accounts = (result.get("body") or {}).get("accounts") or []
            email_filter = str(self.email_filter or "").strip().lower()
            rows = []
            for item in accounts:
                email = item.get("email", "")
                if email_filter and email_filter not in email.lower():
                    continue
                if not self.include_disabled and item.get("disabled"):
                    continue
                rows.append(
                    {
                        "email": email,
                        "displayName": item.get("displayName"),
                        "uniqueId": item.get("uniqueId"),
                        "disabled": item.get("disabled", False),
                        "oauth2ClientId": item.get("oauth2ClientId"),
                    }
                )

            print_info("=" * 80)
            if not rows:
                print_warning("No service accounts found")
            else:
                for row in rows:
                    status = "disabled" if row.get("disabled") else "active"
                    print_info(f"{row['email']} [{status}]")
                    if row.get("displayName"):
                        print_info(f"  displayName: {row['displayName']}")
                print_success(f"Found {len(rows)} service account(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "accounts": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "accounts": rows})
        except Exception as exc:
            print_error(f"Service account enumeration failed: {exc}")
            return False
