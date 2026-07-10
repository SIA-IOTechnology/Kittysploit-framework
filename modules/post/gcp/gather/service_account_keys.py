#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from urllib.parse import quote

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Service Account Keys",
        "description": "Enumerate keys for IAM service accounts in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "iam", "service-account", "keys", "enumeration"],
    'agent': {
        'risk': '',
        'effects': ['api_request'],
        'expected_requests': 5,
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

    email_filter = OptString("", "Only inspect service accounts matching this email substring", False)
    key_type = OptString(
        "",
        "Filter by key type (USER_MANAGED, SYSTEM_MANAGED); empty lists all",
        False,
    )
    max_accounts = OptInteger(50, "Maximum service accounts to inspect for keys", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating service account keys in {project_id}...")
            sa_result = self._gcp_request("service_accounts")
            if not sa_result.get("ok"):
                print_error(f"Service account list failed: {sa_result.get('raw', '')[:500]}")
                return False

            accounts = (sa_result.get("body") or {}).get("accounts") or []
            email_filter = str(self.email_filter or "").strip().lower()
            key_type_filter = str(self.key_type or "").strip().upper()
            max_accounts = max(1, int(self.max_accounts or 50))

            rows = []
            inspected = 0
            for account in accounts:
                if inspected >= max_accounts:
                    break
                email = account.get("email", "")
                if not email:
                    continue
                if email_filter and email_filter not in email.lower():
                    continue
                inspected += 1
                keys = self._list_keys(project_id, email, key_type_filter)
                if keys:
                    rows.append({"email": email, "keys": keys})

            print_info("=" * 80)
            total_keys = sum(len(item["keys"]) for item in rows)
            if not rows:
                print_warning("No service account keys found")
            else:
                for item in rows:
                    print_info(f"{item['email']} ({len(item['keys'])} key(s))")
                    for key in item["keys"]:
                        print_info(
                            f"  [{key.get('keyType', 'unknown')}] "
                            f"valid={key.get('validAfterTime', '?')} -> {key.get('validBeforeTime', '?')}"
                        )
                print_success(f"Found {total_keys} key(s) across {len(rows)} service account(s)")

            if self.export_json:
                payload = {"project_id": project_id, "accounts_with_keys": rows}
                exported = self._gcp_export_json(str(self.export_json or ""), payload)
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(
                success=True,
                data={"project_id": project_id, "accounts_with_keys": rows, "key_count": total_keys},
            )
        except Exception as exc:
            print_error(f"Service account key enumeration failed: {exc}")
            return False

    def _list_keys(self, project_id, email, key_type_filter):
        encoded_email = quote(email, safe="")
        url = (
            f"https://iam.googleapis.com/v1/projects/{self._quote_project(project_id)}"
            f"/serviceAccounts/{encoded_email}/keys"
        )
        data = self._gcp_get_body(url)
        if not isinstance(data, dict):
            return []
        keys = []
        for key in data.get("keys") or []:
            key_type = str(key.get("keyType") or "").upper()
            if key_type_filter and key_type != key_type_filter:
                continue
            keys.append(
                {
                    "name": key.get("name"),
                    "keyType": key_type,
                    "validAfterTime": key.get("validAfterTime"),
                    "validBeforeTime": key.get("validBeforeTime"),
                    "keyAlgorithm": key.get("keyAlgorithm"),
                }
            )
        return keys
