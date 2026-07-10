#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP IAM Policy",
        "description": "Retrieve and display the IAM policy for the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "iam", "enumeration"],
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

    filter_member = OptString("", "Only show bindings containing this member (email or serviceAccount:...)", False)
    filter_role = OptString("", "Only show bindings for this role (exact or prefix ending with *)", False)
    export_json = OptString("", "Optional output JSON file", False)
    verbose = OptBool(False, "Print full IAM policy JSON", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Fetching IAM policy for project {project_id}...")
            result = self._gcp_request("iam_policy")
            if not result.get("ok"):
                print_error(f"IAM policy request failed: {result.get('raw', '')[:500]}")
                return False

            policy = result.get("body") or {}
            bindings = policy.get("bindings") or []
            filtered = self._filter_bindings(bindings)

            print_info("=" * 80)
            print_success(f"IAM policy retrieved ({len(filtered)}/{len(bindings)} binding(s) shown)")
            for idx, binding in enumerate(filtered, 1):
                role = binding.get("role", "unknown")
                members = binding.get("members") or []
                print_info(f"[{idx}] {role}")
                for member in members:
                    print_info(f"    - {member}")
                if binding.get("condition"):
                    print_info(f"    condition: {json.dumps(binding['condition'])}")
                print_info("-" * 80)

            if self.verbose:
                print_info(json.dumps(policy, indent=2))

            if self.export_json:
                payload = {
                    "project_id": project_id,
                    "policy": policy,
                    "filtered_bindings": filtered,
                }
                exported = self._gcp_export_json(str(self.export_json or ""), payload)
                if exported:
                    print_success(f"IAM policy exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "bindings": filtered})
        except Exception as exc:
            print_error(f"IAM policy gather failed: {exc}")
            return False

    def _filter_bindings(self, bindings):
        member_filter = str(self.filter_member or "").strip().lower()
        role_filter = str(self.filter_role or "").strip()
        role_prefix = role_filter[:-1] if role_filter.endswith("*") else ""
        filtered = []
        for binding in bindings:
            role = str(binding.get("role") or "")
            members = binding.get("members") or []
            if role_filter and not role_filter.endswith("*") and role != role_filter:
                continue
            if role_prefix and not role.startswith(role_prefix):
                continue
            if member_filter:
                if not any(member_filter in str(member).lower() for member in members):
                    continue
            filtered.append(binding)
        return filtered
