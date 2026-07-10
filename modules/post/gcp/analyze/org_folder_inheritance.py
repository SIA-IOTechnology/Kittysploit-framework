#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Org Folder Inheritance",
        "description": "Map project ancestry and inherited IAM bindings from folders and organization",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "iam", "organization", "folder", "inheritance", "cloud"],
        "references": [
            "https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['api_request'],
        'expected_requests': 10,
        'reversible': False,
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
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    principal = OptString("", "Highlight bindings affecting this member; defaults to current client email", False)
    include_project_policy = OptBool(True, "Include direct project IAM bindings", False)
    export_json = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Print all inherited bindings", False)

    IMPERSONATION_ROLES = {
        "roles/owner",
        "roles/editor",
        "roles/iam.securityAdmin",
        "roles/iam.serviceAccountAdmin",
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountUser",
    }

    def run(self):
        try:
            print_info("Analyzing GCP org/folder IAM inheritance...")
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            member = str(self.principal or "").strip() or self._gcp_client_email()
            print_info(f"Project: {project_id}")
            if member:
                print_info(f"Principal filter: {member}")
            print_info("=" * 80)

            ancestry = self._gcp_project_ancestry(project_id)
            hierarchy = []
            inherited_bindings = []
            principal_roles = []

            for ancestor in ancestry:
                resource = ancestor.get("resourceId") or {}
                resource_type = str(resource.get("type") or "")
                resource_id = str(resource.get("id") or "")
                if not resource_type or not resource_id:
                    continue
                resource_name = f"{resource_type}s/{resource_id}" if resource_type != "project" else f"projects/{resource_id}"
                if resource_type == "project" and resource_id != project_id:
                    resource_name = f"projects/{resource_id}"

                entry = {
                    "type": resource_type,
                    "id": resource_id,
                    "resource": resource_name,
                }
                if resource_type in ("folder", "organization"):
                    policy_result = self._gcp_get_resource_iam_policy(resource_name)
                    entry["policy_available"] = bool(policy_result.get("ok"))
                    if policy_result.get("ok"):
                        policy = policy_result.get("policy") or {}
                        bindings = policy.get("bindings") or []
                        entry["binding_count"] = len(bindings)
                        entry["summary"] = self._summarize_bindings(policy)
                        for binding in bindings:
                            inherited_bindings.append(
                                {
                                    "source": resource_name,
                                    "role": binding.get("role"),
                                    "members": binding.get("members") or [],
                                    "condition": binding.get("condition"),
                                }
                            )
                        if member:
                            roles = self._gcp_roles_for_member(member, bindings=bindings)
                            for role in roles:
                                principal_roles.append({"source": resource_name, "role": role})
                    else:
                        entry["policy_error"] = str(policy_result.get("error") or "")[:300]
                hierarchy.append(entry)

            project_policy = None
            if self.include_project_policy:
                project_policy = self._gcp_get_project_iam_policy(project_id)
                if project_policy.get("ok") and member:
                    for role in self._gcp_roles_for_member(
                        member, bindings=(project_policy.get("policy") or {}).get("bindings")
                    ):
                        principal_roles.append({"source": f"projects/{project_id}", "role": role, "direct": True})

            findings = {
                "project_id": project_id,
                "principal": member,
                "ancestry": hierarchy,
                "inherited_bindings": inherited_bindings,
                "principal_roles": principal_roles,
                "privileged_inherited_roles": self._privileged_roles(principal_roles),
                "project_policy_summary": (
                    self._summarize_bindings(project_policy.get("policy"))
                    if project_policy and project_policy.get("ok")
                    else None
                ),
            }

            print_status("Resource hierarchy")
            for item in hierarchy:
                print_info(f"  {item.get('type')}: {item.get('id')}")
                if item.get("binding_count") is not None:
                    print_info(f"    bindings: {item.get('binding_count')}")

            if principal_roles:
                print_warning(f"Principal inherits/applies {len(principal_roles)} role binding(s)")
                for item in principal_roles[:20]:
                    source = item.get("source")
                    role = item.get("role")
                    suffix = " (direct project)" if item.get("direct") else " (inherited)"
                    print_info(f"  {role} <= {source}{suffix}")
            else:
                print_success("No matching principal bindings found in inspected hierarchy")

            privileged = findings.get("privileged_inherited_roles") or []
            if privileged:
                print_error(f"Privileged inherited/direct roles for principal: {len(privileged)}")
                for role in privileged:
                    print_error(f"  {role}")

            if self.verbose:
                for binding in inherited_bindings[:30]:
                    print_info(json.dumps(binding, ensure_ascii=False))

            print_info("=" * 80)
            exported = self._gcp_export_json(self.export_json, findings) if self.export_json else ""
            if exported:
                print_success(f"Results exported to {exported}")
            return self.module_result(success=True, data=findings)
        except Exception as exc:
            print_error(f"Org/folder inheritance analysis failed: {exc}")
            return False

    def _privileged_roles(self, principal_roles):
        roles = sorted({item.get("role") for item in principal_roles if item.get("role")})
        return [role for role in roles if role in self.IMPERSONATION_ROLES or self._gcp_is_primitive_role(role)]
