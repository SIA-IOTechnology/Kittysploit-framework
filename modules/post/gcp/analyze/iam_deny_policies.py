#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP IAM Deny Policies",
        "description": "Analyze IAM v2 deny policies attached to the project and inherited ancestors",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "iam", "deny-policy", "cloud"],
        "references": [
            "https://cloud.google.com/iam/docs/deny-overview",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['api_request'],
        'expected_requests': 8,
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

    include_ancestors = OptBool(True, "Also inspect deny policies on parent folders and organization", False)
    show_rules = OptBool(True, "Include deny rule details in output", False)
    export_json = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Print full policy payloads", False)

    def run(self):
        try:
            print_info("Analyzing GCP IAM deny policies...")
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Project: {project_id}")
            print_info("=" * 80)

            scopes = [{"scope": "project", "parent": f"projects/{project_id}/locations/global"}]
            if self.include_ancestors:
                scopes.extend(self._ancestor_scopes(project_id))

            findings = {"project_id": project_id, "scopes": []}
            total_policies = 0
            total_rules = 0

            for scope in scopes:
                policies = self._gcp_list_deny_policies(scope["parent"])
                analyzed = []
                for policy in policies:
                    entry = self._analyze_policy(policy)
                    analyzed.append(entry)
                    total_policies += 1
                    total_rules += len(entry.get("rules") or [])

                scope_entry = {
                    "scope": scope["scope"],
                    "parent": scope["parent"],
                    "policy_count": len(analyzed),
                    "policies": analyzed,
                }
                findings["scopes"].append(scope_entry)

                print_status(f"Scope: {scope['scope']} ({scope['parent']})")
                if not analyzed:
                    print_success("No deny policies found")
                else:
                    print_warning(f"Found {len(analyzed)} deny policy(ies)")
                    for item in analyzed:
                        print_info(f"  {item.get('name')} rules={len(item.get('rules') or [])}")
                        if self.show_rules:
                            for rule in (item.get("rules") or [])[:5]:
                                print_info(f"    - {json.dumps(rule, ensure_ascii=False)[:300]}")
                        if self.verbose:
                            print_info(json.dumps(item.get("raw") or {}, indent=2)[:4000])
                print_info("-" * 80)

            findings["summary"] = {
                "policy_count": total_policies,
                "rule_count": total_rules,
            }
            print_info("=" * 80)
            if total_policies == 0:
                print_success("No IAM deny policies discovered in inspected scopes")
            else:
                print_warning(f"Total deny policies: {total_policies} ({total_rules} rule(s))")

            exported = self._gcp_export_json(self.export_json, findings) if self.export_json else ""
            if exported:
                print_success(f"Results exported to {exported}")
            return self.module_result(success=True, data=findings)
        except Exception as exc:
            print_error(f"IAM deny policy analysis failed: {exc}")
            return False

    def _ancestor_scopes(self, project_id):
        scopes = []
        for ancestor in self._gcp_project_ancestry(project_id):
            resource = ancestor.get("resourceId") or {}
            resource_type = str(resource.get("type") or "").lower()
            resource_id = str(resource.get("id") or "")
            if resource_type in ("folder", "organization") and resource_id:
                scopes.append(
                    {
                        "scope": resource_type,
                        "parent": f"{resource_type}s/{resource_id}/locations/global",
                    }
                )
        return scopes

    @staticmethod
    def _analyze_policy(policy):
        rules = []
        for rule in policy.get("rules") or []:
            deny_rule = rule.get("denyRule") or rule
            rules.append(
                {
                    "description": deny_rule.get("description") or rule.get("description"),
                    "deniedPermissions": deny_rule.get("deniedPermissions") or [],
                    "deniedPrincipals": deny_rule.get("deniedPrincipals") or [],
                    "exceptionPrincipals": deny_rule.get("exceptionPrincipals") or [],
                    "denialCondition": deny_rule.get("denialCondition"),
                }
            )
        return {
            "name": policy.get("name"),
            "uid": policy.get("uid"),
            "displayName": policy.get("displayName"),
            "rules": rules,
            "raw": policy,
        }
