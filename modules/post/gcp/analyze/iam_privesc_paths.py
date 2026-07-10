#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP IAM PrivEsc Paths",
        "description": "Identify practical IAM privilege escalation paths for the current GCP principal",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "iam", "privilege-escalation", "cloud"],
        "references": [
            "https://cloud.google.com/iam/docs/overview",
            "https://attack.mitre.org/techniques/T1098/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
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

    include_role_expansion = OptBool(True, "Expand project roles into permissions", False)
    check_impersonation_targets = OptBool(True, "List service accounts as impersonation targets", False)
    max_service_accounts = OptString("40", "Maximum service accounts to inspect", False)
    export_json = OptString("", "Optional output JSON file for path findings", False)
    verbose = OptBool(False, "Show role permission details", False)

    def run(self):
        try:
            print_info("Starting GCP IAM privilege-escalation path analysis...")
            principal = self._gcp_client_email()
            project_id = self._gcp_project_id()
            if not principal:
                print_error("Could not resolve current principal (whoami)")
                return False

            print_info(f"Project: {project_id or 'unknown'}")
            print_info(f"Principal: {principal}")
            print_info("=" * 80)

            bindings = self._gcp_iam_bindings()
            roles = self._gcp_roles_for_member(principal, bindings=bindings)
            if not roles:
                print_warning("No project-level IAM roles found for current principal")
                return True

            print_info(f"Project roles: {', '.join(roles)}")
            if not self.include_role_expansion:
                print_warning("Role expansion disabled; path analysis requires permission expansion")
                return True

            effective = self._gcp_collect_effective_permissions(principal, bindings=bindings)
            paths = self._gcp_identify_privesc_paths(effective["permissions"], principal)
            if self.check_impersonation_targets:
                paths = self._attach_impersonation_targets(paths)

            self._print_paths(paths, principal, roles)
            exported = self._gcp_export_json(self.export_json,
                {"project_id": project_id, "principal": principal, "roles": roles, "paths": paths},) if self.export_json else ""
            if exported:
                print_success(f"Path findings exported to {exported}")
            return True
        except Exception as exc:
            print_error(f"Error during GCP IAM PrivEsc path analysis: {exc}")
            return False

    def _attach_impersonation_targets(self, paths):
        limit = self._gcp_to_int(self.max_service_accounts, 40)
        sa_data = self._gcp_body_dict("service_accounts")
        targets = []
        for account in list(sa_data.get("accounts") or [])[:limit]:
            email = account.get("email", "")
            if not email or email.endswith("-compute@developer.gserviceaccount.com"):
                continue
            targets.append(
                {
                    "email": email,
                    "display_name": account.get("displayName", ""),
                    "disabled": account.get("disabled", False),
                }
            )
        for path in paths:
            if path["id"] == "sa_impersonation" and targets:
                path["target_service_accounts"] = targets[:15]
        return paths

    def _print_paths(self, paths, principal, roles):
        print_info(f"Analyzed principal: {principal}")
        print_info(f"Roles analyzed: {len(roles)}")
        print_info("=" * 80)
        if not paths:
            print_success("No concrete privilege-escalation path identified from analyzed permissions")
            return

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for idx, path in enumerate(sorted(paths, key=lambda item: severity_order.get(item["severity"], 99)), 1):
            print_warning(f"[{idx}] {path['name']} ({path['severity']})")
            print_info(f"  Impact: {path['impact']}")
            perms = path.get("matched_permissions") or []
            if perms:
                print_info(f"  Matched permissions: {', '.join(perms[:12])}")
            for target in path.get("target_service_accounts") or []:
                print_info(f"  SA target: {target.get('email')}")
            print_info("  Validation commands:")
            for cmd in path.get("validation_commands") or []:
                print_info(f"    - {cmd}")
            if self.verbose:
                print_info(f"  Path ID: {path.get('id')}")
            print_info("-" * 80)
