#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Overprivileged Bindings",
        "description": "Find overprivileged IAM bindings: primitive roles, public principals, and broad group grants",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "iam", "overprivileged", "cloud"],
        "references": [
            "https://cloud.google.com/iam/docs/understanding-roles",
            "https://attack.mitre.org/techniques/T1098/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['api_request'],
        'expected_requests': 4,
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

    check_primitive_roles = OptBool(True, "Flag Owner/Editor/Viewer and IAM admin roles", False)
    check_public_members = OptBool(True, "Flag allUsers/allAuthenticatedUsers bindings", False)
    check_domain_wide = OptBool(True, "Flag domain-wide principal grants", False)
    check_service_account_owner = OptBool(True, "Flag primitive roles on service accounts", False)
    min_members = OptString("3", "Minimum members on a primitive role to flag as broad grant", False)
    export_json = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Show all members for each finding", False)

    def run(self):
        try:
            print_info("Starting GCP overprivileged binding analysis...")
            project_id = self._gcp_project_id()
            principal = self._gcp_client_email()
            print_info(f"Project: {project_id or 'unknown'}")
            if principal:
                print_info(f"Principal: {principal}")
            print_info("=" * 80)

            bindings = self._gcp_iam_bindings()
            if not bindings:
                print_warning("Could not read project IAM policy bindings")
                return False

            min_count = self._gcp_to_int(self.min_members, 3)
            findings = {
                "project_id": project_id,
                "primitive_bindings": [],
                "public_bindings": [],
                "domain_bindings": [],
                "service_account_primitive": [],
            }

            if self.check_primitive_roles:
                findings["primitive_bindings"] = self._primitive_bindings(bindings, min_count)
            if self.check_public_members:
                findings["public_bindings"] = self._gcp_public_bindings(bindings)
            if self.check_domain_wide:
                findings["domain_bindings"] = self._domain_bindings(bindings)
            if self.check_service_account_owner:
                findings["service_account_primitive"] = self._service_account_primitive(bindings)

            self._print_findings(findings)
            exported = self._gcp_export_json(self.export_json, findings) if self.export_json else ""
            if exported:
                print_success(f"Results exported to {exported}")
            return True
        except Exception as exc:
            print_error(f"Error during GCP overprivileged binding analysis: {exc}")
            return False

    def _primitive_bindings(self, bindings, min_count):
        findings = []
        for binding in bindings:
            role = binding.get("role", "")
            if not self._gcp_is_primitive_role(role):
                continue
            members = list(binding.get("members") or [])
            if len(members) < min_count:
                continue
            findings.append(
                {
                    "role": role,
                    "member_count": len(members),
                    "members": members if self.verbose else members[:8],
                }
            )
        return findings

    def _domain_bindings(self, bindings):
        findings = []
        for binding in bindings:
            domain_members = [m for m in binding.get("members") or [] if str(m).startswith("domain:")]
            if domain_members:
                findings.append({"role": binding.get("role", ""), "members": domain_members})
        return findings

    def _service_account_primitive(self, bindings):
        findings = []
        for binding in bindings:
            role = binding.get("role", "")
            if not self._gcp_is_primitive_role(role):
                continue
            sa_members = [m for m in binding.get("members") or [] if str(m).startswith("serviceAccount:")]
            if sa_members:
                findings.append({"role": role, "members": sa_members})
        return findings

    def _print_findings(self, findings):
        primitive = findings.get("primitive_bindings") or []
        print_status("Broad primitive role grants")
        if primitive:
            print_error(f"Found {len(primitive)} broad primitive binding group(s)")
            for item in primitive[:12]:
                print_warning(f"  {item['role']}: {item['member_count']} member(s)")
        else:
            print_success("No broad primitive role grants meeting threshold")

        public = findings.get("public_bindings") or []
        print_status("Public IAM bindings")
        if public:
            print_error(f"Found {len(public)} public binding group(s)")
            for item in public:
                print_warning(f"  {item['role']}: {', '.join(item['members'])}")
        else:
            print_success("No allUsers/allAuthenticatedUsers project bindings")

        domain = findings.get("domain_bindings") or []
        if domain:
            print_warning(f"Found {len(domain)} domain-wide binding group(s)")

        sa_prim = findings.get("service_account_primitive") or []
        print_status("Primitive roles on service accounts")
        if sa_prim:
            print_error(f"Found {len(sa_prim)} primitive service-account binding group(s)")
        else:
            print_success("No primitive roles bound directly to service accounts")

        total = sum(len(findings.get(key) or []) for key in (
            "primitive_bindings", "public_bindings", "domain_bindings", "service_account_primitive"
        ))
        print_info("=" * 80)
        if total == 0:
            print_success("No overprivileged binding patterns detected")
        else:
            print_warning(f"Total overprivileged binding groups: {total}")
