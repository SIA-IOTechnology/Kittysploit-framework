#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Service Account Risk",
        "description": "Assess service account hygiene, key exposure, and privilege concentration",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "service-account", "credentials", "cloud"],
        "references": [
            "https://cloud.google.com/iam/docs/service-accounts",
            "https://attack.mitre.org/techniques/T1078/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
        'expected_requests': 15,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals', 'credentials'],
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

    check_user_managed_keys = OptBool(True, "Enumerate user-managed service account keys", False)
    check_disabled_accounts = OptBool(True, "Report disabled service accounts still bound in IAM", False)
    check_default_compute_sa = OptBool(True, "Flag default Compute Engine service account usage", False)
    check_privileged_roles = OptBool(True, "Flag service accounts with primitive roles", False)
    max_service_accounts = OptString("50", "Maximum service accounts to inspect", False)
    export_json = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Show per-account details", False)

    DEFAULT_COMPUTE_SUFFIX = "-compute@developer.gserviceaccount.com"

    def run(self):
        try:
            print_info("Starting GCP service account risk analysis...")
            project_id = self._gcp_project_id()
            print_info(f"Project: {project_id or 'unknown'}")
            print_info("=" * 80)

            limit = self._gcp_to_int(self.max_service_accounts, 50)
            accounts = list(self._gcp_body_dict("service_accounts").get("accounts") or [])[:limit]
            bindings = self._gcp_iam_bindings()
            findings = {
                "project_id": project_id,
                "service_accounts_scanned": len(accounts),
                "user_managed_keys": [],
                "disabled_with_bindings": [],
                "default_compute_sa": [],
                "privileged_bindings": [],
            }

            for account in accounts:
                email = account.get("email", "")
                if not email:
                    continue
                if self.check_user_managed_keys:
                    keys = self._user_managed_keys(project_id, email)
                    if keys:
                        findings["user_managed_keys"].append({"email": email, "keys": keys})
                if self.check_disabled_accounts and account.get("disabled"):
                    roles = self._gcp_roles_for_member(email, bindings=bindings)
                    if roles:
                        findings["disabled_with_bindings"].append({"email": email, "roles": roles})
                if self.check_default_compute_sa and email.endswith(self.DEFAULT_COMPUTE_SUFFIX):
                    findings["default_compute_sa"].append(
                        {"email": email, "roles": self._gcp_roles_for_member(email, bindings=bindings)}
                    )

            if self.check_privileged_roles:
                for binding in bindings:
                    role = binding.get("role", "")
                    if not self._gcp_is_primitive_role(role):
                        continue
                    sa_members = [m for m in binding.get("members") or [] if str(m).startswith("serviceAccount:")]
                    if sa_members:
                        findings["privileged_bindings"].append({"role": role, "members": sa_members})

            self._print_findings(findings)
            exported = self._gcp_export_json(self.export_json, findings) if self.export_json else ""
            if exported:
                print_success(f"Results exported to {exported}")
            return True
        except Exception as exc:
            print_error(f"Error during GCP service account risk analysis: {exc}")
            return False

    def _user_managed_keys(self, project_id, email):
        encoded = email.replace("@", "%40")
        data = self._gcp_get_body(
            f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{encoded}/keys"
        )
        if not isinstance(data, dict):
            return []
        keys = []
        for key in data.get("keys") or []:
            if str(key.get("keyType", "")).upper() != "USER_MANAGED":
                continue
            keys.append(
                {
                    "name": key.get("name", ""),
                    "valid_after": key.get("validAfterTime", ""),
                    "valid_before": key.get("validBeforeTime", ""),
                }
            )
        return keys

    def _print_findings(self, findings):
        key_findings = findings.get("user_managed_keys") or []
        print_status("User-managed keys")
        if not key_findings:
            print_success("No user-managed keys found on inspected service accounts")
        else:
            print_warning(f"Found user-managed keys on {len(key_findings)} service account(s)")
            for item in key_findings[:15]:
                print_warning(f"  {item['email']}: {len(item['keys'])} key(s)")

        disabled = findings.get("disabled_with_bindings") or []
        print_status("Disabled accounts with IAM bindings")
        if disabled:
            print_error(f"Found {len(disabled)} disabled account(s) still bound in IAM")
        else:
            print_success("No disabled service accounts retain project IAM bindings")

        default_sa = findings.get("default_compute_sa") or []
        if default_sa:
            print_warning(f"Default compute SA present on {len(default_sa)} inspected account(s)")

        privileged = findings.get("privileged_bindings") or []
        print_status("Privileged service account bindings")
        if privileged:
            print_error(f"Found {len(privileged)} privileged SA binding group(s)")
        else:
            print_success("No primitive roles bound directly to service accounts")
        print_info("=" * 80)
