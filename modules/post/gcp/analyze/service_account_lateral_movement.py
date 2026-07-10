#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Service Account Lateral Movement",
        "description": "Map service account impersonation and workload attachment chains for lateral movement",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "service-account", "lateral-movement", "iam", "cloud"],
        "references": [
            "https://cloud.google.com/iam/docs/service-account-impersonation",
            "https://attack.mitre.org/tactics/TA0008/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
        'expected_requests': 30,
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

    max_service_accounts = OptInteger(40, "Maximum service accounts to inspect for impersonation grants", False)
    include_attachments = OptBool(True, "Map compute, Cloud Run, and Cloud Functions attachments", False)
    include_privileged_targets = OptBool(True, "Highlight targets with primitive or admin roles", False)
    export_json = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Show full movement chains", False)

    PRIVILEGED_ROLES = {
        "roles/owner",
        "roles/editor",
        "roles/iam.securityAdmin",
        "roles/iam.serviceAccountAdmin",
        "roles/iam.serviceAccountTokenCreator",
    }

    def run(self):
        try:
            print_info("Analyzing GCP service account lateral movement paths...")
            project_id = self._gcp_project_id()
            principal = self._gcp_client_email()
            if not project_id or not principal:
                print_error("Could not resolve project_id or current principal")
                return False

            print_info(f"Project: {project_id}")
            print_info(f"Principal: {principal}")
            print_info("=" * 80)

            bindings = self._gcp_iam_bindings()
            attachments = self._gcp_collect_service_account_attachments(project_id) if self.include_attachments else {}
            accounts = list(self._gcp_body_dict("service_accounts").get("accounts") or [])
            max_sa = max(1, int(self.max_service_accounts or 40))

            chains = []
            reachable = []
            for account in accounts[:max_sa]:
                email = str(account.get("email") or "")
                if not email or email.endswith("-compute@developer.gserviceaccount.com"):
                    continue

                grants = self._gcp_members_can_impersonate_sa(project_id, email)
                project_roles = self._gcp_roles_for_member(email, bindings=bindings)
                can_reach = any(principal.lower() in str(g.get("member") or "").lower() for g in grants)
                can_reach = can_reach or self._project_impersonation_allows(principal, bindings)

                entry = {
                    "service_account": email,
                    "disabled": account.get("disabled"),
                    "impersonation_grants": grants,
                    "project_roles": project_roles,
                    "attachments": attachments.get(email, []),
                    "reachable_by_principal": can_reach,
                    "privileged_roles": [role for role in project_roles if role in self.PRIVILEGED_ROLES or self._gcp_is_primitive_role(role)],
                }
                if can_reach:
                    reachable.append(entry)
                    chain = self._build_chain(principal, entry)
                    chains.append(chain)
                    severity = "HIGH" if entry.get("privileged_roles") else "MEDIUM"
                    print_warning(f"[{severity}] Reachable SA: {email}")
                    if entry.get("privileged_roles"):
                        print_error(f"  privileged roles: {', '.join(entry['privileged_roles'])}")
                    if entry.get("attachments"):
                        print_info(f"  attachments: {len(entry['attachments'])}")
                    for step in chain.get("steps") or []:
                        print_info(f"    -> {step}")
                elif self.verbose and grants:
                    print_info(f"SA {email}: impersonation grants exist but not for current principal")

            findings = {
                "project_id": project_id,
                "principal": principal,
                "reachable_service_accounts": reachable,
                "movement_chains": chains,
                "summary": {
                    "service_accounts_scanned": min(len(accounts), max_sa),
                    "reachable_count": len(reachable),
                    "privileged_reachable_count": sum(1 for item in reachable if item.get("privileged_roles")),
                    "attachment_backed_count": sum(1 for item in reachable if item.get("attachments")),
                },
            }

            if self.include_privileged_targets and not reachable:
                print_success("No direct service account lateral movement path found for current principal")
            elif reachable:
                print_warning(
                    f"Found {len(reachable)} reachable service account(s); "
                    f"{findings['summary']['privileged_reachable_count']} with privileged roles"
                )

            print_info("=" * 80)
            exported = self._gcp_export_json(self.export_json, findings) if self.export_json else ""
            if exported:
                print_success(f"Results exported to {exported}")
            return self.module_result(success=True, data=findings)
        except Exception as exc:
            print_error(f"Service account lateral movement analysis failed: {exc}")
            return False

    @staticmethod
    def _project_impersonation_allows(principal, bindings):
        impersonation_roles = {"roles/owner", "roles/editor", "roles/iam.serviceAccountTokenCreator"}
        for binding in bindings:
            if binding.get("role") not in impersonation_roles:
                continue
            for member in binding.get("members") or []:
                if principal.lower() in str(member).lower():
                    return True
        return False

    @staticmethod
    def _build_chain(principal, entry):
        steps = [f"Start as {principal}"]
        steps.append(f"Impersonate {entry.get('service_account')}")
        if entry.get("project_roles"):
            steps.append(f"Inherit project roles: {', '.join(entry['project_roles'][:5])}")
        for attachment in (entry.get("attachments") or [])[:5]:
            steps.append(
                f"Pivot via {attachment.get('type')} {attachment.get('name')}"
                + (f" ({attachment.get('external_ip')})" if attachment.get("external_ip") else "")
            )
        return {
            "target_service_account": entry.get("service_account"),
            "privileged": bool(entry.get("privileged_roles")),
            "steps": steps,
        }
