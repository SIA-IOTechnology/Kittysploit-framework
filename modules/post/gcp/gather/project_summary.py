#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Project Summary",
        "description": "Summarize a Google Cloud project from the current GCP API session",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "enumeration", "project"],
    'agent': {
        'risk': '',
        'effects': ['api_request'],
        'expected_requests': 8,
        'reversible': True,
        'approval_required': False,
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    include_services = OptBool(True, "Include enabled API services", False)
    include_iam = OptBool(True, "Include IAM policy summary", False)
    include_service_accounts = OptBool(True, "Include service account count", False)
    include_compute = OptBool(True, "Include compute instance count", False)
    include_storage = OptBool(True, "Include storage bucket count", False)
    include_secrets = OptBool(True, "Include Secret Manager secret count", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            print_info("Gathering GCP project summary...")
            whoami = self._gcp_whoami()
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            summary = {
                "project_id": project_id,
                "client_email": whoami.get("client_email", ""),
                "scopes": whoami.get("scopes", []),
            }

            project = self._gcp_request("project")
            if project.get("ok"):
                body = project.get("body") or {}
                summary["project"] = {
                    "name": body.get("name"),
                    "projectNumber": body.get("projectNumber"),
                    "lifecycleState": body.get("lifecycleState"),
                    "createTime": body.get("createTime"),
                }
                print_success(f"Project: {body.get('name', project_id)} ({body.get('lifecycleState', 'unknown')})")
            else:
                print_warning("Could not read project metadata")

            if self.include_services:
                services = self._gcp_request("enabled_services")
                count = 0
                if services.get("ok") and isinstance(services.get("body"), dict):
                    count = len((services["body"] or {}).get("services") or [])
                summary["enabled_services_count"] = count
                print_info(f"Enabled services: {count}")

            if self.include_iam:
                iam = self._gcp_request("iam_policy")
                iam_body = iam.get("body") if iam.get("ok") else {}
                summary["iam"] = self._summarize_bindings(iam_body)
                print_info(
                    f"IAM bindings: {summary['iam']['binding_count']} "
                    f"({len(summary['iam']['roles'])} roles, {len(summary['iam']['members'])} members)"
                )

            if self.include_service_accounts:
                sa = self._gcp_request("service_accounts")
                count = 0
                if sa.get("ok") and isinstance(sa.get("body"), dict):
                    count = len((sa["body"] or {}).get("accounts") or [])
                summary["service_accounts_count"] = count
                print_info(f"Service accounts: {count}")

            if self.include_compute:
                compute = self._gcp_request("compute_instances")
                instances = self._flatten_compute_instances(compute.get("body"))
                summary["compute_instances_count"] = len(instances)
                print_info(f"Compute instances: {len(instances)}")

            if self.include_storage:
                storage = self._gcp_request("storage_buckets")
                count = 0
                if storage.get("ok") and isinstance(storage.get("body"), dict):
                    count = len((storage["body"] or {}).get("items") or [])
                summary["storage_buckets_count"] = count
                print_info(f"Storage buckets: {count}")

            if self.include_secrets:
                secrets = self._gcp_request("secrets")
                count = 0
                if secrets.get("ok") and isinstance(secrets.get("body"), dict):
                    count = len((secrets["body"] or {}).get("secrets") or [])
                summary["secrets_count"] = count
                print_info(f"Secret Manager secrets: {count}")

            print_info("=" * 80)
            print_success("Project summary complete")
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), summary)
                if exported:
                    print_success(f"Summary exported to {exported}")
            return self.module_result(success=True, data=summary)
        except Exception as exc:
            print_error(f"Project summary failed: {exc}")
            return False
