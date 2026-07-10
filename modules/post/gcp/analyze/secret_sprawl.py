#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Secret Sprawl",
        "description": "Detect Secret Manager sprawl: stale secrets, many versions, and weak replication posture",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "secrets", "secret-manager", "cloud"],
        "references": [
            "https://cloud.google.com/secret-manager/docs",
            "https://attack.mitre.org/techniques/T1552/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['api_request'],
        'expected_requests': 20,
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

    check_version_count = OptBool(True, "Flag secrets with many enabled versions", False)
    check_rotation = OptBool(True, "Flag secrets without rotation configured", False)
    check_labels = OptBool(True, "Flag secrets missing ownership labels", False)
    check_replication = OptBool(True, "Flag automatic replication across regions", False)
    version_threshold = OptString("5", "Version count threshold for sprawl", False)
    max_secrets = OptString("40", "Maximum secrets to inspect deeply", False)
    export_json = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Show per-secret details", False)

    def run(self):
        try:
            print_info("Starting GCP Secret Manager sprawl analysis...")
            project_id = self._gcp_project_id()
            print_info(f"Project: {project_id or 'unknown'}")
            print_info("=" * 80)

            limit = self._gcp_to_int(self.max_secrets, 40)
            threshold = self._gcp_to_int(self.version_threshold, 5)
            secrets = list(self._gcp_body_dict("secrets").get("secrets") or [])[:limit]
            findings = {
                "project_id": project_id,
                "secrets_scanned": len(secrets),
                "many_versions": [],
                "no_rotation": [],
                "missing_labels": [],
                "automatic_replication": [],
            }

            for secret in secrets:
                name = secret.get("name", "")
                short_name = name.rsplit("/", 1)[-1]
                if not name:
                    continue
                if self.check_rotation and not secret.get("rotation"):
                    findings["no_rotation"].append(short_name)
                if self.check_labels and not secret.get("labels"):
                    findings["missing_labels"].append(short_name)
                if self.check_replication and (secret.get("replication") or {}).get("automatic"):
                    findings["automatic_replication"].append(short_name)
                if self.check_version_count:
                    versions = self._list_versions(name)
                    enabled = [v for v in versions if str(v.get("state", "")).upper() == "ENABLED"]
                    if len(enabled) >= threshold:
                        findings["many_versions"].append(
                            {"secret": short_name, "enabled_versions": len(enabled)}
                        )

            self._print_findings(findings, threshold)
            exported = self._gcp_export_json(self.export_json, findings) if self.export_json else ""
            if exported:
                print_success(f"Results exported to {exported}")
            return True
        except Exception as exc:
            print_error(f"Error during GCP secret sprawl analysis: {exc}")
            return False

    def _list_versions(self, secret_name):
        data = self._gcp_get_body(f"https://secretmanager.googleapis.com/v1/{secret_name}/versions")
        if not isinstance(data, dict):
            return []
        return list(data.get("versions") or [])

    def _print_findings(self, findings, threshold):
        many = findings.get("many_versions") or []
        print_status(f"Secrets with >= {threshold} enabled versions")
        if many:
            print_warning(f"Found {len(many)} secret(s) with many versions")
        else:
            print_success("No high version-count secrets detected")

        no_rotation = findings.get("no_rotation") or []
        print_status("Secrets without rotation")
        if no_rotation:
            print_warning(f"{len(no_rotation)} secret(s) without rotation")
        else:
            print_success("All inspected secrets have rotation configured")

        missing_labels = findings.get("missing_labels") or []
        if missing_labels:
            print_warning(f"{len(missing_labels)} secret(s) missing labels")

        auto_rep = findings.get("automatic_replication") or []
        if auto_rep:
            print_info(f"{len(auto_rep)} secret(s) use automatic multi-region replication")
        print_info("=" * 80)
