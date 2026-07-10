#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Cloud Run Services",
        "description": "Enumerate Cloud Run services in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "cloud-run", "enumeration"],
    'agent': {
        'risk': '',
        'effects': ['api_request'],
        'expected_requests': 2,
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
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    name_filter = OptString("", "Filter services by name substring", False)
    max_services = OptInteger(100, "Maximum services to return", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating Cloud Run services in {project_id}...")
            url = (
                f"https://run.googleapis.com/v2/projects/{self._quote_project(project_id)}"
                "/locations/-/services"
            )
            services = self._gcp_paginate_get(
                url, "services", max_items=int(self.max_services or 100)
            )
            name_filter = str(self.name_filter or "").strip().lower()
            rows = []
            for item in services:
                name = str(item.get("name") or "")
                short_name = name.rsplit("/", 1)[-1]
                if name_filter and name_filter not in name.lower():
                    continue
                template = (item.get("template") or {})
                containers = ((template.get("containers") or [{}])[0])
                row = {
                    "name": short_name,
                    "resource": name,
                    "location": self._location_from_name(name),
                    "uri": item.get("uri"),
                    "ingress": item.get("ingress"),
                    "serviceAccount": (template.get("serviceAccount") or ""),
                    "image": containers.get("image"),
                    "latestReadyRevision": item.get("latestReadyRevision"),
                }
                rows.append(row)

            print_info("=" * 80)
            if not rows:
                print_warning("No Cloud Run services found")
            else:
                for row in rows:
                    print_info(f"{row['name']} location={row.get('location')}")
                    if row.get("uri"):
                        print_info(f"  uri: {row['uri']}")
                    if row.get("serviceAccount"):
                        print_info(f"  serviceAccount: {row['serviceAccount']}")
                    if row.get("image"):
                        print_info(f"  image: {row['image']}")
                print_success(f"Found {len(rows)} service(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "services": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "services": rows})
        except Exception as exc:
            print_error(f"Cloud Run service enumeration failed: {exc}")
            return False

    @staticmethod
    def _location_from_name(resource_name):
        parts = str(resource_name or "").split("/")
        try:
            loc_index = parts.index("locations")
            return parts[loc_index + 1]
        except (ValueError, IndexError):
            return ""
