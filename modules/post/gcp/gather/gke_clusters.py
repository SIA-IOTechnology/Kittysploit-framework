#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP GKE Clusters",
        "description": "Enumerate Google Kubernetes Engine clusters in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "gke", "kubernetes", "enumeration"],
    'agent': {
        'risk': '',
        'effects': ['api_request'],
        'expected_requests': 1,
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    name_filter = OptString("", "Filter clusters by name substring", False)
    show_endpoints = OptBool(True, "Include control plane endpoint details", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating GKE clusters in {project_id}...")
            result = self._gcp_request("gke_clusters")
            if not result.get("ok"):
                print_error(f"GKE API request failed: {result.get('raw', '')[:500]}")
                return False

            clusters = self._flatten_clusters(result.get("body"))
            name_filter = str(self.name_filter or "").strip().lower()
            if name_filter:
                clusters = [
                    item for item in clusters if name_filter in str(item.get("name") or "").lower()
                ]

            rows = []
            for cluster in clusters:
                private_cfg = cluster.get("privateClusterConfig") or {}
                row = {
                    "name": cluster.get("name"),
                    "location": cluster.get("location"),
                    "status": cluster.get("status"),
                    "currentMasterVersion": cluster.get("currentMasterVersion"),
                    "currentNodeCount": cluster.get("currentNodeCount"),
                    "privateEndpointEnabled": private_cfg.get("enablePrivateEndpoint", False),
                }
                if self.show_endpoints:
                    row["endpoint"] = cluster.get("endpoint")
                    row["privateEndpoint"] = private_cfg.get("privateEndpoint")
                rows.append(row)

            print_info("=" * 80)
            if not rows:
                print_warning("No GKE clusters found")
            else:
                for row in rows:
                    print_info(
                        f"{row['name']} [{row.get('status', 'unknown')}] "
                        f"location={row.get('location')} nodes={row.get('currentNodeCount')}"
                    )
                    if self.show_endpoints and row.get("endpoint"):
                        private = "private" if row.get("privateEndpointEnabled") else "public"
                        print_info(f"  endpoint ({private}): {row['endpoint']}")
                print_success(f"Found {len(rows)} cluster(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "clusters": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "clusters": rows})
        except Exception as exc:
            print_error(f"GKE cluster enumeration failed: {exc}")
            return False

    @staticmethod
    def _flatten_clusters(body):
        if not isinstance(body, dict):
            return []
        scoped = body.get("clusters") or {}
        clusters = []
        if isinstance(scoped, dict):
            for zone_data in scoped.values():
                if isinstance(zone_data, dict):
                    clusters.extend(zone_data.get("clusters") or [])
        elif isinstance(scoped, list):
            clusters.extend(scoped)
        return clusters
