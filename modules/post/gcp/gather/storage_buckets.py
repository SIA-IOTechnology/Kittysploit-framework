#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Storage Buckets",
        "description": "Enumerate Cloud Storage buckets in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "gcs", "storage", "enumeration"],
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

    name_filter = OptString("", "Filter buckets by name substring", False)
    fetch_iam = OptBool(False, "Fetch IAM policy for each bucket (extra API calls)", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating Cloud Storage buckets in {project_id}...")
            result = self._gcp_request("storage_buckets")
            if not result.get("ok"):
                print_error(f"Storage API request failed: {result.get('raw', '')[:500]}")
                return False

            body = result.get("body") or {}
            buckets = body.get("items") or []
            name_filter = str(self.name_filter or "").strip().lower()
            if name_filter:
                buckets = [
                    item for item in buckets if name_filter in str(item.get("name") or "").lower()
                ]

            print_info("=" * 80)
            if not buckets:
                print_warning("No storage buckets found")
                return self.module_result(success=True, data={"buckets": []})

            rows = []
            for item in buckets:
                name = item.get("name", "unknown")
                row = {
                    "name": name,
                    "location": item.get("location"),
                    "locationType": item.get("locationType"),
                    "storageClass": item.get("storageClass"),
                    "timeCreated": item.get("timeCreated"),
                    "publicAccessPrevention": (item.get("iamConfiguration") or {}).get(
                        "publicAccessPrevention"
                    ),
                }
                if self.fetch_iam:
                    iam = self._gcp_get(
                        f"https://storage.googleapis.com/storage/v1/b/{name}/iam"
                    )
                    if iam.get("ok"):
                        row["iamPolicy"] = iam.get("body")
                rows.append(row)

                print_info(f"{name} location={row.get('location')} class={row.get('storageClass')}")
                if row.get("publicAccessPrevention"):
                    print_info(f"  publicAccessPrevention={row['publicAccessPrevention']}")
                if self.fetch_iam and row.get("iamPolicy"):
                    summary = self._summarize_bindings(row["iamPolicy"])
                    print_info(
                        f"  IAM: {summary['binding_count']} binding(s), "
                        f"{len(summary['roles'])} role(s)"
                    )

            print_success(f"Found {len(rows)} bucket(s)")
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "buckets": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "buckets": rows})
        except Exception as exc:
            print_error(f"Storage bucket enumeration failed: {exc}")
            return False
