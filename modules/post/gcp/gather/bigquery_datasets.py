#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP BigQuery Datasets",
        "description": "Enumerate BigQuery datasets in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "bigquery", "enumeration"],
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
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    name_filter = OptString("", "Filter datasets by datasetId substring", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating BigQuery datasets in {project_id}...")
            result = self._gcp_request("bigquery_datasets")
            if not result.get("ok"):
                print_error(f"BigQuery API request failed: {result.get('raw', '')[:500]}")
                return False

            datasets = (result.get("body") or {}).get("datasets") or []
            name_filter = str(self.name_filter or "").strip().lower()
            rows = []
            for item in datasets:
                ref = item.get("datasetReference") or {}
                dataset_id = ref.get("datasetId") or ""
                if name_filter and name_filter not in dataset_id.lower():
                    continue
                rows.append(
                    {
                        "datasetId": dataset_id,
                        "projectId": ref.get("projectId"),
                        "friendlyName": item.get("friendlyName"),
                        "location": item.get("location"),
                    }
                )

            print_info("=" * 80)
            if not rows:
                print_warning("No BigQuery datasets found")
            else:
                for row in rows:
                    label = row.get("friendlyName") or row["datasetId"]
                    print_info(f"{label} location={row.get('location')}")
                    if row.get("friendlyName"):
                        print_info(f"  datasetId: {row['datasetId']}")
                print_success(f"Found {len(rows)} dataset(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "datasets": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "datasets": rows})
        except Exception as exc:
            print_error(f"BigQuery dataset enumeration failed: {exc}")
            return False
