#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Pub/Sub Inventory",
        "description": "Enumerate Pub/Sub topics and subscriptions in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "pubsub", "enumeration"],
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    name_filter = OptString("", "Filter topics/subscriptions by name substring", False)
    include_topics = OptBool(True, "Enumerate Pub/Sub topics", False)
    include_subscriptions = OptBool(True, "Enumerate Pub/Sub subscriptions", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating Pub/Sub inventory in {project_id}...")
            name_filter = str(self.name_filter or "").strip().lower()
            inventory = {"topics": [], "subscriptions": []}

            if self.include_topics:
                topics_result = self._gcp_request("pubsub_topics")
                if topics_result.get("ok"):
                    for item in (topics_result.get("body") or {}).get("topics") or []:
                        name = str(item.get("name") or "")
                        short_name = name.rsplit("/", 1)[-1]
                        if name_filter and name_filter not in name.lower():
                            continue
                        inventory["topics"].append({"name": short_name, "resource": name})
                else:
                    print_warning(f"Pub/Sub topics request failed: {topics_result.get('raw', '')[:200]}")

            if self.include_subscriptions:
                subs_result = self._gcp_request("pubsub_subscriptions")
                if subs_result.get("ok"):
                    for item in (subs_result.get("body") or {}).get("subscriptions") or []:
                        name = str(item.get("name") or "")
                        short_name = name.rsplit("/", 1)[-1]
                        if name_filter and name_filter not in name.lower():
                            continue
                        inventory["subscriptions"].append(
                            {
                                "name": short_name,
                                "resource": name,
                                "topic": item.get("topic"),
                                "ackDeadlineSeconds": item.get("ackDeadlineSeconds"),
                                "pushConfig": item.get("pushConfig"),
                            }
                        )
                else:
                    print_warning(
                        f"Pub/Sub subscriptions request failed: {subs_result.get('raw', '')[:200]}"
                    )

            print_info("=" * 80)
            if inventory["topics"]:
                print_info(f"Topics ({len(inventory['topics'])}):")
                for topic in inventory["topics"]:
                    print_info(f"  {topic['name']}")
            if inventory["subscriptions"]:
                print_info(f"Subscriptions ({len(inventory['subscriptions'])}):")
                for sub in inventory["subscriptions"]:
                    topic = str(sub.get("topic") or "").rsplit("/", 1)[-1]
                    print_info(f"  {sub['name']} -> {topic or 'unknown'}")

            total = len(inventory["topics"]) + len(inventory["subscriptions"])
            if total == 0:
                print_warning("No Pub/Sub topics or subscriptions found")
            else:
                print_success(
                    f"Found {len(inventory['topics'])} topic(s) and "
                    f"{len(inventory['subscriptions'])} subscription(s)"
                )

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, **inventory})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, **inventory})
        except Exception as exc:
            print_error(f"Pub/Sub inventory gather failed: {exc}")
            return False
