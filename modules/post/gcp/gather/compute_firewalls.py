#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Compute Firewalls",
        "description": "Enumerate Compute Engine firewall rules in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "compute", "firewall", "enumeration"],
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

    name_filter = OptString("", "Filter firewalls by name substring", False)
    ingress_only = OptBool(False, "Only show ingress rules", False)
    public_only = OptBool(False, "Only show rules with Internet-facing source ranges", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating Compute firewalls in {project_id}...")
            result = self._gcp_request("compute_firewalls")
            if not result.get("ok"):
                print_error(f"Compute API request failed: {result.get('raw', '')[:500]}")
                return False

            rules = (result.get("body") or {}).get("items") or []
            name_filter = str(self.name_filter or "").strip().lower()
            rows = []
            for rule in rules:
                name = rule.get("name", "")
                if name_filter and name_filter not in name.lower():
                    continue
                direction = str(rule.get("direction") or "INGRESS").upper()
                if self.ingress_only and direction != "INGRESS":
                    continue
                source_ranges = self._gcp_as_list(rule.get("sourceRanges"))
                if self.public_only and not self._gcp_firewall_is_public_source(source_ranges):
                    continue
                rows.append(
                    {
                        "name": name,
                        "network": rule.get("network"),
                        "direction": direction,
                        "disabled": rule.get("disabled", False),
                        "priority": rule.get("priority"),
                        "sourceRanges": source_ranges,
                        "targetTags": rule.get("targetTags"),
                        "allowed": rule.get("allowed"),
                        "denied": rule.get("denied"),
                    }
                )

            print_info("=" * 80)
            if not rows:
                print_warning("No firewall rules found")
            else:
                for row in rows:
                    status = "disabled" if row.get("disabled") else "active"
                    print_info(f"{row['name']} [{status}] {row['direction']} priority={row.get('priority')}")
                    if row.get("sourceRanges"):
                        print_info(f"  sources: {', '.join(row['sourceRanges'])}")
                    if row.get("allowed"):
                        for entry in row["allowed"]:
                            ports = entry.get("ports") or ["all"]
                            print_info(f"  allow {entry.get('IPProtocol', 'tcp')}: {', '.join(ports)}")
                print_success(f"Found {len(rows)} firewall rule(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "firewalls": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "firewalls": rows})
        except Exception as exc:
            print_error(f"Compute firewall enumeration failed: {exc}")
            return False
