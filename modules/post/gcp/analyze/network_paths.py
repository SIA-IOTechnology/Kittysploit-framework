#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Network Paths",
        "description": "Map network exposure paths via firewalls, VPCs, GKE endpoints, and Cloud Run ingress",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "network", "firewall", "gke", "cloud"],
        "references": [
            "https://cloud.google.com/vpc/docs/firewalls",
            "https://attack.mitre.org/techniques/T1021/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['api_request'],
        'expected_requests': 10,
        'reversible': False,
        'approval_required': True,
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
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    check_firewalls = OptBool(True, "Analyze Compute firewall ingress paths", False)
    check_gke = OptBool(True, "Analyze GKE control plane reachability", False)
    check_cloud_run = OptBool(True, "List Cloud Run jobs/services locations", False)
    check_internal_ranges = OptBool(True, "Highlight broad internal source ranges", False)
    export_json = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Show detailed rule metadata", False)

    BROAD_INTERNAL_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

    def run(self):
        try:
            print_info("Starting GCP network path analysis...")
            project_id = self._gcp_project_id()
            print_info(f"Project: {project_id or 'unknown'}")
            print_info("=" * 80)

            findings = {
                "project_id": project_id,
                "internet_ingress_paths": [],
                "broad_internal_ingress": [],
                "gke_paths": [],
                "cloud_run_locations": {},
            }

            if self.check_firewalls:
                self._analyze_firewalls(findings)
            if self.check_gke:
                findings["gke_paths"] = self._analyze_gke()
            if self.check_cloud_run:
                findings["cloud_run_locations"] = self._analyze_cloud_run()

            internet = findings.get("internet_ingress_paths") or []
            public_gke = [
                c for c in findings.get("gke_paths") or []
                if c.get("endpoint") and not c.get("private_endpoint_enabled")
            ]
            print_info("=" * 80)
            print_warning(f"Internet ingress paths: {len(internet)}")
            print_warning(f"Broad internal ingress rules: {len(findings.get('broad_internal_ingress') or [])}")
            if public_gke:
                print_error(f"GKE clusters with public endpoints: {len(public_gke)}")
            else:
                print_success("No public GKE endpoints detected")

            exported = self._gcp_export_json(self.export_json, findings) if self.export_json else ""
            if exported:
                print_success(f"Results exported to {exported}")
            return True
        except Exception as exc:
            print_error(f"Error during GCP network path analysis: {exc}")
            return False

    def _analyze_firewalls(self, findings):
        print_status("Check: firewall ingress paths")
        for rule in list(self._gcp_body_dict("compute_firewalls").get("items") or []):
            if rule.get("disabled") or str(rule.get("direction", "INGRESS")).upper() != "INGRESS":
                continue
            source_ranges = self._gcp_as_list(rule.get("sourceRanges"))
            path = {
                "name": rule.get("name", ""),
                "network": rule.get("network", ""),
                "source_ranges": source_ranges,
                "allowed": rule.get("allowed"),
            }
            if self._gcp_firewall_is_public_source(source_ranges):
                sensitive_ports = []
                for entry in rule.get("allowed") or []:
                    sensitive_ports.extend(self._gcp_sensitive_ports(entry.get("ports")))
                path["sensitive_ports"] = sensitive_ports or ["all"]
                findings["internet_ingress_paths"].append(path)
                print_error(f"  Internet path: {path['name']} ports={path['sensitive_ports']}")
            elif self.check_internal_ranges and any(src in self.BROAD_INTERNAL_CIDRS for src in source_ranges):
                findings["broad_internal_ingress"].append(path)
        if not findings["internet_ingress_paths"]:
            print_success("No direct Internet ingress firewall paths found")
        print_info("-" * 80)

    def _analyze_gke(self):
        print_status("Check: GKE network paths")
        paths = []
        for scoped in (self._gcp_body_dict("gke_clusters").get("clusters") or {}).values():
            for cluster in scoped.get("clusters") or []:
                private_cfg = cluster.get("privateClusterConfig") or {}
                master_auth = cluster.get("masterAuthorizedNetworksConfig") or {}
                item = {
                    "name": cluster.get("name", ""),
                    "location": cluster.get("location", ""),
                    "endpoint": cluster.get("endpoint", ""),
                    "private_endpoint_enabled": private_cfg.get("enablePrivateEndpoint", False),
                    "master_authorized_networks": master_auth.get("enabled", False),
                }
                paths.append(item)
                if item["endpoint"] and not item["private_endpoint_enabled"]:
                    print_error(f"  Public GKE endpoint: {item['name']} -> {item['endpoint']}")
        print_info("-" * 80)
        return paths

    def _analyze_cloud_run(self):
        print_status("Check: Cloud Run locations")
        locs = list(self._gcp_body_dict("cloud_run_locations").get("locations") or [])
        jobs = list(self._gcp_body_dict("cloud_run_jobs").get("jobs") or [])
        if locs:
            print_info(f"Cloud Run enabled in {len(locs)} location(s)")
        if jobs:
            print_warning(f"Found {len(jobs)} Cloud Run job(s) — review ingress/IAM separately")
        print_info("-" * 80)
        return {"locations": locs, "jobs": [j.get("name", "") for j in jobs]}
