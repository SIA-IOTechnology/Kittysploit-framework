#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Compute Attack Surface",
        "description": "Map Compute Engine attack surface: public IPs, scopes, metadata, and weak controls",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "compute", "attack-surface", "cloud"],
        "references": [
            "https://cloud.google.com/compute/docs/instances/verifying-instance-identity",
            "https://attack.mitre.org/techniques/T1525/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['api_request'],
        'expected_requests': 6,
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

    check_instances = OptBool(True, "Analyze Compute instances", False)
    check_firewalls = OptBool(True, "Correlate instances with Internet-facing firewalls", False)
    check_gke = OptBool(True, "Check GKE clusters with public control planes", False)
    max_instances = OptString("50", "Maximum instances to inspect", False)
    export_json = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Show per-instance details", False)

    def run(self):
        try:
            print_info("Starting GCP Compute attack surface analysis...")
            project_id = self._gcp_project_id()
            print_info(f"Project: {project_id or 'unknown'}")
            print_info("=" * 80)

            findings = {
                "project_id": project_id,
                "public_instances": [],
                "full_scope_instances": [],
                "default_sa_instances": [],
                "weak_controls": [],
                "internet_firewalls": [],
                "gke_public_endpoints": [],
            }

            if self.check_firewalls:
                findings["internet_firewalls"] = self._internet_firewalls()

            if self.check_instances:
                limit = self._gcp_to_int(self.max_instances, 50)
                for instance in self._flatten_compute_instances(self._gcp_body("compute_instances"))[:limit]:
                    self._analyze_instance(instance, findings)

            if self.check_gke:
                findings["gke_public_endpoints"] = self._analyze_gke()

            self._print_findings(findings)
            exported = self._gcp_export_json(self.export_json, findings) if self.export_json else ""
            if exported:
                print_success(f"Results exported to {exported}")
            return True
        except Exception as exc:
            print_error(f"Error during GCP Compute attack surface analysis: {exc}")
            return False

    def _internet_firewalls(self):
        exposed = []
        for rule in list(self._gcp_body_dict("compute_firewalls").get("items") or []):
            if rule.get("disabled") or str(rule.get("direction", "INGRESS")).upper() != "INGRESS":
                continue
            if not self._gcp_firewall_is_public_source(rule.get("sourceRanges")):
                continue
            sensitive = []
            for allowed in rule.get("allowed") or []:
                sensitive.extend(self._gcp_sensitive_ports(allowed.get("ports")))
            exposed.append(
                {
                    "name": rule.get("name", ""),
                    "target_tags": rule.get("targetTags"),
                    "sensitive_ports": sensitive or ["all"],
                }
            )
        return exposed

    def _analyze_instance(self, instance, findings):
        name = instance.get("name", "")
        zone = str(instance.get("zone", "")).rsplit("/", 1)[-1]
        external_ip = self._gcp_instance_external_ip(instance)
        sa_email = self._gcp_instance_service_account(instance)
        item = {
            "name": name,
            "zone": zone,
            "status": instance.get("status", ""),
            "external_ip": external_ip,
            "service_account": sa_email,
            "full_cloud_platform_scope": self._gcp_instance_full_scope(instance),
        }
        if external_ip:
            findings["public_instances"].append(item)
        if item["full_cloud_platform_scope"]:
            findings["full_scope_instances"].append(item)
        if sa_email.endswith("-compute@developer.gserviceaccount.com"):
            findings["default_sa_instances"].append(item)

        weak = []
        if instance.get("canIpForward"):
            weak.append("can_ip_forward")
        meta_keys = {
            str(entry.get("key", "")).lower()
            for entry in ((instance.get("metadata") or {}).get("items")) or []
        }
        if "enable-oslogin" not in meta_keys:
            weak.append("os_login_not_enforced")
        if instance.get("serialPortEnabled"):
            weak.append("serial_port_enabled")
        shielded = instance.get("shieldedInstanceConfig") or {}
        if shielded.get("enableSecureBoot") is False:
            weak.append("secure_boot_disabled")
        if weak:
            findings["weak_controls"].append({"name": name, "zone": zone, "issues": weak})

    def _analyze_gke(self):
        data = self._gcp_body_dict("gke_clusters")
        exposed = []
        for scoped in (data.get("clusters") or {}).values():
            for cluster in scoped.get("clusters") or []:
                private_cfg = cluster.get("privateClusterConfig") or {}
                if cluster.get("endpoint") and not private_cfg.get("enablePrivateEndpoint"):
                    exposed.append(
                        {
                            "name": cluster.get("name", ""),
                            "location": cluster.get("location", ""),
                            "endpoint": cluster.get("endpoint", ""),
                        }
                    )
        return exposed

    def _print_findings(self, findings):
        public = findings.get("public_instances") or []
        print_status("Instances with external IPs")
        if public:
            print_warning(f"Found {len(public)} instance(s) with external IPs")
        else:
            print_success("No instances with external NAT IPs in inspected set")

        scopes = findings.get("full_scope_instances") or []
        if scopes:
            print_error(f"Found {len(scopes)} instance(s) with cloud-platform scope")

        gke = findings.get("gke_public_endpoints") or []
        print_status("GKE public control planes")
        if gke:
            print_error(f"Found {len(gke)} GKE cluster(s) with public endpoints")
        else:
            print_success("No GKE clusters with public endpoints detected")
        print_info("=" * 80)
