#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.azure import AzurePostMixin


class Module(Post, AzurePostMixin):
	__info__ = {
		"name": "Azure Whoami",
		"description": "Display the Azure identity and subscription context for the current Run Command session",
		"author": "KittySploit Team",
		"session_type": SessionType.AZURE_RUN_COMMAND,
		"tags": ["azure", "cloud", "enumeration", "identity"],
		"agent": {
			"risk": "passive",
			"effects": ["api_request"],
			"expected_requests": 2,
			"reversible": True,
			"approval_required": False,
			"produces": ["risk_signals"],
			"chain": {
				"produces_capabilities": [
					{"capability": "cloud_identity", "from_detail": "subscription_id"},
					"cloud_credentials",
				],
				"suggested_followups": ["post/azure/gather/enum_resources"],
			},
		},
	}

	run_vm_whoami = OptBool(True, "Also run whoami on the target VM via Run Command", False)
	export_json = OptString("", "Optional output JSON file", False)

	def run(self):
		try:
			print_info("Resolving Azure session identity...")
			whoami = self._azure_whoami()
			if not whoami.get("subscription_id"):
				print_error("Could not resolve subscription_id from session")
				return False

			print_info("=" * 80)
			print_success("Azure session identity")
			for key in (
				"subscription_id",
				"subscription_name",
				"subscription_state",
				"tenant_id",
				"upn",
				"name",
				"object_id",
				"app_id",
				"resource_group",
				"vm_name",
				"os_type",
			):
				value = whoami.get(key, "")
				if value:
					print_info(f"  {key}: {value}")

			if self.run_vm_whoami:
				print_info("-" * 80)
				print_status("Target VM identity (Run Command)")
				vm_output = (self.cmd_execute("whoami") or "").strip()
				if vm_output:
					print_info(f"  {vm_output}")
				else:
					print_warning("Run Command whoami returned no output")

			if self.export_json:
				relpath = str(self.export_json or "").strip().lstrip("/")
				if relpath and self.write_out_dir(relpath, json.dumps(whoami, indent=2), quiet=True):
					print_success(f"Identity exported to {self.output_dir_path(relpath)}")

			return self.module_result(success=True, data=whoami)
		except RuntimeError as exc:
			print_error(str(exc))
			return False
		except Exception as exc:
			print_error(f"Azure whoami failed: {exc}")
			return False
