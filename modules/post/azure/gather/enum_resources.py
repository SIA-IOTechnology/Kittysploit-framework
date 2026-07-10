#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.azure import AzurePostMixin


class Module(Post, AzurePostMixin):
	__info__ = {
		"name": "Enumerate Azure Resources",
		"description": "List Azure resources visible to the current Run Command session identity",
		"author": "KittySploit Team",
		"session_type": SessionType.AZURE_RUN_COMMAND,
		"tags": ["azure", "cloud", "enumeration", "resources"],
		"agent": {
			"risk": "passive",
			"effects": ["api_request"],
			"expected_requests": 4,
			"reversible": True,
			"approval_required": False,
			"produces": ["risk_signals"],
			"chain": {
				"consumes_capabilities": ["cloud_identity"],
			},
		},
	}

	resource_group = OptString("", "Limit to one resource group (empty = subscription-wide)", False)
	type_filter = OptString("", "ARM resource type filter (e.g. Microsoft.Compute/virtualMachines)", False)
	max_items = OptInteger(200, "Maximum resources to list", False)
	group_by_type = OptBool(True, "Group output by resource type", False)
	export_json = OptString("", "Optional output JSON file", False)

	def run(self):
		try:
			subscription_id = self._azure_subscription_id()
			if not subscription_id:
				print_error("Could not resolve subscription_id from session")
				return False

			rg = str(self.resource_group or "").strip() or self._azure_resource_group()
			type_filter = str(self.type_filter or "").strip()
			filter_expr = f"resourceType eq '{type_filter}'" if type_filter else ""

			print_info("=" * 80)
			print_status(f"Enumerating Azure resources in subscription {subscription_id}")
			if rg:
				print_info(f"  resource_group: {rg}")
			if type_filter:
				print_info(f"  type_filter: {type_filter}")

			resources = self._azure_list_resources(
				resource_group=rg,
				filter_expr=filter_expr,
				max_items=int(self.max_items or 200),
			)
			if not resources:
				print_warning("No resources found or access denied")
				return self.module_result(success=True, data={"resources": []})

			if self.group_by_type:
				by_type = {}
				for item in resources:
					by_type.setdefault(item.get("type", "unknown"), []).append(item)
				for rtype in sorted(by_type.keys()):
					items = by_type[rtype]
					print_info("-" * 80)
					print_status(f"{rtype} ({len(items)})")
					for item in items:
						location = item.get("location") or "n/a"
						rg_name = item.get("resource_group") or "n/a"
						print_info(f"  - {item.get('name')} [{location}] (rg: {rg_name})")
			else:
				for item in resources:
					print_info(
						f"  - {item.get('name')} ({item.get('type')}) "
						f"[{item.get('location') or 'n/a'}]"
					)

			print_info("=" * 80)
			print_success(f"Found {len(resources)} resource(s)")

			if self.export_json:
				relpath = str(self.export_json or "").strip().lstrip("/")
				payload = {"subscription_id": subscription_id, "resources": resources}
				if relpath and self.write_out_dir(relpath, json.dumps(payload, indent=2), quiet=True):
					print_success(f"Results exported to {self.output_dir_path(relpath)}")

			return self.module_result(success=True, data={"resources": resources})
		except RuntimeError as exc:
			print_error(str(exc))
			return False
		except Exception as exc:
			print_error(f"Azure resource enumeration failed: {exc}")
			return False
