#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Firebase Exposure",
        "description": "Analyze Firebase/Firestore exposure: apps, hosting, rules, remote config, and API keys",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "firebase", "firestore", "exposure", "cloud"],
        "references": [
            "https://firebase.google.com/docs/rules",
            "https://attack.mitre.org/techniques/T1190/",
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

    check_web_apps = OptBool(True, "List Firebase web apps", False)
    check_hosting = OptBool(True, "List Firebase Hosting sites", False)
    check_rules = OptBool(True, "Inspect Firebase security rules releases", False)
    check_remote_config = OptBool(True, "Fetch Firebase Remote Config", False)
    check_api_keys = OptBool(True, "List API keys and restriction posture", False)
    check_firestore = OptBool(True, "List Firestore collections", False)
    export_json = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Show detailed API responses", False)

    def run(self):
        try:
            print_info("Starting GCP Firebase exposure analysis...")
            project_id = self._gcp_project_id()
            print_info(f"Project: {project_id or 'unknown'}")
            print_info("=" * 80)

            findings = {
                "project_id": project_id,
                "web_apps": [],
                "hosting_sites": [],
                "rules_releases": [],
                "remote_config": {},
                "api_keys": [],
                "firestore_collections": [],
                "risk_notes": [],
            }

            if self.check_web_apps:
                findings["web_apps"] = self._check_web_apps()
            if self.check_hosting:
                findings["hosting_sites"] = self._check_hosting()
            if self.check_rules:
                findings["rules_releases"] = self._check_rules(findings)
            if self.check_remote_config:
                findings["remote_config"] = self._check_remote_config(findings)
            if self.check_api_keys:
                findings["api_keys"] = self._check_api_keys(findings)
            if self.check_firestore:
                findings["firestore_collections"] = self._check_firestore(findings)

            notes = findings.get("risk_notes") or []
            print_info("=" * 80)
            if notes:
                print_warning("Risk notes:")
                for note in notes:
                    print_warning(f"  - {note}")
            else:
                print_success("No immediate Firebase exposure notes generated")

            exported = self._gcp_export_json(self.export_json, findings) if self.export_json else ""
            if exported:
                print_success(f"Results exported to {exported}")
            return True
        except Exception as exc:
            print_error(f"Error during GCP Firebase exposure analysis: {exc}")
            return False

    def _check_web_apps(self):
        print_status("Check: Firebase web apps")
        apps = list(self._gcp_body_dict("firebase_apps").get("apps") or [])
        if apps:
            print_warning(f"Found {len(apps)} Firebase web app(s)")
        else:
            print_info("No Firebase web apps returned")
        print_info("-" * 80)
        return apps

    def _check_hosting(self):
        print_status("Check: Firebase Hosting sites")
        sites = list(self._gcp_body_dict("firebase_sites").get("sites") or [])
        if sites:
            print_warning(f"Found {len(sites)} hosting site(s)")
        else:
            print_info("No Firebase Hosting sites returned")
        print_info("-" * 80)
        return sites

    def _check_rules(self, findings):
        print_status("Check: Firebase security rules releases")
        releases = list(self._gcp_body_dict("firebase_rules").get("releases") or [])
        risky = [{"release": r.get("name", ""), "ruleset": r.get("rulesetName", "")} for r in releases]
        if releases:
            findings["risk_notes"].append(
                "Review rulesets manually; open Firestore/Storage rules may allow unauthenticated access."
            )
            print_warning(f"Found {len(releases)} rules release(s) — manual rules review recommended")
        else:
            print_info("No Firebase rules releases returned")
        print_info("-" * 80)
        return risky

    def _check_remote_config(self, findings):
        print_status("Check: Firebase Remote Config")
        data = self._gcp_body_dict("remote_config")
        parameters = data.get("parameters") or {}
        if parameters:
            findings["risk_notes"].append(
                "Remote Config may expose feature flags, endpoints, or secrets to client apps."
            )
            print_warning(f"Remote Config returned {len(parameters)} parameter(s)")
        else:
            print_info("Remote Config not available or empty")
        print_info("-" * 80)
        return data

    def _check_api_keys(self, findings):
        print_status("Check: API keys")
        keys = list(self._gcp_body_dict("api_keys").get("keys") or [])
        risky = []
        for key in keys:
            restrictions = key.get("restrictions") or {}
            risky.append(
                {
                    "uid": key.get("uid", ""),
                    "display_name": key.get("displayName", ""),
                    "restrictions": restrictions,
                }
            )
            if not restrictions:
                findings["risk_notes"].append(
                    f"API key without restrictions: {key.get('displayName', key.get('uid', ''))}"
                )
        unrestricted = [k for k in risky if not k.get("restrictions")]
        if keys and unrestricted:
            print_error(f"{len(unrestricted)} API key(s) without restrictions")
        elif keys:
            print_success(f"Inspected {len(keys)} API key(s)")
        else:
            print_info("No API keys returned")
        print_info("-" * 80)
        return risky

    def _check_firestore(self, findings):
        print_status("Check: Firestore collections")
        collections = list(self._gcp_body_dict("firestore_collections").get("collectionIds") or [])
        if collections:
            findings["risk_notes"].append(
                "Firestore collections exist; validate security rules before assuming data is protected."
            )
            print_warning(f"Found {len(collections)} top-level Firestore collection(s)")
        else:
            print_info("No Firestore collections returned")
        print_info("-" * 80)
        return collections
