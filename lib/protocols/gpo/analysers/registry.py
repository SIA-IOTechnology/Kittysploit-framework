#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Registry-oriented GPO analysers."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from lib.protocols.gpo.decrypt import decrypt_vnc_password
from lib.protocols.gpo.rules import load_registry_rules


class GpoRegistryAnalyser:
    """Detect insecure or credential-bearing registry settings in GPO."""

    def __init__(self, rules: List[Dict[str, Any]] | None = None):
        self.rules = rules or load_registry_rules()

    def _match_rule(self, entry: Dict[str, str], rule: Dict[str, Any]) -> bool:
        key = (entry.get("Key") or "").lower()
        data = str(entry.get("Data") or "").lower()
        condition = rule.get("condition")
        target = str(rule.get("key") or "").lower()
        expected = str(rule.get("value") or "").lower()

        if condition == "value_equals":
            return key == target and data == expected
        if condition == "value_less_than":
            try:
                return key == target and int(entry.get("Data") or "0") < int(rule.get("value") or "0")
            except ValueError:
                return False
        if condition == "key_ends_with":
            return key.endswith(target)
        if condition == "key_regex":
            return bool(re.search(target, key, flags=re.I))
        return False

    def analyse(self, processed: Dict[str, Dict[str, List[Dict[str, str]]]]) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {}
        for policy_type in ("User", "Machine"):
            for source in ("Registry.xml", "registry.pol", "Registry Values"):
                for entry in processed.get(policy_type, {}).get(source, []):
                    for rule in self.rules:
                        if not self._match_rule(entry, rule):
                            continue
                        finding = {
                            "analysis": rule.get("analysis"),
                            "regkey": f'{entry.get("Hive")}\\{entry.get("Key")}',
                            "value": entry.get("Data"),
                            "references": rule.get("references"),
                            "source": source,
                        }
                        if rule.get("bloodhound_property"):
                            finding["bloodhound_property"] = rule.get("bloodhound_property")
                        if rule.get("decrypt") == "VNC" and entry.get("Data"):
                            decrypted = decrypt_vnc_password(str(entry.get("Data")))
                            if decrypted:
                                finding["decrypted"] = decrypted
                        results.setdefault(policy_type, []).append(finding)
        return results
