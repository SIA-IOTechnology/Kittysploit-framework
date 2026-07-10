#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect risky local group assignments in processed GPO settings."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Set

from lib.protocols.gpo.rules import load_group_rules

SamLookup = Callable[[], Set[str]]


class GpoGroupAnalyser:
    """Analyse privileged local group memberships configured via GPO."""

    def __init__(
        self,
        privileged_groups: Optional[Dict[str, Any]] = None,
        sam_lookup: Optional[SamLookup] = None,
        affected_computers: Optional[Callable[[str], List[Dict[str, str]]]] = None,
    ):
        self.privileged_groups = privileged_groups or load_group_rules()
        self._sam_lookup = sam_lookup
        self._affected_computers = affected_computers
        self._sam_cache: Optional[Set[str]] = None

    def _known_samaccountnames(self) -> Set[str]:
        if self._sam_cache is not None:
            return self._sam_cache
        if self._sam_lookup:
            self._sam_cache = {name.upper() for name in self._sam_lookup() if name}
        else:
            self._sam_cache = set()
        return self._sam_cache

    def _resolve_env_members(
        self,
        member_name: str,
        gpo_guid: str,
    ) -> tuple[Optional[Dict[str, List[str]]], List[Dict[str, str]]]:
        env_members: List[Dict[str, str]] = []
        env_match = re.findall(r"%(.*?)%", member_name, flags=re.I)
        if not env_match or "%computername%" not in [v.lower() for v in env_match]:
            return None, env_members

        if not self._affected_computers:
            return None, env_members

        computers = self._affected_computers(gpo_guid)
        known = self._known_samaccountnames()
        hijackable = {"lte_20": [], "gt_20": []}

        for computer in computers:
            machine_name = (computer.get("samaccountname") or computer.get("name") or "").strip()
            if not machine_name:
                continue
            resolved = re.sub(r"%computername%", machine_name.rstrip("$"), member_name, flags=re.I)
            sam = resolved.split("\\", 1)[-1].upper()
            if known and sam in known:
                env_members.append({
                    "sid": computer.get("sid") or "",
                    "name": resolved,
                    "computer_sid": computer.get("sid") or "",
                    "computer_name": machine_name,
                })
            else:
                bucket = "lte_20" if len(resolved) <= 20 else "gt_20"
                hijackable[bucket].append(resolved)

        if hijackable["lte_20"] or hijackable["gt_20"]:
            return hijackable, env_members
        return None, env_members

    def analyse(
        self,
        processed_gpo: Dict[str, Dict[str, List[Dict[str, Any]]]],
        *,
        gpo_guid: str = "",
        domain_sid: Optional[str] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {}

        for policy_type in ("User", "Machine"):
            output: Dict[str, Dict[str, Any]] = {}
            scope = processed_gpo.get(policy_type) or {}

            for config_name in ("Groups.xml", "Group Membership"):
                for group in scope.get(config_name) or []:
                    if not group or group.get("Action") == "REMOVE":
                        continue

                    group_info = group.get("Group") or {}
                    group_sid = (group_info.get("sid") or "").upper()
                    if group_sid not in self.privileged_groups:
                        continue

                    meta = self.privileged_groups[group_sid]
                    output.setdefault(group_sid, {
                        "sid": group_sid,
                        "name": meta.get("name"),
                        "edge": meta.get("edge"),
                        "analysis": set(),
                        "references": set(),
                    })

                    if group.get("Members"):
                        output[group_sid]["analysis"].add(
                            f'Trustees are added to the local "{meta.get("name")}" group.'
                        )
                        output[group_sid]["references"].add(meta.get("edge_reference") or "")

                        for member in group.get("Members") or []:
                            if (member.get("action") or "ADD").upper() != "ADD":
                                continue
                            entry = {
                                "sid": member.get("sid"),
                                "name": member.get("name"),
                            }
                            output[group_sid].setdefault("Members", []).append(entry)

                            name = member.get("name") or ""
                            member_name = name.split("\\", 1)[-1] if "\\" in name else name
                            env_match = re.findall(r"%(.*?)%", member_name)
                            if env_match:
                                output[group_sid]["references"].add(
                                    "https://www.cogiceo.com/en/whitepaper_gpphijacking/"
                                )

                            if not member.get("sid") and member_name:
                                hijackable, env_members = self._resolve_env_members(member_name, gpo_guid)
                                if env_members:
                                    output[group_sid].setdefault("EnvMembers", []).extend(env_members)
                                if hijackable:
                                    output[group_sid]["analysis"].add(
                                        "Potentially hijackable sAMAccountName(s) if not linked to local account(s)."
                                    )
                                    output[group_sid]["references"].add(
                                        "https://www.cogiceo.com/en/whitepaper_gpphijacking/"
                                    )
                                    output[group_sid].setdefault("Hijackable", {"lte_20": [], "gt_20": []})
                                    output[group_sid]["Hijackable"]["lte_20"].extend(hijackable.get("lte_20", []))
                                    output[group_sid]["Hijackable"]["gt_20"].extend(hijackable.get("gt_20", []))
                                elif "@" in member_name and not member.get("sid"):
                                    bucket = "lte_20" if len(member_name) <= 20 else "gt_20"
                                    output[group_sid].setdefault("Hijackable", {"lte_20": [], "gt_20": []})
                                    output[group_sid]["Hijackable"][bucket].append(member_name)

                    if policy_type == "User" and group_info.get("useraction") == "ADD":
                        output[group_sid]["analysis"].add(
                            f'Interactive logon users are assigned to the local "{group_info.get("name")}" group.'
                        )
                        output[group_sid]["references"].add(
                            "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/4b6788a7-c106-4e55-9cfc-1a52bb786e86"
                        )

                    if group_info.get("newname"):
                        output[group_sid]["analysis"].add(
                            f'The privileged group "{meta.get("name")}" is renamed to "{group_info.get("newname")}".'
                        )
                        output[group_sid]["references"].add(
                            "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/4b6788a7-c106-4e55-9cfc-1a52bb786e86"
                        )

            for group_sid, finding in output.items():
                if not finding.get("analysis"):
                    continue
                finding["analysis"] = "\n".join(sorted(finding["analysis"]))
                finding["references"] = "\n".join(sorted(ref for ref in finding["references"] if ref))
                results.setdefault(policy_type, []).append(finding)

        return results
