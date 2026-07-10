#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Normalize parsed GPO group settings for analysis."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

Resolver = Callable[[str, Optional[str]], Dict[str, Optional[str]]]


def _default_resolver(trustee: str, domain_sid: Optional[str] = None) -> Dict[str, Optional[str]]:
    trustee = (trustee or "").strip()
    if trustee.startswith("*S-") or trustee.startswith("S-"):
        sid = trustee.strip("*")
        return {"sid": sid, "name": trustee}
    return {"sid": None, "name": trustee}


def process_group_membership(
    settings: Dict[str, Dict[str, List[str]]],
    domain_sid: Optional[str] = None,
    resolver: Optional[Resolver] = None,
) -> List[Dict[str, Any]]:
    """Convert GptTmpl.inf Group Membership to analyser-friendly entries."""
    resolve = resolver or _default_resolver
    output: List[Dict[str, Any]] = []
    members_of: Dict[str, List[str]] = {}

    for group, membership in settings.items():
        if group.startswith("*"):
            sid = group.strip("*")
            info = resolve(sid, domain_sid)
            group_dict = {"sid": info.get("sid") or sid, "name": info.get("name") or group}
        else:
            info = resolve(group, domain_sid)
            group_dict = {"sid": info.get("sid"), "name": info.get("name") or group}

        members: List[Dict[str, Any]] = []
        for member in membership.get("Members", []):
            if not member:
                continue
            if member.startswith("*"):
                sid = member.strip("*")
                info = resolve(sid, domain_sid)
                members.append({"sid": info.get("sid") or sid, "name": info.get("name") or member, "action": "ADD"})
            else:
                info = resolve(member, domain_sid)
                members.append({"sid": info.get("sid"), "name": info.get("name") or member, "action": "ADD"})

        if members:
            output.append({
                "Group": group_dict,
                "Members": members,
                "Action": "REPLACE",
                "DeleteUsers": True,
                "DeleteGroups": True,
            })

        for member_of in membership.get("Memberof", []):
            if member_of:
                members_of.setdefault(member_of, []).append(group)

    for group, members in members_of.items():
        if group.startswith("*"):
            sid = group.strip("*")
            info = resolve(sid, domain_sid)
            parsed_group = {"sid": info.get("sid") or sid, "name": info.get("name") or group}
        else:
            info = resolve(group, domain_sid)
            parsed_group = {"sid": info.get("sid"), "name": info.get("name") or group}

        parsed_members: List[Dict[str, Any]] = []
        for member in members:
            if member.startswith("*"):
                sid = member.strip("*")
                info = resolve(sid, domain_sid)
                parsed_members.append({"sid": info.get("sid") or sid, "name": info.get("name") or member, "action": "ADD"})
            else:
                info = resolve(member, domain_sid)
                parsed_members.append({"sid": info.get("sid"), "name": info.get("name") or member, "action": "ADD"})

        if parsed_members:
            output.append({
                "Group": parsed_group,
                "Members": parsed_members,
                "Action": "UPDATE",
                "DeleteUsers": False,
                "DeleteGroups": False,
            })

    return output


def process_groups_xml(
    settings: Dict[str, Any],
    domain_sid: Optional[str] = None,
    resolver: Optional[Resolver] = None,
) -> List[Dict[str, Any]]:
    """Convert Groups.xml parsed structure to analyser-friendly entries."""
    resolve = resolver or _default_resolver
    groups = settings.get("Group")
    if not groups:
        return []

    output: List[Dict[str, Any]] = []
    for group in groups if isinstance(groups, list) else [groups]:
        props = group.get("Group") or {}
        group_sid = props.get("sid")
        group_name = props.get("name")
        if not group_sid and not group_name:
            continue

        group_dict = {"sid": group_sid, "name": group_name}
        if props.get("newname"):
            group_dict["newname"] = props.get("newname")
        if props.get("useraction"):
            group_dict["useraction"] = props.get("useraction")

        if group.get("Action") == "DELETE":
            output.append({"Group": group_dict, "Action": "DELETE"})
            continue

        members_out: List[Dict[str, Any]] = []
        for member in group.get("Members") or []:
            member_sid = member.get("sid")
            member_name = member.get("name")
            if not member_sid and not member_name:
                continue
            resolved_name = member_name
            resolved_sid = member_sid
            if member_sid:
                info = resolve(member_sid, domain_sid)
                resolved_name = info.get("name") or member_name
                resolved_sid = info.get("sid") or member_sid
            elif member_name:
                info = resolve(member_name, domain_sid)
                resolved_sid = info.get("sid")
                resolved_name = info.get("name") or member_name
            members_out.append({
                "sid": resolved_sid,
                "name": resolved_name,
                "action": (member.get("action") or "ADD").upper(),
            })

        output.append({
            "Group": group_dict,
            "Members": members_out,
            "Action": group.get("Action") or "UPDATE",
            "DeleteUsers": bool(group.get("DeleteUsers")),
            "DeleteGroups": bool(group.get("DeleteGroups")),
        })

    return output


def build_processed_gpo(
    parsed_files: Dict[str, Any],
    policy_type: str,
    domain_sid: Optional[str] = None,
    resolver: Optional[Resolver] = None,
) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """Merge parsed GPO files into processed settings for one policy scope."""
    processed: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    groups_xml = parsed_files.get("Groups.xml")
    if groups_xml:
        entries = process_groups_xml(groups_xml, domain_sid=domain_sid, resolver=resolver)
        if entries:
            processed.setdefault(policy_type, {}).setdefault("Groups.xml", []).extend(entries)

    if policy_type == "Machine":
        gpttmpl = parsed_files.get("GptTmpl.inf", {})
        membership = gpttmpl.get("Group Membership") if isinstance(gpttmpl, dict) else None
        if membership:
            entries = process_group_membership(membership, domain_sid=domain_sid, resolver=resolver)
            if entries:
                processed.setdefault(policy_type, {}).setdefault("Group Membership", []).extend(entries)

    return processed
