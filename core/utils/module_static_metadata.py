#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Read module __info__ from .py sources without importing (no side effects, no payload init)."""

from __future__ import annotations

import ast
import os
from typing import Any, Dict, List, Optional


def _string_ast_value(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Str):  # pragma: no cover - py<3.8
        return node.s
    return None


def _parse_static_info_dict(dict_node: ast.Dict) -> Dict[str, Any]:
    """When literal_eval(__info__) fails, read only static string / list-of-strings fields."""
    r: Dict[str, Any] = {
        "name": "",
        "description": "",
        "author": "",
        "tags": [],
        "cve": "",
    }
    for k_node, v_node in zip(dict_node.keys, dict_node.values):
        key = _string_ast_value(k_node)
        if not key:
            continue
        kl = key.lower()
        if kl == "name":
            v = _string_ast_value(v_node)
            if v is not None:
                r["name"] = v
        elif kl == "description":
            v = _string_ast_value(v_node)
            if v is not None:
                r["description"] = v
        elif kl == "author":
            if isinstance(v_node, (ast.List, ast.Tuple, ast.Set)):
                parts: List[str] = []
                for el in v_node.elts:
                    s = _string_ast_value(el)
                    if s is not None:
                        parts.append(s)
                r["author"] = ", ".join(parts)
            else:
                v = _string_ast_value(v_node)
                if v is not None:
                    r["author"] = v
        elif kl == "tags":
            tags: List[str] = []
            if isinstance(v_node, (ast.List, ast.Tuple, ast.Set)):
                for el in v_node.elts:
                    s = _string_ast_value(el)
                    if s:
                        tags.append(s)
            r["tags"] = tags
        elif kl == "cve":
            v = _string_ast_value(v_node)
            if v is not None:
                r["cve"] = v
    return r


def _find_module_info_dict(tree: ast.Module):
    """Locate __info__ dict: module-level or inside class Module (KittySploit layout)."""
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__info__":
                    return node.value
        if isinstance(node, ast.ClassDef) and node.name == "Module":
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name) and target.id == "__info__":
                            return item.value
    return None


def _apply_class_module_string_fallback(tree: ast.Module, out: Dict[str, Any]) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Module":
            for item in node.body:
                if not isinstance(item, ast.Assign):
                    continue
                for target in item.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    v = _string_ast_value(item.value)
                    if v is None:
                        continue
                    if target.id == "name" and not out["name"]:
                        out["name"] = v
                    elif target.id == "description" and not out["description"]:
                        out["description"] = v
                    elif target.id == "author" and not out["author"]:
                        out["author"] = v


def parse_static_module_info(file_path: str) -> Dict[str, Any]:
    """
    Return __info__ fields needed for DB sync / search, parsed from source only.

    Keys: name, description, author, version, cve, tags (list of str),
    references (list of str), options (dict).
    """
    out: Dict[str, Any] = {
        "name": "",
        "description": "",
        "author": "",
        "version": "",
        "cve": "",
        "tags": [],
        "references": [],
        "options": {},
    }
    if not file_path or not os.path.isfile(file_path):
        return out

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            source = fh.read()
        tree = ast.parse(source, filename=file_path)
    except Exception:
        return out

    info_value = _find_module_info_dict(tree)

    if isinstance(info_value, ast.Dict):
        try:
            ev = ast.literal_eval(info_value)
        except Exception:
            merged = {**out, **_parse_static_info_dict(info_value)}
            return merged

        if isinstance(ev, dict):
            out["name"] = str(ev.get("name") or "")
            out["description"] = str(ev.get("description") or "")
            auth = ev.get("author", "")
            if isinstance(auth, (list, tuple)):
                out["author"] = ", ".join(str(x) for x in auth if str(x).strip())
            else:
                out["author"] = str(auth or "")
            ver = ev.get("version", "")
            out["version"] = str(ver) if ver is not None else ""
            cv = ev.get("cve", "")
            out["cve"] = str(cv) if cv is not None else ""
            tgs = ev.get("tags") or []
            if isinstance(tgs, (list, tuple, set)):
                out["tags"] = [str(x) for x in tgs if str(x).strip()]
            refs = ev.get("references") or []
            if isinstance(refs, (list, tuple)):
                out["references"] = [str(x) for x in refs if str(x).strip()]
            elif isinstance(refs, str) and refs.strip():
                out["references"] = [refs.strip()]
            opts = ev.get("options")
            if isinstance(opts, dict):
                out["options"] = opts
            return out
        return out

    _apply_class_module_string_fallback(tree, out)
    return out


def extract_module_sync_metadata(file_path: str) -> Dict[str, Any]:
    """Alias for parse_static_module_info (DB sync, no imports)."""
    return parse_static_module_info(file_path)


def extract_module_search_metadata(file_path: str) -> Dict[str, Any]:
    """
    Parse __info__ for filesystem search fallback: name, description, author, tags (lowercased), cve.
    """
    p = parse_static_module_info(file_path)
    return {
        "name": p.get("name") or "",
        "description": p.get("description") or "",
        "author": p.get("author") or "",
        "tags": [t.lower() for t in (p.get("tags") or []) if t],
        "cve": p.get("cve") or "",
    }


def infer_module_type_from_path(module_path: str) -> str:
    """Map filesystem path prefix to a module type string (aligned with DB / filters)."""
    path = (module_path or "").lower()
    ordered = (
        ("analysis/", "auxiliary"),
        ("auxiliary/scanner/", "auxiliary"),
        ("auxiliary/", "auxiliary"),
        ("browser_exploits/", "browser_exploits"),
        ("browser_auxiliary/", "browser_auxiliary"),
        ("docker_environment/", "docker_environment"),
        ("exploits/", "exploits"),
        ("scanner/", "scanner"),
        ("post/", "post"),
        ("payloads/", "payloads"),
        ("payload/", "payloads"),
        ("workflow/", "workflow"),
        ("listeners/", "listeners"),
        ("listener/", "listeners"),
        ("encoders/", "encoders"),
        ("encoder/", "encoders"),
        ("obfuscators/", "obfuscator"),
        ("obfuscator/", "obfuscator"),
        ("backdoors/", "backdoors"),
        ("shortcut/", "shortcut"),
    )
    for pref, mtype in ordered:
        if path.startswith(pref):
            return mtype
    parts = path.split("/")
    if parts and parts[0]:
        first = parts[0].lower()
        remap = {
            "exploit": "exploits",
            "payload": "payloads",
            "scanner": "scanner",
            "listener": "listeners",
            "encoder": "encoders",
        }
        return remap.get(first, first)
    return "auxiliary"


def search_text_matches_title_description(name: str, description: str, query: str) -> bool:
    """Each query token must appear in name or description (case-insensitive)."""
    if not query or not str(query).strip():
        return True
    blob = f"{name} {description}".lower()
    for token in str(query).lower().replace(",", " ").split():
        t = token.strip()
        if t and t not in blob:
            return False
    return True
