#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Read module __info__ from .py sources without importing (no side effects, no payload init)."""

from __future__ import annotations

import ast
import os
import re
from typing import Any, Dict, List, Optional, Set


SUPPORTED_MODULE_TYPES: Set[str] = {
    "analysis",
    "auxiliary",
    "backdoors",
    "browser_auxiliary",
    "browser_exploits",
    "docker_environment",
    "encoders",
    "exploits",
    "listeners",
    "transform",
    "payloads",
    "post",
    "scanner",
    "shortcut",
    "workflow",
}

# Map legacy or singular aliases to canonical DB/search types (see SUPPORTED_MODULE_TYPES).
MODULE_TYPE_ALIASES: Dict[str, str] = {
    "browserexploit": "browser_exploits",
    "browser_exploit": "browser_exploits",
    "browserauxiliary": "browser_auxiliary",
    "exploit": "exploits",
    "payload": "payloads",
    "listener": "listeners",
    "encoder": "encoders",
    "transforms": "transform",
    "obfuscators": "transform",
    "obfuscator": "transform",
    "backdoor": "backdoors",
    "scan": "scanner",
    "scanners": "scanner",
}


def normalize_module_type(module_type: str) -> str:
    """Map variant module type strings to canonical DB/search form."""
    if not module_type:
        return module_type
    key = str(module_type).strip().lower()
    return MODULE_TYPE_ALIASES.get(key, key)

MODULE_BASE_TYPES: Dict[str, str] = {
    "Analysis": "analysis",
    "Auxiliary": "auxiliary",
    "Backdoor": "backdoors",
    "BrowserAuxiliary": "browser_auxiliary",
    "BrowserExploit": "browser_exploits",
    "DockerEnvironment": "docker_environment",
    "Encoder": "encoders",
    "Exploit": "exploits",
    "Listener": "listeners",
    "LocalExploit": "exploits",
    "Transform": "transform",
    "Payload": "payloads",
    "Post": "post",
    "Scanner": "scanner",
    "Shortcut": "shortcut",
    "Workflow": "workflow",
}

OPTION_CLASS_NAMES: Set[str] = {
    "OptBool",
    "OptChoice",
    "OptFile",
    "OptFloat",
    "OptIP",
    "OptInteger",
    "OptPayload",
    "OptPort",
    "OptString",
}

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _string_ast_value(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Str):  # pragma: no cover - py<3.8
        return node.s
    return None


def _node_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _node_name(node.func)
    if isinstance(node, ast.Subscript):
        return _node_name(node.value)
    return ""


def _node_display(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - ast.unparse is available on supported Python
        return _node_name(node) or type(node).__name__


def _find_module_class(tree: ast.Module) -> Optional[ast.ClassDef]:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Module":
            return node
    return None


def _module_base_names(module_class: Optional[ast.ClassDef]) -> List[str]:
    if module_class is None:
        return []
    return [_node_name(base) for base in module_class.bases if _node_name(base)]


def _recognized_module_types(base_names: List[str]) -> List[str]:
    seen: List[str] = []
    for base_name in base_names:
        module_type = MODULE_BASE_TYPES.get(base_name)
        if module_type and module_type not in seen:
            seen.append(module_type)
    return seen


def _class_string_assignment(module_class: Optional[ast.ClassDef], attr_name: str) -> Optional[str]:
    if module_class is None:
        return None
    for item in module_class.body:
        if not isinstance(item, ast.Assign):
            continue
        for target in item.targets:
            if isinstance(target, ast.Name) and target.id == attr_name:
                return _string_ast_value(item.value)
    return None


def _find_info_assignment(module_class: Optional[ast.ClassDef], tree: ast.Module) -> Optional[ast.Assign]:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__info__":
                    return node
    if module_class is not None:
        for item in module_class.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name) and target.id == "__info__":
                        return item
    return None


def _dict_entries(dict_node: ast.Dict) -> Dict[str, ast.AST]:
    entries: Dict[str, ast.AST] = {}
    for key_node, value_node in zip(dict_node.keys, dict_node.values):
        key = _string_ast_value(key_node) if key_node is not None else None
        if key:
            entries[key] = value_node
    return entries


def _literal_strings(node: ast.AST) -> List[str]:
    value = _string_ast_value(node)
    if value is not None:
        return [value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        out: List[str] = []
        for element in node.elts:
            element_value = _string_ast_value(element)
            if element_value is not None:
                out.append(element_value)
        return out
    return []


def _literal_bool(node: ast.AST) -> Optional[bool]:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.NameConstant) and isinstance(node.value, bool):  # pragma: no cover - py<3.8
        return node.value
    return None


def _truthy_required_arg(node: ast.AST) -> Optional[bool]:
    bool_value = _literal_bool(node)
    if bool_value is not None:
        return bool_value
    string_value = _string_ast_value(node)
    if string_value is not None:
        return string_value.strip().lower() in {"1", "true", "yes", "y", "required"}
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return bool(node.value)
    return None


def _option_call_info(assign: ast.Assign) -> Optional[Dict[str, Any]]:
    if not isinstance(assign.value, ast.Call):
        return None
    option_class = _node_name(assign.value.func)
    if option_class not in OPTION_CLASS_NAMES:
        return None

    labels = [target.id for target in assign.targets if isinstance(target, ast.Name)]
    if not labels:
        return None

    required: Optional[bool] = None
    description = ""
    default_repr = ""
    if assign.value.args:
        default_repr = _node_display(assign.value.args[0])
    if len(assign.value.args) >= 2:
        description = _string_ast_value(assign.value.args[1]) or ""
    if len(assign.value.args) >= 3:
        required = _truthy_required_arg(assign.value.args[2])
    choices: List[str] = []
    for keyword in assign.value.keywords:
        if keyword.arg == "required":
            required = _truthy_required_arg(keyword.value)
        elif keyword.arg == "description":
            description = _string_ast_value(keyword.value) or description
        elif keyword.arg == "choices" and isinstance(keyword.value, (ast.List, ast.Tuple)):
            for element in keyword.value.elts:
                choice = _string_ast_value(element)
                if choice is not None:
                    choices.append(choice)

    result = {
        "labels": labels,
        "option_class": option_class,
        "required": bool(required),
        "description": description,
        "default": default_repr,
    }
    if choices:
        result["choices"] = choices
    return result


def _collect_class_options(module_class: Optional[ast.ClassDef]) -> Dict[str, Dict[str, Any]]:
    options: Dict[str, Dict[str, Any]] = {}
    if module_class is None:
        return options
    for item in module_class.body:
        if not isinstance(item, ast.Assign):
            continue
        option_info = _option_call_info(item)
        if not option_info:
            continue
        for label in option_info["labels"]:
            data = dict(option_info)
            data.pop("labels", None)
            options[label] = data
    return options


def _reference_entries_are_valid(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        for element in node.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                continue
            if isinstance(element, (ast.List, ast.Tuple)):
                pair_values = [_string_ast_value(item) for item in element.elts]
                if len(pair_values) >= 2 and all(pair_values[:2]):
                    continue
            return False
        return True
    return False


def _has_key(entries: Dict[str, ast.AST], key: str) -> bool:
    return key in entries


def _parse_static_info_dict(dict_node: ast.Dict) -> Dict[str, Any]:
    """When literal_eval(__info__) fails, read only static string / list-of-strings fields."""
    r: Dict[str, Any] = {
        "name": "",
        "description": "",
        "author": "",
        "tags": [],
        "cve": "",
        "platform": "",
        "protocol": "",
        "reliability": "",
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
        elif kl == "platform":
            r["platform"] = _metadata_scalar(v_node)
        elif kl == "protocol":
            v = _string_ast_value(v_node)
            if v is not None:
                r["protocol"] = v
        elif kl in {"reliability", "severity", "confidence"}:
            if not r.get("reliability"):
                r["reliability"] = _metadata_scalar(v_node)
    return r


def _metadata_scalar(node: ast.AST) -> str:
    value = _string_ast_value(node)
    if value is not None:
        return value
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr
    return _node_display(node)


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
        "platform": "",
        "protocol": "",
        "reliability": "",
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
            for key in ("platform", "protocol", "reliability"):
                if ev.get(key) is not None and not out.get(key):
                    out[key] = str(ev.get(key))
            if not out.get("reliability"):
                for fallback in ("severity", "confidence"):
                    if ev.get(fallback) is not None:
                        out["reliability"] = str(ev.get(fallback))
                        break
            merged_ast = _parse_static_info_dict(info_value)
            for key in ("platform", "protocol", "reliability"):
                if not out.get(key) and merged_ast.get(key):
                    out[key] = merged_ast[key]
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
        "platform": p.get("platform") or "",
        "protocol": p.get("protocol") or "",
        "reliability": p.get("reliability") or "",
    }


def validate_static_module_contract(module_path: str, file_path: str) -> Dict[str, Any]:
    """
    Validate the static module contract without importing the module.

    The validator is intentionally side-effect free: it parses source only and returns
    structured diagnostics that callers can decide to warn or block on.
    """
    errors: List[str] = []
    warnings: List[str] = []
    metadata: Dict[str, Any] = {
        "module_path": module_path,
        "file_path": file_path,
        "module_type": infer_module_type_from_path(module_path),
        "base_types": [],
        "options": {},
    }

    if not file_path or not os.path.isfile(file_path):
        errors.append("Module source file is missing")
        return {"valid": False, "errors": errors, "warnings": warnings, "metadata": metadata}

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            source = fh.read()
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as exc:
        errors.append(f"Python syntax error: {exc.msg} at line {exc.lineno}")
        return {"valid": False, "errors": errors, "warnings": warnings, "metadata": metadata}
    except Exception as exc:
        errors.append(f"Could not parse module source: {exc}")
        return {"valid": False, "errors": errors, "warnings": warnings, "metadata": metadata}

    module_class = _find_module_class(tree)
    if module_class is None:
        errors.append("Missing class Module")

    base_names = _module_base_names(module_class)
    recognized_types = _recognized_module_types(base_names)
    class_type = _class_string_assignment(module_class, "TYPE_MODULE")
    if class_type:
        normalized_class_type = infer_module_type_from_path(f"{class_type}/")
        if normalized_class_type in SUPPORTED_MODULE_TYPES and normalized_class_type not in recognized_types:
            recognized_types.append(normalized_class_type)
    metadata["base_classes"] = base_names
    metadata["base_types"] = recognized_types
    if module_class is not None and not recognized_types:
        errors.append(
            "class Module does not inherit a recognized KittySploit base class "
            f"({', '.join(sorted(MODULE_BASE_TYPES))}) or declare a valid TYPE_MODULE"
        )

    inferred_type = metadata["module_type"]
    if inferred_type not in SUPPORTED_MODULE_TYPES:
        errors.append(f"Invalid module type inferred from path: {inferred_type!r}")
    if recognized_types and inferred_type not in recognized_types:
        warnings.append(
            f"Path type {inferred_type!r} does not match Module base type(s): "
            f"{', '.join(recognized_types)}"
        )

    info_assignment = _find_info_assignment(module_class, tree)
    if info_assignment is None:
        errors.append("Missing __info__ dictionary")
        info_entries: Dict[str, ast.AST] = {}
    elif not isinstance(info_assignment.value, ast.Dict):
        errors.append("__info__ must be a dictionary literal")
        info_entries = {}
    else:
        info_entries = _dict_entries(info_assignment.value)

    metadata.update(parse_static_module_info(file_path))
    options = _collect_class_options(module_class)
    metadata["options"] = options

    if info_entries:
        for required_key in ("name", "description"):
            values = _literal_strings(info_entries.get(required_key, ast.Constant("")))
            if not any(str(value).strip() for value in values):
                errors.append(f"__info__ missing non-empty {required_key!r}")
        if not _has_key(info_entries, "author"):
            warnings.append("__info__ missing 'author'")

        type_values = _literal_strings(info_entries.get("type", ast.Constant("")))
        for type_value in type_values:
            normalized_type = infer_module_type_from_path(f"{type_value}/placeholder.py")
            if normalized_type not in SUPPORTED_MODULE_TYPES and type_value not in SUPPORTED_MODULE_TYPES:
                warnings.append(f"__info__ has unsupported type value: {type_value!r}")

        if _has_key(info_entries, "references"):
            refs_node = info_entries["references"]
            if not _reference_entries_are_valid(refs_node):
                warnings.append("__info__ references should be a string, list of strings, or list of [label, url] pairs")

        if _has_key(info_entries, "cve"):
            cve_values = _literal_strings(info_entries["cve"])
            for cve_value in cve_values:
                if cve_value and not CVE_RE.match(cve_value.strip()):
                    warnings.append(f"Invalid CVE format in __info__: {cve_value!r}")

        if inferred_type in {"exploits", "browser_exploits"}:
            if _has_key(info_entries, "payload"):
                payload_node = info_entries["payload"]
                if not isinstance(payload_node, ast.Dict):
                    warnings.append("__info__ payload metadata should be a dictionary")
                else:
                    payload_entries = _dict_entries(payload_node)
                    default_values = _literal_strings(payload_entries.get("default", ast.Constant("")))
                    if not any(value.strip() for value in default_values):
                        warnings.append("__info__ payload metadata missing non-empty 'default'")
            else:
                payload_option = options.get("payload")
                if payload_option is None or payload_option.get("required"):
                    warnings.append("Exploit has no payload compatibility metadata in __info__")

        if inferred_type == "payloads":
            for key in ("listener", "handler"):
                if not _has_key(info_entries, key):
                    warnings.append(f"Payload __info__ missing {key!r} compatibility metadata")
            listener_values = _literal_strings(info_entries.get("listener", ast.Constant("")))
            for listener_path in listener_values:
                if listener_path and not listener_path.startswith("listeners/") and not listener_path.startswith("metasploit/"):
                    warnings.append(f"Payload listener should reference listeners/... or metasploit/...: {listener_path!r}")

        if inferred_type == "listeners":
            for key in ("handler", "session_type"):
                if not _has_key(info_entries, key):
                    warnings.append(f"Listener __info__ missing {key!r} compatibility metadata")

    for option_name, option_data in options.items():
        if option_data.get("required"):
            if not option_data.get("description"):
                warnings.append(f"Required option {option_name!r} has no description")
            if option_data.get("default") in {"", "None"}:
                warnings.append(f"Required option {option_name!r} has an empty default")

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "metadata": metadata,
    }


def infer_module_type_from_path(module_path: str) -> str:
    """Map filesystem path prefix to a module type string (aligned with DB / filters)."""
    path = (module_path or "").lower()
    if path.startswith("modules/marketplace/"):
        parts = path.split("/")
        if len(parts) >= 3:
            return infer_module_type_from_path(f"{parts[2]}/")
    if path.startswith("modules/"):
        path = path[len("modules/"):]
    ordered = (
        ("analysis/", "analysis"),
        ("auxiliary/scanner/", "auxiliary"),
        ("auxiliary/", "auxiliary"),
        ("browser_exploits/", "browser_exploits"),
        ("browser_auxiliary/", "browser_auxiliary"),
        ("docker_environments/", "docker_environment"),
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
        ("transforms/", "transform"),
        ("transform/", "transform"),
        ("obfuscators/", "transform"),
        ("obfuscator/", "transform"),
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
            "browser_exploit": "browser_exploits",
            "browserexploit": "browser_exploits",
            "browserauxiliary": "browser_auxiliary",
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
