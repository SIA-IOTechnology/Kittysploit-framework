#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Agent chain context: structured details, KB sync, and module option pre-fill.

Bridges scanner ``details`` → ``attack_chain_memory`` → ``option_bindings`` on
downstream modules without requiring the LLM.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional
from urllib.parse import urlparse

from interfaces.command_system.builtin.agent.attack_chain_memory import (
    best_capability_value,
    build_chain_option_overrides,
    capabilities_present,
)
from interfaces.command_system.builtin.agent.chain_meta import normalize_chain_block


def sqli_chain_details_from_hit(hit: Mapping[str, Any]) -> Dict[str, str]:
    """Normalize a SQLi scanner hit into chain option / poison fields."""
    if not isinstance(hit, Mapping):
        return {}
    param = str(hit.get("param") or "").strip()
    method = str(hit.get("method") or "GET").strip().upper() or "GET"
    raw_url = str(hit.get("request_url") or hit.get("url") or "").strip()
    path = str(hit.get("path") or "").strip()
    if raw_url:
        parsed = urlparse(raw_url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
    if not path:
        path = "/"
    return {
        "inj_param": param,
        "inj_path": path[:512],
        "inj_method": method,
        "technique": str(hit.get("injection_type") or hit.get("technique") or "").strip(),
        "dbms": str(hit.get("dbms") or "").strip(),
    }


def lfi_chain_details_from_hit(
    hit: Mapping[str, Any],
    *,
    parameter: str = "file",
) -> Dict[str, str]:
    if not isinstance(hit, Mapping):
        return {}
    payload = str(hit.get("payload") or hit.get("lfi_path") or "").strip()
    log_path = ""
    if "access.log" in payload or "error.log" in payload:
        log_path = payload
    return {
        "lfi_param": str(parameter or hit.get("parameter") or "file").strip(),
        "lfi_path": payload[:512],
        "log_path": log_path[:512],
    }


def auth_chain_details_from_details(details: Mapping[str, Any]) -> Dict[str, str]:
    if not isinstance(details, Mapping):
        return {}
    out: Dict[str, str] = {}
    landing = (
        str(details.get("post_login_final_path") or "").strip()
        or str(details.get("landing_path") or "").strip()
    )
    if landing:
        out["landing_path"] = landing[:256]
    cookie_header = str(details.get("cookie_header") or "").strip()
    if cookie_header:
        out["cookie_header"] = cookie_header[:4000]
    session = str(details.get("session_cookie") or "").strip()
    if session:
        out["session_cookie"] = session[:512]
    return out


def enrich_result_details_for_chain(result: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Return a copy of ``result`` with normalized chain fields merged into ``details``.
    """
    if not isinstance(result, Mapping):
        return {}
    merged = dict(result)
    details = dict(merged.get("details") or {}) if isinstance(merged.get("details"), dict) else {}
    path = str(merged.get("path") or "").lower()

    if "sqli_engine" in path or "sql_injection" in path:
        rows = details.get("sqli_findings")
        if not isinstance(rows, list) or not rows:
            rows = details.get("hits")
        hit = rows[-1] if isinstance(rows, list) and rows else {}
        if isinstance(hit, dict):
            details.update({k: v for k, v in sqli_chain_details_from_hit(hit).items() if v})

    if "lfi_fuzzer" in path or ("lfi" in path and "poison" not in path):
        rows = details.get("lfi_findings") or details.get("hits") or []
        hit = rows[0] if isinstance(rows, list) and rows else {}
        if isinstance(hit, dict):
            details.update({
                k: v for k, v in lfi_chain_details_from_hit(
                    hit,
                    parameter=str(details.get("parameter") or hit.get("parameter") or "file"),
                ).items() if v
            })

    if "lfi_log_poison" in path:
        for key in ("log_path", "poison_payload", "lfi_param", "rce_confirmed"):
            val = details.get(key)
            if val:
                details[key] = str(val)

    if "admin_login_bruteforce" in path or "login" in path:
        details.update({k: v for k, v in auth_chain_details_from_details(details).items() if v})

    if "ssrf" in path:
        rows = details.get("ssrf_findings") or details.get("hits") or []
        hit = rows[0] if isinstance(rows, list) and rows else {}
        if isinstance(hit, dict):
            if hit.get("param"):
                details["ssrf_param"] = str(hit.get("param"))
            if hit.get("method"):
                details["ssrf_method"] = str(hit.get("method")).upper()

    if "graphql" in path:
        gql = str(details.get("graphql_path") or details.get("graphql_endpoint") or "").strip()
        if gql:
            details["graphql_endpoint"] = gql

    merged["details"] = details
    return merged


def sync_chain_context_to_kb(
    kb: MutableMapping[str, Any],
    results: List[Mapping[str, Any]],
) -> None:
    """Mirror the latest chain context slices onto the knowledge base."""
    if not isinstance(kb, MutableMapping):
        return

    for raw in results or []:
        if not isinstance(raw, Mapping):
            continue
        row = enrich_result_details_for_chain(raw)
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        path = str(row.get("path") or "").lower()

        if "sqli_engine" in path or "sql_injection" in path:
            sqli_rows = details.get("sqli_findings")
            if isinstance(sqli_rows, list) and sqli_rows:
                kb["sqli_findings"] = list(sqli_rows)[-24:]
            ctx = {k: details.get(k) for k in ("inj_param", "inj_path", "inj_method", "technique", "dbms") if details.get(k)}
            if ctx:
                kb["sqli_chain_context"] = ctx

        if "lfi" in path:
            ctx = {k: details.get(k) for k in ("lfi_param", "lfi_path", "log_path", "poison_payload") if details.get(k)}
            if ctx:
                kb["lfi_chain_context"] = ctx

        if "admin_login_bruteforce" in path and row.get("vulnerable"):
            ctx = auth_chain_details_from_details(details)
            if ctx:
                kb["auth_chain_context"] = ctx

        if "ssrf" in path:
            ctx = {k: details.get(k) for k in ("ssrf_param", "ssrf_method", "cloud_provider") if details.get(k)}
            if ctx:
                kb["ssrf_chain_context"] = ctx

        if "graphql" in path:
            gql = details.get("graphql_endpoint") or details.get("graphql_path")
            if gql:
                kb["graphql_chain_context"] = {"graphql_endpoint": gql}


def _best_sqli_hit(kb: Mapping[str, Any]) -> Dict[str, Any]:
    ctx = kb.get("sqli_chain_context") if isinstance(kb.get("sqli_chain_context"), dict) else {}
    if ctx:
        return dict(ctx)
    hits = kb.get("sqli_findings") or []
    if isinstance(hits, list) and hits:
        last = hits[-1]
        if isinstance(last, dict):
            return sqli_chain_details_from_hit(last)
    return {}


def _best_lfi_context(kb: Mapping[str, Any]) -> Dict[str, str]:
    ctx = kb.get("lfi_chain_context") if isinstance(kb.get("lfi_chain_context"), dict) else {}
    if ctx:
        return {str(k): str(v) for k, v in ctx.items() if v}
    memory_val = best_capability_value(kb, "log_file_path")
    out: Dict[str, str] = {}
    if memory_val and memory_val != "confirmed":
        out["log_path"] = memory_val
    param_val = best_capability_value(kb, "lfi_param")
    if param_val and param_val != "confirmed":
        out["lfi_param"] = param_val
    return out


def _best_auth_context(kb: Mapping[str, Any]) -> Dict[str, str]:
    ctx = kb.get("auth_chain_context") if isinstance(kb.get("auth_chain_context"), dict) else {}
    if ctx:
        return {str(k): str(v) for k, v in ctx.items() if v}
    out: Dict[str, str] = {}
    landing = best_capability_value(kb, "landing_path")
    if landing and landing != "confirmed":
        out["landing_path"] = landing
    cookie = best_capability_value(kb, "session_cookie")
    if cookie and cookie != "confirmed":
        out["cookies"] = cookie
        out["cookie_header"] = cookie
    return out


def build_chain_context_option_overrides(
    modules: List[Mapping[str, Any]],
    kb: Mapping[str, Any],
) -> Dict[str, Dict[str, Any]]:
    """
    Poison bindings plus KB context fallbacks for chain-aware modules.
    """
    overrides = dict(build_chain_option_overrides(modules, kb))
    if not isinstance(kb, Mapping):
        return overrides

    sqli_hit = _best_sqli_hit(kb)
    lfi_ctx = _best_lfi_context(kb)
    auth_ctx = _best_auth_context(kb)

    for module in modules or []:
        if not isinstance(module, Mapping):
            continue
        path = str(module.get("path") or "").strip()
        if not path:
            continue
        low = path.lower()
        mod_opts: Dict[str, Any] = dict(overrides.get(path) or {})

        if "sqli_shell" in low and sqli_hit:
            for opt in ("inj_param", "inj_path", "inj_method", "technique"):
                val = sqli_hit.get(opt)
                if val:
                    mod_opts[opt] = val
            technique = str(sqli_hit.get("technique") or "").lower()
            if technique in ("boolean", "boolean_numeric", "time", "blind_boolean"):
                mod_opts["technique"] = "blind_boolean"
            elif technique:
                mod_opts["technique"] = "union"
            mod_opts.setdefault("shell_sqli", True)

        if "lfi_log_poison" in low:
            target = str(kb.get("target_url") or kb.get("raw_target") or "").strip()
            if target and "target" not in mod_opts:
                mod_opts["target"] = target
            if lfi_ctx.get("lfi_param"):
                mod_opts["parameter"] = lfi_ctx["lfi_param"]
            if lfi_ctx.get("log_path"):
                mod_opts["log_path"] = lfi_ctx["log_path"]
            poison = best_capability_value(kb, "poisoned_payload")
            if poison and poison != "confirmed":
                mod_opts["php_payload"] = poison

        if "lfi_fuzzer" in low:
            endpoints = [str(e).strip() for e in (kb.get("discovered_endpoints", []) or []) if str(e).strip()]
            for ep in endpoints:
                if "?" in ep or lfi_ctx.get("lfi_param"):
                    mod_opts["target"] = ep if ep.startswith("http") else mod_opts.get("target")
                    break
            if lfi_ctx.get("lfi_param"):
                mod_opts["parameter"] = lfi_ctx["lfi_param"]

        if "authenticated_surface" in low and auth_ctx:
            if auth_ctx.get("landing_path"):
                mod_opts["landing_path"] = auth_ctx["landing_path"]
            if auth_ctx.get("cookies"):
                mod_opts["cookies"] = auth_ctx["cookies"]
            elif auth_ctx.get("cookie_header"):
                mod_opts["cookies"] = auth_ctx["cookie_header"]

        if "ssrf_cloud_metadata" in low:
            ssrf_param = best_capability_value(kb, "ssrf_param")
            if ssrf_param and ssrf_param != "confirmed":
                mod_opts["ssrf_param"] = ssrf_param
            ctx = kb.get("ssrf_chain_context") if isinstance(kb.get("ssrf_chain_context"), dict) else {}
            for key in ("ssrf_param", "ssrf_method"):
                if ctx.get(key):
                    mod_opts[key] = ctx[key]

        if "graphql_abuse" in low:
            gql = best_capability_value(kb, "graphql_endpoint")
            if gql and gql != "confirmed":
                mod_opts["graphql_path"] = gql

        if "dnp3_read_points" in low:
            dest = best_capability_value(kb, "dnp3_dest")
            if dest and dest != "confirmed":
                mod_opts["dest_address"] = dest

        if mod_opts:
            overrides[path] = mod_opts

    return overrides


def apply_chain_module_options(module_instance: Any, module_path: str, kb: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Apply chain context options directly on a loaded module instance.

    Returns the option mapping applied (for logging/tests).
    """
    path = str(module_path or "").strip()
    if not path or module_instance is None:
        return {}
    module_info = {"path": path, "agent": {}}
    try:
        info = getattr(module_instance, "__info__", {}) or {}
        if isinstance(info, dict):
            module_info["agent"] = info.get("agent") or {}
    except Exception:
        pass
    opts = build_chain_context_option_overrides([module_info], kb).get(path) or {}
    for key, value in opts.items():
        if not hasattr(module_instance, key):
            continue
        try:
            module_instance.set_option(key, value)
        except Exception:
            continue
    return opts


def chain_modules_ready(modules: List[Mapping[str, Any]], kb: Mapping[str, Any]) -> List[str]:
    """Module paths whose ``consumes_capabilities`` are satisfied in *kb*."""
    ready: List[str] = []
    present = capabilities_present(kb if isinstance(kb, Mapping) else {})
    for module in modules or []:
        if not isinstance(module, Mapping):
            continue
        path = str(module.get("path") or "").strip()
        agent = module.get("agent") if isinstance(module.get("agent"), dict) else {}
        chain = normalize_chain_block(agent.get("chain"))
        consumes = chain.get("consumes_capabilities") or []
        if consumes and all(cap in present for cap in consumes):
            ready.append(path)
    return ready
