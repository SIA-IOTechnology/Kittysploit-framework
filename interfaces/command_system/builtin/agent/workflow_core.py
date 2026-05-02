#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent workflow implementation (scan, knowledge, exploit, reasoning)."""

import ast
import asyncio
import json
import os
import random
import re
import socket

import ssl
import random
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import aiohttp
    HAS_AIOHTTP = True
except Exception:
    aiohttp = None
    HAS_AIOHTTP = False

from interfaces.command_system.builtin.agent.state import (
    AgentState,
    agent_state_from_dict,
    agent_state_to_dict,
)

from interfaces.command_system.builtin.scanner_command import ScannerCommand
from core.output_handler import (
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    set_thread_output_quiet,
)

try:
    from langgraph.graph import END, StateGraph
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False
    END = "__end__"
    StateGraph = None

from interfaces.command_system.builtin.agent.agent_constants import (
    AUTH_FIRST_DEPRIORITIZE_SUBSTRINGS,
    AUTH_PATH_MARKERS,
    CAMPAIGN_GOAL_EXPLOIT,
    CAMPAIGN_GOAL_OBTAIN_AUTH,
    CAMPAIGN_GOAL_POST_AUTH,
    CAMPAIGN_GOAL_RECON,
    CAMPAIGN_GOAL_SHELL_STOP,
    CMS_HINT_TOKENS,
    CMS_LOCK_NAMES,
    CMS_SPECIALIZATION_BLOB_TOKENS,
    DEFAULT_AGENT_USER_AGENT,
    DISALLOWED_POST_AUTH_TOKENS,
    DRUPAL_BLOB_MARKERS,
    DERIVED_HOST_SCAN_MAX_HOSTS,
    DERIVED_HOST_SCAN_MODULES_PER_HOST,
    EXPANDED_SURFACE_MODULE_PREFIXES,
    EXPANDED_SURFACE_RECON_SKIP_SUBSTR,
    HTTP_REDIRECT_STATUSES,
    HTTP_STATUS_RISK_SIGNALS,
    JOOMLA_BLOB_MARKERS,
    NEGATIVE_EVIDENCE_MARKERS,
    POSITIVE_EVIDENCE_MARKERS,
    POSITIVE_SCAN_MESSAGE_MARKERS,
    SAFE_PROFILE_BLOCKED_MODULE_SUBSTRINGS,
    SAFE_FOLLOWUP_ACTION_TYPES,
    WAF_BODY_MARKERS,
    WAF_RISK_HTTP_STATUS_CODES,
    WORDPRESS_BODY_FINGERPRINT_TOKENS,
    WORDPRESS_FORM_FIELD_TOKENS,
    WORDPRESS_LANDING_PATH_MARKERS,
)
from interfaces.command_system.builtin.agent.target_resolver import TargetResolver
from interfaces.command_system.builtin.agent.module_catalog import ModuleCatalogService
from interfaces.command_system.builtin.agent.local_llm import LocalLLMService
from interfaces.command_system.builtin.agent.report_service import ReportService
from interfaces.command_system.builtin.agent.auth_operations import AuthContextOperations
from interfaces.command_system.builtin.agent.io_utils import atomic_write_json, load_json_dict
from interfaces.command_system.builtin.agent.module_scoring import (
    ModuleScoreRules,
    information_score_kb,
    module_blob_lower,
    module_path_lower,
    score_rules,
    score_tech_hints_in_blob,
)
from interfaces.command_system.builtin.agent.campaign_utility import (
    module_utility,
    select_opportunistic_batch,
    unified_module_score,
)
from interfaces.command_system.builtin.agent.module_context_memory import ModuleContextMemory
from interfaces.command_system.builtin.agent.module_performance_memory import (
    ModulePerformanceMemory,
    kb_light_copy,
)
from interfaces.command_system.builtin.agent.compiled_patterns import (
    ABSOLUTE_URL_RE,
    ACRONYM_RE,
    COMMA_SEMICOLON_SPLIT_RE,
    ENDPOINT_RE,
    HTTP_STATUS_IN_TEXT_RE,
    LOGIN_PAGE_PATH_IN_MESSAGE_RE,
    PARAM_RE,
    POST_AUTH_WORD_RE,
    SCRIPT_RE,
    STYLE_RE,
    TAG_RE,
    WORD_RE,
)


class AgentWorkflowCore:
    """Orchestrates autonomous scan → analyze → reason → exploit → report."""

    def __init__(self, framework):
        self.framework = framework
        self._catalog = ModuleCatalogService(framework)
        self._target_resolver = TargetResolver()
        self._llm = LocalLLMService()
        self._report = ReportService()
        self._auth_ops = AuthContextOperations(self._normalize_relative_path)
        self._module_perf = ModulePerformanceMemory()
        self._module_ctx = ModuleContextMemory()

    def _network_error_markers(self) -> Tuple[str, ...]:
        return (
            "connection refused",
            "failed to establish a new connection",
            "max retries exceeded",
            "name or service not known",
            "temporary failure in name resolution",
            "nodename nor servname provided",
            "network is unreachable",
            "no route to host",
            "target is not reachable",
            "target not reachable",
            "connection timeout",
            "read timed out",
            "connect timeout",
            "connection aborted",
            "remote end closed connection",
        )

    def _agent_user_agent(self, state: AgentState) -> str:
        value = str(getattr(state, "user_agent", "") or "").strip()
        if value:
            return value
        
        # Spoofed user agents list
        chrome_uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]
        return random.choice(chrome_uas)


    def _create_spoofed_ssl_context(self) -> Any:
        ctx = ssl.create_default_context()
        # Chrome JA3-like ciphers
        ctx.set_ciphers('TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA')
        try:
            ctx.set_ecdh_curve('prime256v1')
        except Exception:
            pass
        return ctx

    def _agent_http_headers(self, state: AgentState) -> Dict[str, str]:
        return {"User-Agent": self._agent_user_agent(state)}

    async def _async_http_probe_one(
        self,
        session: Any,
        url: str,
        timeout_s: float,
        read_bytes: int,
    ) -> Dict[str, Any]:
        try:
            async with session.get(url, timeout=timeout_s, allow_redirects=True) as response:
                raw = await response.content.read(read_bytes)
                return {
                    "url": url,
                    "status": int(response.status or 0),
                    "headers": {str(k).lower(): str(v) for k, v in response.headers.items()},
                    "body": raw.decode("utf-8", errors="ignore"),
                    "final_url": str(response.url),
                    "error": "",
                }
        except Exception as exc:
            return {"url": url, "status": 0, "headers": {}, "body": "", "final_url": "", "error": str(exc)}

    async def _async_http_probe_many(
        self,
        state: AgentState,
        urls: List[str],
        timeout_s: float = 4.0,
        read_bytes: int = 8192,
    ) -> List[Dict[str, Any]]:
        timeout = aiohttp.ClientTimeout(total=timeout_s) if HAS_AIOHTTP else None
        headers = self._agent_http_headers(state)
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            tasks = [self._async_http_probe_one(session, url, timeout_s, read_bytes) for url in urls]
            return list(await asyncio.gather(*tasks))

    def _run_async_http_probe_many(
        self,
        state: AgentState,
        urls: List[str],
        timeout_s: float = 4.0,
        read_bytes: int = 8192,
    ) -> Optional[List[Dict[str, Any]]]:
        if not getattr(state, "async_probes", False) or not HAS_AIOHTTP or not urls:
            return None
        try:
            return asyncio.run(self._async_http_probe_many(state, urls, timeout_s, read_bytes))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(self._async_http_probe_many(state, urls, timeout_s, read_bytes))
            finally:
                loop.close()
        except Exception as exc:
            if getattr(state, "verbose", False):
                print_warning(f"Async probe failed, falling back to urllib: {exc}")
            return None

    def _sync_http_probe_one(
        self,
        state: AgentState,
        url: str,
        timeout_s: float = 4.0,
        read_bytes: int = 8192,
    ) -> Dict[str, Any]:
        request = urllib.request.Request(
            url,
            headers=self._agent_http_headers(state),
            method="GET",
        )
        try:
            if url.startswith("https://"):
                ctx = self._create_spoofed_ssl_context()
                with urllib.request.urlopen(request, timeout=timeout_s, context=ctx) as response:
                    body = response.read(read_bytes).decode("utf-8", errors="ignore")
                    return {
                        "url": url,
                        "status": int(getattr(response, "status", 0) or response.getcode() or 0),
                        "headers": {k.lower(): str(v) for k, v in response.headers.items()},
                        "body": body,
                        "final_url": str(response.geturl() or ""),
                        "error": "",
                    }
            else:
                with urllib.request.urlopen(request, timeout=timeout_s) as response:
                    body = response.read(read_bytes).decode("utf-8", errors="ignore")
                    return {
                        "url": url,
                        "status": int(getattr(response, "status", 0) or response.getcode() or 0),
                        "headers": {k.lower(): str(v) for k, v in response.headers.items()},
                        "body": body,
                        "final_url": str(response.geturl() or ""),
                        "error": "",
                    }
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(read_bytes).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return {
                "url": url,
                "status": int(exc.code or 0),
                "headers": {k.lower(): str(v) for k, v in (exc.headers.items() if exc.headers else [])},
                "body": body,
                "final_url": str(getattr(exc, "url", "") or ""),
                "error": "",
            }
        except Exception as exc:
            return {"url": url, "status": 0, "headers": {}, "body": "", "final_url": "", "error": str(exc)}

    def _http_probe_many(
        self,
        state: AgentState,
        urls: List[str],
        timeout_s: float = 4.0,
        read_bytes: int = 8192,
    ) -> List[Dict[str, Any]]:
        async_rows = self._run_async_http_probe_many(state, urls, timeout_s, read_bytes)
        if async_rows is not None:
            return async_rows
        rows = []
        for url in urls:
            self._sleep_between_agent_actions(state, f"http-probe:{url}")
            rows.append(self._sync_http_probe_one(state, url, timeout_s, read_bytes))
        return rows

    def _normalized_safety_profile(self, state: AgentState) -> str:
        profile = str(getattr(state, "safety_profile", "normal") or "normal").strip().lower()
        if profile not in {"safe", "normal", "aggressive"}:
            return "normal"
        return profile

    def _action_delay_bounds(self, state: AgentState) -> Tuple[float, float]:
        try:
            delay_min = max(0.0, float(getattr(state, "request_delay_min", 0.0) or 0.0))
        except Exception:
            delay_min = 0.0
        try:
            delay_max = max(0.0, float(getattr(state, "request_delay_max", 0.0) or 0.0))
        except Exception:
            delay_max = 0.0
        if delay_max < delay_min:
            delay_max = delay_min
        return delay_min, delay_max

    def _sleep_between_agent_actions(self, state: AgentState, context: str = "") -> None:
        delay_min, delay_max = self._action_delay_bounds(state)
        if delay_max <= 0:
            return
        delay = random.uniform(delay_min, delay_max)
        if delay <= 0:
            return
        if getattr(state, "verbose", False):
            suffix = f" before {context}" if context else ""
            print_info(f"Rate limit: sleeping {delay:.2f}s{suffix}")
        time.sleep(delay)

    def _module_block_reason_for_profile(self, state: AgentState, module_path: Any) -> str:
        if self._normalized_safety_profile(state) != "safe":
            return ""
        low = str(module_path or "").lower()
        for token in SAFE_PROFILE_BLOCKED_MODULE_SUBSTRINGS:
            if token in low:
                return f"safe profile blocks noisy module token `{token}`"
        return ""

    def _filter_modules_for_safety_profile(
        self,
        state: AgentState,
        modules: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        allowed: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        for module in modules or []:
            path = module.get("path") if isinstance(module, dict) else ""
            reason = self._module_block_reason_for_profile(state, path)
            if reason:
                skipped.append({
                    "module": module.get("name", path) if isinstance(module, dict) else str(path),
                    "path": path,
                    "status": "skipped",
                    "vulnerable": False,
                    "message": reason,
                    "details": {"safety_profile": self._normalized_safety_profile(state)},
                })
                continue
            allowed.append(module)
        if skipped and getattr(state, "verbose", False):
            print_warning(f"Safety profile skipped {len(skipped)} noisy module(s)")
        return allowed, skipped

    def _adapt_rate_limit_from_results(self, state: AgentState, results: List[Any]) -> None:
        if self._normalized_safety_profile(state) == "aggressive":
            return
        saw_rate_limit = False
        for result in results or []:
            if not isinstance(result, dict):
                continue
            blob = " ".join([
                str(result.get("status", "")),
                str(result.get("message", "")),
                str(result.get("details", "")),
            ]).lower()
            if "429" in blob or "rate limit" in blob or "too many requests" in blob:
                saw_rate_limit = True
                break
        if not saw_rate_limit:
            return
        delay_min, delay_max = self._action_delay_bounds(state)
        state.request_delay_min = max(delay_min, 2.0)
        state.request_delay_max = max(delay_max, 6.0)
        if getattr(state, "verbose", False):
            print_warning("Rate limit signal detected; increasing agent delay window")

    def _result_waf_signal(self, result: Any) -> bool:
        if not isinstance(result, dict):
            return False
        status_values = []
        for key in ("status_code", "http_status", "code"):
            try:
                if key in result:
                    status_values.append(int(result.get(key) or 0))
            except Exception:
                pass
        blob = " ".join([
            str(result.get("status", "")),
            str(result.get("message", "")),
            str(result.get("details", "")),
            str(result.get("body", ""))[:4096],
        ]).lower()
        status_values.extend([int(code) for code in HTTP_STATUS_IN_TEXT_RE.findall(blob)])
        if any(code in WAF_RISK_HTTP_STATUS_CODES for code in status_values):
            return True
        return any(marker in blob for marker in WAF_BODY_MARKERS)

    def _record_waf_signals_from_results(self, state: AgentState, results: List[Any], phase_name: str) -> bool:
        if self._normalized_safety_profile(state) == "aggressive":
            return False
        signals = [row for row in (results or []) if self._result_waf_signal(row)]
        if not signals:
            return False
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        risk = set(kb.get("risk_signals", []) or [])
        risk.add("waf_or_blocking_detected")
        kb["risk_signals"] = sorted(risk)
        kb["waf_signal_count"] = int(kb.get("waf_signal_count", 0) or 0) + len(signals)
        state.knowledge_base = kb
        threshold = 1 if self._normalized_safety_profile(state) == "safe" else 3
        if int(kb.get("waf_signal_count", 0) or 0) >= threshold:
            state.campaign_stop_reason = (
                f"{phase_name}: blocking/WAF signals detected; pausing campaign to avoid target overload"
            )
            delay_min, delay_max = self._action_delay_bounds(state)
            state.request_delay_min = max(delay_min, 5.0)
            state.request_delay_max = max(delay_max, 15.0)
            if getattr(state, "verbose", False):
                print_warning(state.campaign_stop_reason)
            return True
        return False

    def _execute_agent_modules(
        self,
        state: AgentState,
        scanner,
        modules: List[Dict[str, Any]],
        target_info: Dict[str, Any],
        threads: int,
        verbose: bool,
        phase_name: str = "phase",
    ) -> List[Dict[str, Any]]:
        allowed, skipped = self._filter_modules_for_safety_profile(state, modules)
        if not allowed:
            return skipped

        profile = self._normalized_safety_profile(state)
        effective_threads = 1 if profile == "safe" else max(1, int(threads or 1))
        results: List[Dict[str, Any]] = list(skipped)

        if profile == "safe":
            for module in allowed:
                self._sleep_between_agent_actions(state, f"{phase_name}:{module.get('path', '')}")
                batch_results = scanner._execute_modules([module], target_info, 1, verbose)
                results.extend(batch_results)
                self._adapt_rate_limit_from_results(state, batch_results)
                if self._record_waf_signals_from_results(state, batch_results, phase_name):
                    break
            return results

        self._sleep_between_agent_actions(state, phase_name)
        batch_results = scanner._execute_modules(allowed, target_info, effective_threads, verbose)
        results.extend(batch_results)
        self._adapt_rate_limit_from_results(state, batch_results)
        self._record_waf_signals_from_results(state, batch_results, phase_name)
        return results

    def _append_timeline_event(
        self,
        state: AgentState,
        phase: str,
        summary: str,
        *,
        kind: str = "phase",
        modules: Optional[List[Any]] = None,
        results: Optional[List[Dict[str, Any]]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        timeline = state.decision_timeline if isinstance(state.decision_timeline, list) else []
        module_paths: List[str] = []
        if isinstance(modules, list):
            for row in modules:
                if isinstance(row, dict):
                    path = str(row.get("path", "")).strip()
                else:
                    path = str(row or "").strip()
                if path:
                    module_paths.append(path)
        result_summary: Dict[str, Any] = {}
        if isinstance(results, list):
            vuln = [r for r in results if isinstance(r, dict) and r.get("vulnerable")]
            errors = [r for r in results if isinstance(r, dict) and r.get("status") == "error"]
            actionable = [r for r in results if isinstance(r, dict) and self._is_actionable_finding(r)]
            result_summary = {
                "total_results": len(results),
                "vulnerable": len(vuln),
                "actionable": len(actionable),
                "errors": len(errors),
                "top_paths": [
                    str(r.get("path", "")).strip()
                    for r in actionable[:4]
                    if isinstance(r, dict) and str(r.get("path", "")).strip()
                ],
            }
        event = {
            "ts": datetime.now().isoformat(),
            "kind": kind,
            "phase": phase,
            "summary": summary,
        }
        if module_paths:
            event["modules"] = module_paths
        if result_summary:
            event["result_summary"] = result_summary
        if extra:
            event["extra"] = extra
        timeline.append(event)
        state.decision_timeline = timeline

    def _print_timeline_preview(self, state: AgentState, tail: int = 6) -> None:
        rows = state.decision_timeline[-tail:] if isinstance(state.decision_timeline, list) else []
        if not rows:
            return
        print_status("Decision timeline")
        for row in rows:
            if not isinstance(row, dict):
                continue
            phase = str(row.get("phase", "?"))
            summary = self._shorten_text(row.get("summary", ""), 140)
            print_info(f"- {phase}: {summary}")

    def _is_network_error_result(self, result: Any) -> bool:
        if not isinstance(result, dict):
            return False
        blob = " ".join([
            str(result.get("message", "")),
            str(result.get("status", "")),
            str(result.get("error", "")),
            str(result.get("details", "")),
        ]).lower()
        return any(marker in blob for marker in self._network_error_markers())

    def _probe_target_reachability(self, state: AgentState) -> Tuple[bool, str]:
        target_info = state.target_info or {}
        host = str(target_info.get("hostname", "") or "").strip()
        scheme = str(target_info.get("scheme", "http") or "http").lower()
        port = int(target_info.get("port", 443 if scheme == "https" else 80) or (443 if scheme == "https" else 80))
        path = str(target_info.get("path", "") or "").strip() or "/"

        if not host:
            return False, "Missing target hostname."

        try:
            with socket.create_connection((host, port), timeout=2.5):
                pass
        except OSError as exc:
            return False, f"{host}:{port} unreachable: {exc}"

        if scheme not in ("http", "https"):
            return True, f"TCP port {port} reachable."

        url = f"{scheme}://{host}:{port}{path if path.startswith('/') else '/' + path}"
        row = self._http_probe_many(state, [url], timeout_s=4, read_bytes=2048)[0]
        if row.get("error"):
            return False, f"HTTP probe failed for {url}: {row.get('error')}"
        status = int(row.get("status") or 0)
        if self._result_waf_signal({
            "status_code": status,
            "body": row.get("body", ""),
            "details": row.get("headers", {}),
        }):
            self._record_waf_signals_from_results(state, [{
                "status_code": status,
                "body": row.get("body", ""),
                "details": row.get("headers", {}),
            }], "reachability-probe")
        return True, f"HTTP probe reached target and returned status {status}."

    def _result_has_exploit_link(self, result: dict) -> bool:
        if not isinstance(result, dict):
            return False
        if self._catalog.normalize_exploit_module_path(result.get("exploit_module")):
            return True
        return bool(self._catalog.normalize_linked_module_paths(result.get("linked_modules")))

    def _record_module_performance_phase(
        self,
        state: AgentState,
        kb_before_light: dict,
        phase_results: list,
        phase_name: str,
    ) -> None:
        if not phase_results:
            return
        kb_after = kb_light_copy(state.knowledge_base)
        self._module_perf.record_phase_results(
            kb_before_light,
            kb_after,
            phase_results,
            phase_name,
            str(state.target_info.get("hostname", "") or ""),
            self._is_actionable_finding,
            self._result_has_exploit_link,
        )
        self._module_ctx.record_phase_results(
            kb_before_light,
            kb_after,
            phase_results,
            phase_name,
            self._is_actionable_finding,
            self._result_has_exploit_link,
        )

    def _merge_module_produces_into_kb(self, knowledge_base: Any, module_path: str, details: Any) -> None:
        """Merge static ``agent.produces`` and optional runtime ``details['agent_produces']`` into KB."""
        from interfaces.command_system.builtin.agent.agent_module_meta import merge_produces_into_kb

        produces: List[str] = []
        agent = self._catalog.get_agent_metadata(module_path)
        if isinstance(agent, dict):
            produces.extend(agent.get("produces") or [])
        if isinstance(details, dict):
            extra = details.get("agent_produces") or details.get("produces")
            if isinstance(extra, (list, tuple)):
                produces.extend(str(x) for x in extra if str(x).strip())
            elif isinstance(extra, str) and extra.strip():
                produces.append(extra.strip())
        merge_produces_into_kb(knowledge_base, module_path, produces)

    def _bootstrap_knowledge_from_host_profile(self, state: AgentState) -> None:
        target_info = state.target_info or {}
        host = str(target_info.get("hostname", "")).lower().strip()
        if not host:
            return

        profiles = self._load_host_profiles()
        host_profile = profiles.get(host, {})
        if not isinstance(host_profile, dict):
            host_profile = {}
        state.host_profile = host_profile
        if not host_profile:
            return

        kb = state.knowledge_base
        kb["tech_hints"] = sorted(set(kb.get("tech_hints", [])) | set(host_profile.get("tech_hints", [])))
        kb["specializations"] = sorted(set(kb.get("specializations", [])) | set(host_profile.get("specializations", [])))
        kb["discovered_endpoints"] = sorted(
            set(kb.get("discovered_endpoints", [])) | set(host_profile.get("discovered_endpoints", []))
        )[:300]
        kb["discovered_params"] = sorted(
            set(kb.get("discovered_params", [])) | set(host_profile.get("discovered_params", []))
        )[:200]
        kb["login_paths"] = sorted(
            set(kb.get("login_paths", [])) | set(host_profile.get("login_paths", []))
        )[:40]
        merged_confidence = dict(kb.get("tech_confidence", {}))
        for tech, value in host_profile.get("tech_confidence", {}).items():
            try:
                merged_confidence[str(tech).lower()] = max(
                    float(merged_confidence.get(str(tech).lower(), 0.0)),
                    min(max(float(value), 0.0), 1.0),
                )
            except Exception:
                continue
        kb["tech_confidence"] = merged_confidence
        state.knowledge_base = kb

    def _load_host_profiles(self):
        profile_path = os.path.join(os.getcwd(), "reports", "agent", "host_profiles.json")
        return load_json_dict(profile_path)

    def _update_host_profile_cache(self, state: AgentState) -> None:
        target_info = state.target_info or {}
        host = str(target_info.get("hostname", "")).lower().strip()
        if not host:
            return

        profile_path = os.path.join(os.getcwd(), "reports", "agent", "host_profiles.json")
        os.makedirs(os.path.dirname(profile_path), exist_ok=True)
        profiles = self._load_host_profiles()
        kb = state.knowledge_base

        profiles[host] = {
            "updated_at": datetime.now().isoformat(),
            "tech_hints": kb.get("tech_hints", [])[:50],
            "specializations": kb.get("specializations", [])[:20],
            "tech_confidence": kb.get("tech_confidence", {}),
            "discovered_endpoints": kb.get("discovered_endpoints", [])[:200],
            "discovered_params": kb.get("discovered_params", [])[:120],
            "login_paths": kb.get("login_paths", [])[:40],
            "risk_signals": kb.get("risk_signals", [])[:30],
            "last_campaign_stop_reason": state.campaign_stop_reason,
        }
        try:
            atomic_write_json(profile_path, profiles)
        except Exception:
            pass

    def _update_tech_confidence(self, knowledge_base, tech_key: str, delta: float) -> None:
        if not isinstance(knowledge_base, dict) or not tech_key:
            return
        confidence = dict(knowledge_base.get("tech_confidence", {}))
        key = str(tech_key).lower()
        current = float(confidence.get(key, 0.0) or 0.0)
        confidence[key] = round(max(0.0, min(1.0, current + float(delta))), 3)
        knowledge_base["tech_confidence"] = confidence

    def _extract_adaptive_keywords(self, text: str):
        stop = {
            "http", "https", "status", "server", "content", "type", "length", "cache",
            "found", "detect", "detected", "version", "target", "error", "warning",
            "vulnerable", "safe", "false", "true", "admin", "login", "panel", "path",
            "page", "request", "response", "header", "headers", "apache", "nginx",
            "bypass", "close", "config", "crawl", "plugin", "plugins", "extract",
            "file", "files", "signal", "scanner", "scanners", "missing", "information",
            "leak", "leaks", "detector", "detecteds",
        }.union(CMS_LOCK_NAMES)
        words = WORD_RE.findall((text or "").lower())
        unique = []
        seen = set()
        for word in words:
            if word in stop or word.isdigit():
                continue
            if word in seen:
                continue
            seen.add(word)
            unique.append(word)
            if len(unique) >= 20:
                break
        return unique

    def _display_hint_noise_tokens(self) -> set:
        return {
            "api",  # keep confidence, but avoid noisy plain display unless confidence is high
            "bypass", "close", "config", "cors", "crawl", "extract", "file",
            "header", "headers", "information", "leak", "plugin", "plugins",
            "scanner", "signal", "target", "warning", "error",
        }

    def _detect_app_stack_markers(self, text: str) -> List[str]:
        low = str(text or "").lower()
        markers: List[str] = []
        if "dvwa" in low or "damn vulnerable web application" in low:
            markers.append("dvwa")
        if "phpmyadmin" in low:
            markers.append("phpmyadmin")
        return markers

    def _preferred_post_auth_exploit_paths(self, knowledge_base: Dict[str, Any]) -> List[str]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        allowed = set(kb.get("module_capability_catalog", {}).get("all_paths", []) or [])
        conf = kb.get("tech_confidence", {}) or {}
        preferred: List[str] = []

        try:
            dvwa_score = float(conf.get("dvwa", 0.0) or 0.0)
        except Exception:
            dvwa_score = 0.0
        if dvwa_score >= 0.7:
            for path in (
                "exploits/ctf/dvwa_rce",
                "exploits/ctf/dvwa_file_upload",
            ):
                if path in allowed:
                    preferred.append(path)
        return preferred

    def _post_auth_candidate_sort_key(self, path: str, knowledge_base: Dict[str, Any]) -> Tuple[int, int, str]:
        low = str(path or "").lower()
        preferred = self._preferred_post_auth_exploit_paths(knowledge_base)
        if path in preferred:
            return (0, preferred.index(path), low)
        if "dvwa" in low:
            return (1, 0, low)
        if low.startswith(("exploits/", "exploit/")):
            return (2, 0, low)
        return (3, 0, low)

    def _stack_confidence_rows(self, knowledge_base: Dict[str, Any], threshold: float = 0.35) -> List[Tuple[str, float]]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        conf = kb.get("tech_confidence", {}) or {}
        known = (
            "dvwa", "wordpress", "drupal", "joomla", "phpmyadmin", "grafana", "jenkins",
            "elasticsearch", "kibana", "tomcat", "nginx", "apache", "fastapi",
            "django", "flask", "nodejs", "react", "angular", "api",
        )
        rows: List[Tuple[str, float]] = []
        for name in known:
            try:
                value = float(conf.get(name, 0.0) or 0.0)
            except Exception:
                value = 0.0
            if value >= threshold:
                rows.append((name, value))
        rows.sort(key=lambda row: row[1], reverse=True)
        return rows

    def _display_tech_hints(self, knowledge_base: Dict[str, Any], limit: int = 6) -> List[str]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        hints = [str(x).lower() for x in kb.get("tech_hints", []) or []]
        conf_rows = self._stack_confidence_rows(kb, threshold=0.4)
        preferred = [name for name, _ in conf_rows]
        if preferred:
            return preferred[:limit]
        noise = self._display_hint_noise_tokens()
        filtered = [h for h in hints if h and h not in noise]
        return filtered[:limit]

    def _action_reason_for_path(self, path: str, state: AgentState, findings: Optional[List[Any]] = None) -> str:
        low = str(path or "").lower()
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        conf_rows = self._stack_confidence_rows(kb, threshold=0.4)
        top_stack = conf_rows[0][0] if conf_rows else ""
        top_stack_score = conf_rows[0][1] if conf_rows else 0.0
        findings = findings or []

        if "wp_plugin_scanner" in low:
            return (
                f"WordPress validation: stack confidence={top_stack_score:.2f}"
                if top_stack == "wordpress"
                else "WordPress validation based on observed WordPress-like evidence."
            )
        if "wordpress_enum_user" in low:
            return "WordPress follow-up: enumerate likely public users after WordPress evidence."
        if low.endswith("scanner/http/wordpress_detect"):
            return "Stack validation: confirm WordPress before broader follow-up."
        if "phpmyadmin_detect" in low:
            return "Validate phpMyAdmin exposure before treating it as actionable."
        if "dvwa_rce" in low:
            return "DVWA detected after authentication; command execution path is the highest-value exploit."
        if "dvwa_file_upload" in low:
            return "DVWA detected after authentication; file upload is a grounded shell path."
        if "login_page_detector" in low:
            return "Validate authentication surface before any credential strategy."
        if "admin_login_bruteforce" in low:
            return "Auth-first follow-up on a known login surface."
        if "sql_injection" in low:
            return "Parameter-rich surface detected; validate SQLi on observed inputs."
        if "xss_scanner" in low:
            return "Parameter-rich surface detected; validate reflected/stored XSS paths."
        if "lfi_fuzzer" in low:
            return "File/path-like parameters detected; validate LFI risk."
        if top_stack:
            return f"Best next validation step for probable stack `{top_stack}` ({top_stack_score:.2f})."
        if findings:
            return "Best low-noise validation step from current evidence."
        return "Best next low-noise validation step."

    def _match_keywords_to_catalog(self, knowledge_base, keywords):
        catalog_paths = []
        if isinstance(knowledge_base, dict):
            catalog_paths = [str(p).lower() for p in knowledge_base.get("module_capability_catalog", {}).get("all_paths", [])]
        if not catalog_paths:
            return []
        matched = []
        for kw in keywords:
            if any(kw in path for path in catalog_paths):
                matched.append(kw)
            if len(matched) >= 10:
                break
        return matched

    def _extract_post_auth_lexical_tokens(self, text):
        """
        Tokens from authenticated HTML for generic module-path matching (no hardcoded apps).
        """
        if not text:
            return []
        stripped = SCRIPT_RE.sub(" ", text)
        stripped = STYLE_RE.sub(" ", stripped)
        stripped = TAG_RE.sub(" ", stripped)
        low = stripped.lower()
        stop = {
            "html", "body", "head", "meta", "link", "script", "style", "div", "span", "table",
            "tr", "td", "th", "form", "input", "button", "select", "option", "label", "title",
            "href", "http", "https", "charset", "viewport", "width", "height", "class", "charset",
            "this", "that", "with", "from", "your", "have", "been", "will", "here", "there",
            "please", "click", "welcome", "logout", "login", "password", "username", "submit",
            "none", "true", "false", "text", "javascript", "window", "document",
        }
        words = POST_AUTH_WORD_RE.findall(low)
        acronyms = ACRONYM_RE.findall(low)
        out = []
        seen = set()
        for w in list(words) + [a for a in acronyms if len(a) >= 3]:
            if w in stop or w.isdigit():
                continue
            if w in seen:
                continue
            seen.add(w)
            out.append(w)
            if len(out) >= 40:
                break
        return out

    def _semantic_catalog_paths_from_text(self, knowledge_base, text: str, max_paths: int = 25) -> List[str]:
        if not text or not isinstance(knowledge_base, dict):
            return []
        semantic_index = (
            knowledge_base.get("module_capability_catalog", {}).get("semantic_index", []) or []
        )
        if not semantic_index:
            return []
        query_tokens = set(self._extract_post_auth_lexical_tokens(text))
        query_tokens.update(self._extract_adaptive_keywords(text))
        query_tokens = {tok for tok in query_tokens if len(str(tok)) >= 3}
        if not query_tokens:
            return []

        scored: List[Tuple[float, str]] = []
        for row in semantic_index:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", "") or "").strip()
            tokens = {str(tok).lower() for tok in (row.get("tokens") or []) if str(tok).strip()}
            if not path or not tokens:
                continue
            overlap = query_tokens.intersection(tokens)
            if not overlap:
                continue
            score = len(overlap) / max(1.0, (len(query_tokens) * len(tokens)) ** 0.5)
            if score > 0:
                scored.append((score, path))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [path for _, path in scored[:max_paths]]

    def _resolve_catalog_paths_from_text(self, knowledge_base, text, max_paths=25):
        if not text or not isinstance(knowledge_base, dict):
            return []
        paths = knowledge_base.get("module_capability_catalog", {}).get("all_paths", []) or []
        if not paths:
            return []
        tokens = sorted(set(self._extract_post_auth_lexical_tokens(text)), key=len, reverse=True)
        matched = []
        seen = set()
        for path in self._semantic_catalog_paths_from_text(knowledge_base, text, max_paths=max_paths):
            if path not in seen:
                matched.append(path)
                seen.add(path)
            if len(matched) >= max_paths:
                return matched
        for tok in tokens:
            if len(tok) < 4:
                continue
            for p in paths:
                if p in seen:
                    continue
                pl = str(p).lower().replace("-", "_")
                if tok in pl:
                    matched.append(p)
                    seen.add(p)
                    if len(matched) >= max_paths:
                        return matched
        return matched

    def _post_auth_vector_is_disallowed(self, path_lower):
        """
        Responsible triage: avoid auto-chaining noisy / abuse-prone surfaces (email, mass messaging).
        """
        return any(b in path_lower for b in DISALLOWED_POST_AUTH_TOKENS)

    def _has_authenticated_session(self, knowledge_base) -> bool:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        signals = {str(x).lower() for x in kb.get("risk_signals", [])}
        return "authenticated_session" in signals

    def _credential_milestone_reached(self, knowledge_base) -> bool:
        """True when valid credentials or an authenticated session was recorded in the KB."""
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        signals = {str(x).lower() for x in kb.get("risk_signals", [])}
        if "authenticated_session" in signals:
            return True
        return "credentials_obtained" in signals

    def _planner_action_keys(self, path: Any) -> set:
        text = str(path or "").strip().lower()
        if not text:
            return set()
        keys = {text}
        if "/" in text:
            keys.add(text.rstrip("/").split("/")[-1])
        return keys

    def _get_failed_action_keys(self, knowledge_base) -> set:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        failed = set()
        for item in kb.get("planner_failed_actions", []) or []:
            failed.update(self._planner_action_keys(item))
        return failed

    def _remember_planner_actions(self, knowledge_base, attempted_paths, failed_paths=None) -> None:
        kb = knowledge_base if isinstance(knowledge_base, dict) else None
        if kb is None:
            return

        attempted_tokens = set()
        for path in attempted_paths or []:
            attempted_tokens.update(self._planner_action_keys(path))
        failed_tokens = set()
        for path in failed_paths or []:
            failed_tokens.update(self._planner_action_keys(path))

        existing_attempted = set()
        for item in kb.get("planner_executed_actions", []) or []:
            existing_attempted.update(self._planner_action_keys(item))
        existing_failed = set()
        for item in kb.get("planner_failed_actions", []) or []:
            existing_failed.update(self._planner_action_keys(item))

        if attempted_tokens:
            kb["planner_executed_actions"] = sorted(existing_attempted.union(attempted_tokens))[:160]
        if failed_tokens:
            kb["planner_failed_actions"] = sorted(existing_failed.union(failed_tokens))[:160]

    def _filter_previously_failed_plan_actions(self, actions, knowledge_base):
        failed = self._get_failed_action_keys(knowledge_base)
        if not failed:
            return list(actions or [])
        filtered = []
        for row in actions or []:
            if not isinstance(row, dict):
                continue
            action_type = str(row.get("type", "")).strip().lower()
            path = str(row.get("path", "")).strip()
            if action_type in ("run_followup", "run_exploit") and self._planner_action_keys(path).intersection(failed):
                continue
            filtered.append(row)
        return filtered

    def _should_run_post_auth_methodical_wave(self, knowledge_base) -> bool:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        if kb.get("post_auth_methodical_wave_done"):
            return False
        signals = {str(x).lower() for x in kb.get("risk_signals", [])}
        if "authenticated_session" in signals:
            return True
        return (
            "credentials_obtained" in signals and "session_cookie_obtained" in signals
        )

    def _pivot_scan_campaign_after_credentials(
        self,
        state: AgentState,
        modules,
        scanner,
        all_results,
        executed_paths,
        phase_threads,
        tech_hints,
        verbose: bool,
        phase_label: str,
    ):
        state.campaign_stop_reason = (
            f"{phase_label}: credentials obtained — halting broad scan; pivot to post-auth / privilege escalation"
        )
        if self._should_run_post_auth_methodical_wave(state.knowledge_base):
            post_auth_budget = min(12, max(3, int(state.max_modules) - len(executed_paths)))
            self._run_post_auth_methodical_wave(
                state,
                modules,
                scanner,
                all_results,
                executed_paths,
                phase_threads,
                post_auth_budget,
            )
        if verbose:
            print_status(
                "Credential milestone: stopping generic recon/injection waves; "
                "focusing on authenticated follow-up and privilege paths."
            )
        for hint in state.knowledge_base.get("tech_hints", []) or []:
            tech_hints.add(str(hint).lower())
        state.scan_tech_hints = sorted(tech_hints)
        state.scan_modules_executed = len(executed_paths)
        return all_results

    def _has_tech_evidence(self, knowledge_base, tech_key: str, threshold: float = 0.6) -> bool:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        key = str(tech_key or "").lower().strip()
        if not key:
            return False
        confidence = kb.get("tech_confidence", {}) or {}
        try:
            if float(confidence.get(key, 0.0) or 0.0) >= threshold:
                return True
        except Exception:
            pass
        hints = {str(x).lower() for x in kb.get("tech_hints", [])}
        return key in hints

    def _get_probable_cms_specializations(self, knowledge_base):
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        hints = {str(x).lower() for x in kb.get("tech_hints", [])}
        confidence = kb.get("tech_confidence", {}) or {}
        endpoints_blob = " ".join([str(x).lower() for x in kb.get("discovered_endpoints", [])])
        trace_blob = " ".join([
            " ".join([
                str(row.get("path", "")),
                str(row.get("final_path", "")),
                str(row.get("location", "")),
            ]).lower()
            for row in (kb.get("fingerprint_trace", []) or [])
            if isinstance(row, dict)
        ])

        probable = set()
        wp_conf = float(confidence.get("wordpress", 0.0) or 0.0)
        drupal_conf = float(confidence.get("drupal", 0.0) or 0.0)
        joomla_conf = float(confidence.get("joomla", 0.0) or 0.0)

        if (
            wp_conf >= 0.5
            or (
                "wordpress" in hints
                and (
                    wp_conf >= 0.35
                    or any(token in f"{endpoints_blob} {trace_blob}" for token in WORDPRESS_LANDING_PATH_MARKERS)
                )
            )
        ):
            probable.add("wordpress")
        if "drupal" in hints and drupal_conf >= 0.25:
            probable.add("drupal")
        if "joomla" in hints and joomla_conf >= 0.25:
            probable.add("joomla")
        return probable

    def _wordpress_probe_signal(self, path: str, status: int, body: str, final_path: str = "", location: str = "") -> bool:
        low_body = str(body or "").lower()
        low_final = str(final_path or "").lower()
        low_location = str(location or "").lower()
        normalized = str(path or "").lower()

        if any(token in low_body for token in WORDPRESS_BODY_FINGERPRINT_TOKENS):
            return True
        if normalized == "/wp-json/" and (
            "wp-json" in low_body
            or "\"namespaces\"" in low_body
            or "rest_route" in low_body
        ):
            return True
        if normalized == "/xmlrpc.php" and (
            "xml-rpc server accepts post requests only" in low_body
            or "xmlrpc" in low_body
        ):
            return True
        if normalized == "/wp-login.php" and status in (200, 401, 403):
            if any(token in low_body for token in WORDPRESS_FORM_FIELD_TOKENS):
                return True
            if "/wp-login.php" in low_final or "/wp-login.php" in low_location:
                return True
        return False


    def _result_evidence_blob(self, result, include_path=False) -> str:
        if not isinstance(result, dict):
            return ""
        parts = []
        if include_path:
            parts.extend([
                str(result.get("path", "")),
                str(result.get("module", "")),
            ])
        parts.append(str(result.get("message", "")))
        details = result.get("details", {}) or {}
        if isinstance(details, dict):
            for key, value in details.items():
                if isinstance(value, (str, int, float, bool)):
                    parts.append(str(value))
        return " ".join([p for p in parts if p]).lower()

    def _result_has_explicit_evidence(self, result) -> bool:
        text = self._result_evidence_blob(result)
        if not text:
            return False
        return any(marker in text for marker in POSITIVE_EVIDENCE_MARKERS)

    def _normalize_relative_path(self, value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        try:
            parsed = urllib.parse.urlparse(raw)
            if parsed.scheme or parsed.netloc:
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                return path[:256]
        except Exception:
            pass
        if raw.startswith("/"):
            return raw.split("#", 1)[0][:256]
        return ""

    def _sanitize_cookie_map(self, raw: Any) -> Dict[str, str]:
        return self._auth_ops.sanitize_cookie_map(raw)

    def _extract_auth_context_from_details(self, module_path: str, details: Any) -> Optional[Dict[str, Any]]:
        return self._auth_ops.extract_auth_context_from_details(module_path, details)

    def _score_auth_context(self, context: Optional[Dict[str, Any]]) -> int:
        return self._auth_ops.score_auth_context(context)

    def _auth_context_signature(self, context: Optional[Dict[str, Any]]) -> str:
        return self._auth_ops.auth_context_signature(context)

    def _merge_auth_context(self, knowledge_base, candidate: Optional[Dict[str, Any]]) -> None:
        self._auth_ops.merge_auth_context(knowledge_base, candidate)

    def _get_active_auth_context(self, knowledge_base) -> Dict[str, Any]:
        return self._auth_ops.get_active_auth_context(knowledge_base)

    def _extract_preferred_session_cookie(self, auth_context: Optional[Dict[str, Any]]) -> str:
        return self._auth_ops.extract_preferred_session_cookie(auth_context)

    def _seed_http_session_from_auth(self, module_instance, state: AgentState, auth_context=None) -> None:
        self._auth_ops.seed_http_session_from_auth(module_instance, state, auth_context)

    def _infer_auth_option_overrides(self, module_instance, module_path: str, state: AgentState) -> Dict[str, Any]:
        return self._auth_ops.infer_auth_option_overrides(module_instance, module_path, state)

    def _login_surface_wants_bruteforce(self, knowledge_base, findings, auth_session) -> bool:
        """
        True when recon already saw login evidence but no authenticated session yet.
        Used so the execution plan queues admin_login_bruteforce even if linked_modules
        were missing on a finding (e.g. only simple_login_scanner fired).
        """
        if auth_session:
            return False
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        paths_set = {p for p in kb.get("login_paths", []) if isinstance(p, str) and p.startswith("/")}
        exhausted = set(kb.get("auth_bruteforce_exhausted_login_paths", []) or [])
        if paths_set and paths_set <= exhausted:
            return False
        signals = {str(x).lower() for x in kb.get("risk_signals", [])}
        if signals.intersection({
            "login_redirect_detected",
            "login_form_detected",
            "login_surface_detected",
        }):
            return True
        paths = [p for p in kb.get("login_paths", []) if isinstance(p, str) and p.startswith("/")]
        if paths:
            return True
        for row in findings or []:
            if not isinstance(row, dict) or not row.get("vulnerable"):
                continue
            msg = str(row.get("message", "") or "").lower()
            path = str(row.get("path", "") or "").lower()
            if any(t in msg for t in ("login page", "login panel", "login form")):
                return True
            if any(t in path for t in (
                "login_page_detector",
                "simple_login_scanner",
                "admin_panel_detect",
            )):
                return True
        return False

    def _should_prioritize_auth_surface(self, knowledge_base) -> bool:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        signals = {str(x).lower() for x in kb.get("risk_signals", [])}
        if "authenticated_session" in signals:
            return True
        login_signals = signals.intersection({
            "login_redirect_detected",
            "login_form_detected",
            "login_surface_detected",
        })
        login_paths = [p for p in kb.get("login_paths", []) if isinstance(p, str) and p.startswith("/")]
        endpoint_count = len(kb.get("discovered_endpoints", []))
        return bool(login_paths) and (bool(login_signals) or endpoint_count <= 2)

    def _has_shell_milestone(self, state: AgentState) -> bool:
        """True when results/KB indicate an interactive shell or equivalent session win."""
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
        if "interactive_shell" in signals or "shell_obtained" in signals:
            return True
        for r in (state.results or []) + (state.vulnerable_results or []):
            if not isinstance(r, dict):
                continue
            msg = str(r.get("message", "") or "").lower()
            det = str(r.get("details", "") or "").lower()
            blob = f"{msg} {det}"
            if any(
                x in blob
                for x in (
                    "interactive shell",
                    "meterpreter session",
                    "session opened",
                    "opening a shell",
                    "command shell",
                    "shell access",
                    "got a shell",
                    "obtained shell",
                    "reverse shell",
                )
            ):
                return True
        return False

    def _goal_should_prioritize_exploit(self, state: AgentState) -> bool:
        """True when authenticated and we have concrete exploit paths or linked exploit modules."""
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        for p in kb.get("post_auth_exploit_paths") or []:
            if isinstance(p, str) and (p.startswith("exploit/") or p.startswith("exploits/")):
                return True
        for r in state.vulnerable_results or state.results or []:
            if not isinstance(r, dict):
                continue
            if self._catalog.normalize_exploit_module_path(r.get("exploit_module")):
                return True
        return False

    def _sync_campaign_goal(self, state: AgentState) -> None:
        """
        Set ``state.campaign_goal`` from KB + results.

        Rule chain: shell → stop; authenticated → exploit or post_auth; login surface → obtain_auth; else recon.
        """
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        if self._has_shell_milestone(state):
            state.campaign_goal = CAMPAIGN_GOAL_SHELL_STOP
            return
        if self._credential_milestone_reached(kb):
            if self._goal_should_prioritize_exploit(state):
                state.campaign_goal = CAMPAIGN_GOAL_EXPLOIT
            else:
                state.campaign_goal = CAMPAIGN_GOAL_POST_AUTH
            return
        if self._auth_first_mode(state):
            state.campaign_goal = CAMPAIGN_GOAL_OBTAIN_AUTH
            return
        state.campaign_goal = CAMPAIGN_GOAL_RECON

    def _next_best_action_for_goal(self, state: AgentState, findings: List[Any]) -> Dict[str, Any]:
        """
        Strategic choice: one next action derived from ``campaign_goal``, not a vulnerability leaderboard.
        """
        self._sync_campaign_goal(state)
        goal = state.campaign_goal or CAMPAIGN_GOAL_RECON
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        findings = findings or []

        if goal == CAMPAIGN_GOAL_SHELL_STOP:
            return {
                "type": "skip",
                "path": "",
                "reason": "Shell or interactive session obtained; strategic stop.",
            }

        bf = "auxiliary/scanner/http/login/admin_login_bruteforce"
        lpd = "auxiliary/scanner/http/login_page_detector"

        if goal == CAMPAIGN_GOAL_OBTAIN_AUTH:
            if self._login_surface_wants_bruteforce(kb, findings, False) and not self._module_block_reason_for_profile(state, bf):
                return {
                    "type": "run_followup",
                    "path": bf,
                    "reason": "Goal obtain_auth: targeted credential attempt on known login surface.",
                }
            return {
                "type": "run_followup",
                "path": lpd,
                "reason": "Goal obtain_auth: locate or confirm login form.",
            }

        if goal == CAMPAIGN_GOAL_EXPLOIT:
            preferred_paths = self._preferred_post_auth_exploit_paths(kb)
            for path in preferred_paths:
                return {
                    "type": "run_exploit",
                    "path": path,
                    "reason": f"Goal exploit: preferred authenticated exploit for detected stack `{path.split('/')[-1]}`.",
                }
            for f in findings:
                if not isinstance(f, dict):
                    continue
                ex = self._catalog.normalize_exploit_module_path(f.get("exploit_module"))
                if ex:
                    return {
                        "type": "run_exploit",
                        "path": ex,
                        "reason": "Goal exploit: run linked exploit module.",
                    }
            for p in kb.get("post_auth_exploit_paths") or []:
                if isinstance(p, str) and (p.startswith("exploit/") or p.startswith("exploits/")):
                    return {
                        "type": "run_exploit",
                        "path": p,
                        "reason": "Goal exploit: catalog exploit path from authenticated context.",
                    }
            return {
                "type": "run_followup",
                "path": "auxiliary/scanner/http/crawler",
                "reason": "Goal exploit: widen surface to reach weaponizable vectors.",
            }

        if goal == CAMPAIGN_GOAL_POST_AUTH:
            rows = self._suggest_post_auth_methodical_actions(state, kb, max_actions=3)
            if rows:
                r0 = rows[0]
                return {
                    "type": str(r0.get("type", "run_followup")),
                    "path": str(r0.get("path", "") or ""),
                    "reason": "Goal post_auth: leverage authenticated session.",
                }
            return {
                "type": "run_followup",
                "path": "auxiliary/scanner/http/crawler",
                "reason": "Goal post_auth: authenticated enumeration.",
            }

        decision_classes = {
            self._finding_decision_class(f) for f in findings if isinstance(f, dict)
        }
        stack_conf = self._stack_confidence_rows(kb, threshold=0.45)
        if findings and decision_classes <= {"info"}:
            if stack_conf:
                top_stack = stack_conf[0][0]
                stack_map = {
                    "wordpress": "scanner/http/wordpress_detect",
                    "drupal": "scanner/http/drupal_detect",
                    "joomla": "scanner/http/joomla_detect",
                    "phpmyadmin": "scanner/http/phpmyadmin_detect",
                }
                chosen = stack_map.get(top_stack, "")
                if chosen:
                    return {
                        "type": "run_followup",
                        "path": chosen,
                        "reason": (
                            f"Validation-only state: confirm probable stack `{top_stack}` "
                            f"before any exploitation attempt."
                        ),
                    }
            return {
                "type": "run_followup",
                "path": "auxiliary/scanner/http/crawler",
                "reason": "Validation-only state: expand low-noise discovery until stronger evidence exists.",
            }

        for f in findings:
            if isinstance(f, dict) and f.get("path"):
                return {
                    "type": "prioritize",
                    "path": f.get("path"),
                    "reason": "Goal recon: follow strongest scanner signal first.",
                }
        return {"type": "prioritize", "path": "", "reason": "Goal recon: continue discovery."}

    def _log_strategic_next_action(self, state: AgentState) -> None:
        """Verbose: show goal-aligned next action (not a vuln ranking)."""
        if not state.verbose:
            return
        nba = (state.llm_plan or {}).get("next_best_action")
        if isinstance(nba, dict) and nba.get("type"):
            print_info(
                f"Strategic next action [{state.campaign_goal}]: "
                f"{nba.get('type')} {nba.get('path', '')} — {nba.get('reason', '')}"
            )

    def _infer_next_best_action_from_execution_plan(self, execution_plan: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """First concrete run_followup / run_exploit from sanitized plan (priority order)."""
        actions = execution_plan.get("next_actions") if isinstance(execution_plan, dict) else None
        if not isinstance(actions, list):
            return None

        def _pk(row: Dict[str, Any]) -> int:
            try:
                return int(row.get("priority", 999))
            except Exception:
                return 999

        for a in sorted([x for x in actions if isinstance(x, dict)], key=_pk):
            t = str(a.get("type", "")).lower()
            p = str(a.get("path", "")).strip()
            if t in ("run_followup", "run_exploit") and p:
                return {
                    "type": t,
                    "path": p,
                    "reason": "Planner next action (from execution plan).",
                }
        return None

    def _auth_first_mode(self, state: AgentState) -> bool:
        """
        True when login is evidenced + at least one ``/`` login path exists, no session yet,
        no CMS lock from scan specializations, and bruteforce is not exhausted for all paths.
        """
        if self._module_block_reason_for_profile(state, "auxiliary/scanner/http/login/admin_login_bruteforce"):
            return False
        kb = state.knowledge_base
        if self._has_authenticated_session(kb):
            return False
        paths = {p for p in kb.get("login_paths", []) if isinstance(p, str) and p.startswith("/")}
        cms_lock = self._get_cms_lock_specializations(kb, state.scan_specializations)
        # CMS lock alone must not suppress auth-first when we already have explicit login paths
        # (e.g. SPA + weak WordPress hints from plugins).
        if cms_lock and not paths:
            return False
        findings = state.vulnerable_results or state.results or []
        if not self._login_surface_wants_bruteforce(kb, findings, False):
            return False
        if not paths:
            return False
        exhausted = set(kb.get("auth_bruteforce_exhausted_login_paths", []) or [])
        if paths <= exhausted:
            return False
        return True

    def _path_is_auth_first_low_priority(self, path: str) -> bool:
        low = (path or "").lower()
        if "admin_login_bruteforce" in low or "login_page_detector" in low:
            return False
        return any(sub in low for sub in AUTH_FIRST_DEPRIORITIZE_SUBSTRINGS)

    def _apply_auth_first_execution_overrides(
        self,
        state: AgentState,
        plan: Dict[str, Any],
        findings: List[Any],
    ) -> Dict[str, Any]:
        """
        When AUTH-FIRST is active: strip noisy follow-ups, force bruteforce to the front, renumber priorities.
        """
        self._sync_campaign_goal(state)
        out = dict(plan or {})
        out["campaign_goal"] = state.campaign_goal
        if self._module_block_reason_for_profile(state, "auxiliary/scanner/http/login/admin_login_bruteforce"):
            out["auth_first_mode"] = False
            out["next_actions"] = [
                a for a in (out.get("next_actions") or [])
                if not (
                    isinstance(a, dict)
                    and "admin_login_bruteforce" in str(a.get("path", "")).lower()
                )
            ]
            return out
        if not self._auth_first_mode(state):
            out["auth_first_mode"] = False
            return out

        out["auth_first_mode"] = True
        bf_path = "auxiliary/scanner/http/login/admin_login_bruteforce"
        raw_actions = [a for a in (out.get("next_actions") or []) if isinstance(a, dict)]

        filtered: List[Dict[str, Any]] = []
        for a in raw_actions:
            if a.get("type") == "run_followup" and self._path_is_auth_first_low_priority(str(a.get("path", ""))):
                continue
            filtered.append(a)

        seen_run: set = set()
        deduped: List[Dict[str, Any]] = []
        for a in filtered:
            if a.get("type") == "run_followup":
                key = ("run_followup", str(a.get("path", "")))
                if key in seen_run:
                    continue
                seen_run.add(key)
            deduped.append(a)

        kb = state.knowledge_base
        auth_session = self._has_authenticated_session(kb)
        wants_bf = self._login_surface_wants_bruteforce(kb, findings, auth_session)
        has_bf = any(
            a.get("type") == "run_followup" and a.get("path") == bf_path
            for a in deduped
        )
        if wants_bf and not has_bf:
            deduped.insert(0, {"type": "run_followup", "path": bf_path, "priority": 0, "options": {}})
        elif wants_bf:
            bf_rows = [a for a in deduped if a.get("type") == "run_followup" and a.get("path") == bf_path]
            rest = [a for a in deduped if a not in bf_rows]
            deduped = bf_rows + rest

        for i, a in enumerate(deduped, start=1):
            a["priority"] = i

        out["next_actions"] = deduped
        try:
            mr = int(out.get("max_requests_next_phase") or 8)
        except Exception:
            mr = 8
        out["max_requests_next_phase"] = max(mr, 8)
        return out

    def _suggest_post_auth_methodical_actions(self, state: AgentState, knowledge_base, max_actions=8):
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        if not self._has_authenticated_session(kb):
            return []
        catalog_hits = list(dict.fromkeys(
            self._preferred_post_auth_exploit_paths(kb)
            + list(kb.get("post_auth_exploit_paths", []) or [])
            + list(kb.get("post_auth_catalog_paths", []) or [])
        ))
        allowed = set(kb.get("module_capability_catalog", {}).get("all_paths", []) or [])
        catalog_hits = [
            path for path in sorted(
                [str(p).strip() for p in catalog_hits if str(p).strip()],
                key=lambda row: self._post_auth_candidate_sort_key(row, kb),
            )
            if path in allowed
        ]
        catalog_hits = [
            path for path in catalog_hits
            if path.startswith(("scanner/", "auxiliary/scanner/", "exploit/", "exploits/"))
        ]
        preferred_paths = set(self._preferred_post_auth_exploit_paths(kb))
        actions = []
        priority = 50
        for raw_path in catalog_hits:
            path = str(raw_path).strip()
            if not path or path not in allowed:
                continue
            low = path.lower()
            if preferred_paths and low.startswith(("exploit/", "exploits/")) and path not in preferred_paths:
                continue
            if self._post_auth_vector_is_disallowed(low):
                continue
            action_type = "run_exploit" if low.startswith("exploits/") or low.startswith("exploit/") else "run_followup"
            actions.append({"type": action_type, "path": path, "priority": priority, "options": {}})
            priority += 1
            if len(actions) >= max_actions:
                return actions

        if len(actions) < 2:
            if "auxiliary/scanner/http/crawler" in allowed:
                actions.append({
                    "type": "run_followup",
                    "path": "auxiliary/scanner/http/crawler",
                    "priority": priority,
                    "options": {},
                })
                priority += 1

        for inj in (
            "auxiliary/scanner/http/xss_scanner",
            "auxiliary/scanner/http/sql_injection",
            "auxiliary/scanner/http/lfi_fuzzer",
        ):
            if inj in allowed and len(actions) < max_actions:
                low = inj.lower()
                if self._post_auth_vector_is_disallowed(low):
                    continue
                actions.append({"type": "run_followup", "path": inj, "priority": priority, "options": {}})
                priority += 1
        return actions[:max_actions]

    def _run_post_auth_methodical_wave(self, state, modules, scanner, all_results, executed_paths, phase_threads, budget):
        kb = state.knowledge_base
        if not self._should_run_post_auth_methodical_wave(kb):
            return
        signals = [str(s).lower() for s in kb.get("risk_signals", [])]

        by_path = {m.get("path"): m for m in modules if m.get("path")}
        selected = []
        for path in kb.get("post_auth_catalog_paths", []) or []:
            if not path or path in executed_paths:
                continue
            mod = by_path.get(path)
            if not mod:
                continue
            low = str(path).lower()
            if not (low.startswith("scanner/") or low.startswith("auxiliary/scanner/")):
                continue
            if self._post_auth_vector_is_disallowed(low):
                continue
            selected.append(mod)
            if len(selected) >= max(3, budget // 2):
                break

        preferred_post_auth = self._preferred_post_auth_exploit_paths(kb)
        for path in preferred_post_auth:
            if path in executed_paths:
                continue
            mod = by_path.get(path)
            if not mod:
                continue
            if mod not in selected:
                selected.insert(0, mod)

        if not selected and "auxiliary/scanner/http/crawler" not in executed_paths:
            crawler = by_path.get("auxiliary/scanner/http/crawler")
            if crawler:
                selected.append(crawler)

        inject_pool = []
        cms_lock = self._get_cms_lock_specializations(kb)
        allow_inject = ("authenticated_session" in signals) or not cms_lock
        for p in (
            "auxiliary/scanner/http/xss_scanner",
            "auxiliary/scanner/http/sql_injection",
            "auxiliary/scanner/http/lfi_fuzzer",
        ):
            if p in executed_paths or not allow_inject:
                continue
            m = by_path.get(p)
            if m and not self._post_auth_vector_is_disallowed(p.lower()):
                inject_pool.append(m)

        remaining_budget = max(0, budget - len(selected))
        for m in inject_pool:
            if remaining_budget <= 0:
                break
            if len(kb.get("discovered_params", [])) < 1 and len(kb.get("discovered_endpoints", [])) < 2:
                break
            selected.append(m)
            remaining_budget -= 1

        if not selected:
            kb["post_auth_methodical_wave_done"] = True
            state.knowledge_base = kb
            return

        if state.verbose:
            print_status(f"Post-auth methodical wave: {len(selected)} module(s)")

        wave_results = self._execute_plan_modules_with_options(
            selected,
            state,
            option_overrides=self._build_inferred_option_overrides(selected, state),
            verbose=bool(state.verbose),
        )
        all_results.extend(wave_results)
        for m in selected:
            p = m.get("path")
            if p:
                executed_paths.add(p)
        wave_hints = self._extract_tech_hints(wave_results)
        self._update_knowledge_base_from_results(
            kb,
            wave_results,
            [m.get("path") for m in selected if m.get("path")],
            wave_hints,
            set(),
        )
        kb["post_auth_methodical_wave_done"] = True
        state.knowledge_base = kb

    def _run_ultra_fingerprint_pass(self, state: AgentState) -> None:
        target_info = state.target_info or {}
        kb = state.knowledge_base
        if not target_info or not isinstance(kb, dict):
            return

        scheme = str(target_info.get("scheme", "http")).lower()
        host = str(target_info.get("hostname", "")).strip()
        port = int(target_info.get("port", 80))
        if not host:
            return
        base_url = f"{scheme}://{host}:{port}"

        probe_paths = [
            "/",
            "/robots.txt",
            "/sitemap.xml",
            "/login.php",
            "/wp-login.php",
            "/xmlrpc.php",
            "/readme.html",
            "/wp-json/",
            "/?rest_route=/",
        ]
        probe_results = []
        tech_hints = set([str(x).lower() for x in kb.get("tech_hints", [])])
        endpoints = set(kb.get("discovered_endpoints", []))
        params = set(kb.get("discovered_params", []))
        login_paths = set(kb.get("login_paths", []))
        risk_signals = set(kb.get("risk_signals", []))
        fingerprint_blobs = []

        urls = [f"{base_url}{path}" for path in probe_paths[:10]]
        probe_rows = self._http_probe_many(state, urls, timeout_s=4, read_bytes=8192)
        for path, row in zip(probe_paths[:10], probe_rows):
            if row.get("error"):
                continue
            status = int(row.get("status") or 0)
            headers = row.get("headers", {}) if isinstance(row.get("headers"), dict) else {}
            body = str(row.get("body", "") or "")
            try:
                final_url_path = urllib.parse.urlparse(str(row.get("final_url", "") or "")).path or ""
            except Exception:
                final_url_path = ""

            if self._result_waf_signal({"status_code": status, "body": body, "details": headers}):
                risk_signals.add("waf_or_blocking_detected")

            blob = f"{path} {headers} {body}".lower()
            fingerprint_blobs.append(blob)
            probe_results.append({
                "path": path,
                "status": status,
                "location": str(headers.get("location", ""))[:200],
                "final_path": final_url_path[:200],
            })
            for endpoint in self._extract_endpoint_candidates(blob):
                endpoints.add(endpoint)
            for param in self._extract_param_candidates(blob):
                params.add(param)

            if any(m in blob for m in WORDPRESS_BODY_FINGERPRINT_TOKENS):
                tech_hints.add("wordpress")
                self._update_tech_confidence(kb, "wordpress", 0.22)
            if self._wordpress_probe_signal(
                path,
                status,
                body,
                final_url_path,
                headers.get("location", ""),
            ):
                tech_hints.add("wordpress")
                self._update_tech_confidence(kb, "wordpress", 0.18)
            if any(m in blob for m in DRUPAL_BLOB_MARKERS):
                tech_hints.add("drupal")
                self._update_tech_confidence(kb, "drupal", 0.25)
            if any(m in blob for m in JOOMLA_BLOB_MARKERS):
                tech_hints.add("joomla")
                self._update_tech_confidence(kb, "joomla", 0.25)
            if "generator" in blob and "wordpress" in blob:
                self._update_tech_confidence(kb, "wordpress", 0.2)

            # Generic auth-surface inference from redirect/login markers.
            location = str(headers.get("location", "")).lower()
            if status in HTTP_REDIRECT_STATUSES and any(token in location for token in AUTH_PATH_MARKERS):
                risk_signals.add("login_redirect_detected")
                normalized_location = location.split("?", 1)[0] if location.startswith("/") else "/login"
                endpoints.add(normalized_location)
                login_paths.add(normalized_location)
                tech_hints.add("auth_portal")
            final_path_low = str(final_url_path or "").lower()
            normalized_test_path = str(path).split("?", 1)[0].lower()
            # urlopen follows redirects by default: detect login redirects from final URL too.
            if final_path_low and final_path_low != normalized_test_path and any(
                token in final_path_low for token in AUTH_PATH_MARKERS
            ):
                risk_signals.add("login_redirect_detected")
                risk_signals.add("login_surface_detected")
                endpoints.add(final_path_low)
                login_paths.add(final_path_low)
                tech_hints.add("auth_portal")
            if ("type=\"password\"" in blob or "type='password'" in blob) and any(
                token in blob for token in ("username", "name=\"user", "name='user", "email")
            ):
                risk_signals.add("login_form_detected")
                tech_hints.add("auth_portal")
                if any(token in path for token in AUTH_PATH_MARKERS):
                    login_paths.add(path)
            if any(token in path for token in AUTH_PATH_MARKERS) and status in (200, 301, 302, 401, 403):
                risk_signals.add("login_surface_detected")
                login_paths.add(path)

            if status in HTTP_STATUS_RISK_SIGNALS:
                risk_signals.add(f"http_status_{status}")

        if probe_results:
            kb["fingerprint_trace"] = probe_results
            self._record_waf_signals_from_results(
                state,
                [
                    {
                        "status_code": row.get("status"),
                        "body": row.get("body", ""),
                        "details": row.get("headers", {}),
                    }
                    for row in probe_rows
                    if isinstance(row, dict)
                ],
                "ultra-fingerprint",
            )
        dynamic_keywords = self._extract_adaptive_keywords(" ".join(fingerprint_blobs))
        for keyword in self._match_keywords_to_catalog(kb, dynamic_keywords):
            tech_hints.add(keyword)
        kb["tech_hints"] = sorted(tech_hints)
        kb["discovered_endpoints"] = sorted(endpoints)[:300]
        kb["discovered_params"] = sorted(params)[:200]
        kb["login_paths"] = sorted(login_paths)[:40]
        kb["risk_signals"] = sorted(risk_signals)
        state.knowledge_base = kb

    def _run_agent_flow(self, state: AgentState) -> AgentState:
        if HAS_LANGGRAPH:
            return self._run_with_langgraph(state)
        print_warning("LangGraph not installed, using built-in linear workflow.")
        return self._run_linear_fallback(state)

    def _run_with_langgraph(self, state: AgentState) -> AgentState:
        graph = StateGraph(dict)

        def _wrap(fn):
            def _inner(raw: Dict[str, Any]) -> Dict[str, Any]:
                st = agent_state_from_dict(raw)
                out = fn(st)
                return agent_state_to_dict(out)

            return _inner

        graph.add_node("scan", _wrap(self._node_scan))
        graph.add_node("analyze", _wrap(self._node_analyze))
        graph.add_node("reason", _wrap(self._node_reason))
        graph.add_node("exploit", _wrap(self._node_exploit))
        graph.add_node("report", _wrap(self._node_report))
        graph.set_entry_point("scan")
        graph.add_edge("scan", "analyze")
        graph.add_edge("analyze", "reason")
        graph.add_edge("reason", "exploit")
        graph.add_edge("exploit", "report")
        graph.add_edge("report", END)

        app = graph.compile()
        return agent_state_from_dict(app.invoke(agent_state_to_dict(state)))

    def _run_linear_fallback(self, state: AgentState) -> AgentState:
        state = self._node_scan(state)
        if state.error:
            return state
        state = self._node_analyze(state)
        if state.error:
            return state
        state = self._node_reason(state)
        if state.error:
            return state
        state = self._node_exploit(state)
        if state.error:
            return state
        return self._node_report(state)

    def _node_scan(self, state: AgentState) -> AgentState:
        state.metrics.deterministic_steps += 1
        print_status("Scanning target...")
        reachable, reason = self._probe_target_reachability(state)
        state.target_reachable = reachable
        state.reachability_reason = reason
        self._append_timeline_event(
            state,
            "scan",
            f"Reachability probe: {'reachable' if reachable else 'unreachable'} - {reason}",
            kind="probe",
        )
        if not reachable:
            if getattr(state, "expanded_surface", False):
                print_warning(
                    f"Primary target unreachable ({reason}); continuing expanded-surface campaign "
                    "(OSINT / cloud / passive modules may still run)."
                )
            else:
                state.results = []
                state.vulnerable_results = []
                state.contextual_findings = []
                state.sql_findings = []
                state.potential_findings = []
                state.execution_plan = {
                    "next_actions": [],
                    "max_requests_next_phase": 0,
                    "stop_conditions": ["target_unreachable"],
                    "reasoning_confidence": 1.0,
                    "skip_exploitation": True,
                }
                state.llm_plan = {
                    "selected_paths": [],
                    "rationale": f"Target unreachable: {reason}",
                    "next_best_action": None,
                }
                state.campaign_stop_reason = "target_unreachable"
                print_warning(f"Target unreachable, stopping early: {reason}")
                return state
        self._append_timeline_event(
            state,
            "scan",
            "Starting ultra-fingerprint and multi-phase scan campaign.",
            extra={"max_modules": state.max_modules, "threads": state.threads},
        )
        if getattr(state, "expanded_surface", False):
            print_info(
                "Expanded surface (--all): including OSINT / cloud / passive aux modules with web scanners."
            )
        self._run_ultra_fingerprint_pass(state)
        if state.campaign_stop_reason:
            print_warning(f"Campaign paused: {state.campaign_stop_reason}")
            state.execution_plan = {
                "next_actions": [],
                "max_requests_next_phase": 0,
                "stop_conditions": ["waf_or_blocking_detected"],
                "reasoning_confidence": 1.0,
                "skip_exploitation": True,
            }
            return state
        scanner = state.scanner
        all_modules = self._catalog.discover_campaign_modules(
            expanded=bool(getattr(state, "expanded_surface", False)),
        )
        modules = self._select_modules_for_target(state, all_modules)
        if not modules:
            state.error = "No scanner modules available for this target/filter."
            return state

        results = self._run_scan_campaign(state, modules, scanner)
        if not results:
            state.error = "No relevant modules selected after intelligent scan campaign."
            return state

        if getattr(state, "expanded_surface", False):
            results = self._run_derived_host_surface_scans(state, scanner, all_modules, results)

        state.results = results
        state.vulnerable_results = [
            r for r in results
            if self._is_actionable_finding(r)
        ]
        self._append_timeline_event(
            state,
            "scan",
            f"Scan completed with {len(results)} result(s) and {len(state.vulnerable_results)} actionable finding(s).",
            results=results,
        )
        return state

    def _run_scan_campaign(self, state: AgentState, modules, scanner):
        """
        Multi-phase scan campaign with opportunistic ordering within each batch:

        - After each mini-batch, the KB is updated; the next batch is chosen by **utility**
          (expected information gain / estimated network cost), not only static phase lists.
        - Phases remain (cms-probe → recon/crawl → injection → adaptive → follow-up → targeted)
          for safety and budget accounting; **module order inside a phase** is utility-ranked.
        - ``information_score_kb`` (telemetry) summarizes discovery growth; see
          :mod:`interfaces.command_system.builtin.agent.campaign_utility`.

        Phases:
        0) cms-probe (wordpress/drupal/joomla detectors first)
        1) recon/fingerprint
        2) crawl/discovery (skipped when CMS lock is active — no generic crawler needed)
        3) injection-focused checks
        4) adaptive specialized modules
        5) follow-up chains
        6) targeted ranking (hint-weighted baseline, unchanged list composition)
        """
        verbose = bool(state.verbose)
        max_modules = int(state.max_modules)
        threads = int(state.threads)
        self._sync_campaign_goal(state)
        if isinstance(state.knowledge_base, dict):
            state.knowledge_base["planner_campaign_goal"] = state.campaign_goal or ""
        # Avoid mixed/interleaved module output in verbose mode: run campaign
        # phases sequentially so logs remain attributable to the right module.
        phase_threads = 1 if verbose else max(2, min(threads, 8))
        forced_protocol = state.protocol

        # For non-web explicit protocol scans, keep bounded one-pass behavior.
        if forced_protocol and forced_protocol not in ("http", "https"):
            selected = modules[:max_modules]
            if verbose:
                print_info(f"Scan campaign: bounded single-pass ({len(selected)} modules).")
            single_pass_results = self._execute_agent_modules(
                state,
                scanner,
                selected,
                state.target_info,
                threads,
                verbose,
                "single-pass",
            )
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                single_pass_results,
                [m.get("path") for m in selected if m.get("path")],
                set(),
                set(),
            )
            return single_pass_results

        executed_paths = set()
        all_results = []
        kb = state.knowledge_base
        tech_hints = {str(x).lower() for x in kb.get("tech_hints", [])}
        no_novelty_streak = 0
        probable_cms_lock = self._get_probable_cms_specializations(kb)

        # Fast CMS fingerprint pass: run lightweight CMS detectors before recon/crawl so
        # we can skip generic crawling when the stack is already known (WordPress/Drupal/Joomla).
        kb_pre_cms_probe = kb_light_copy(state.knowledge_base)
        cms_probe_modules = self._select_modules_opportunistic(
            self._pick_cms_detector_modules(modules),
            state,
            tech_hints,
            executed_paths,
            min(3, max_modules),
        )
        if cms_probe_modules:
            self._append_timeline_event(
                state,
                "cms-probe",
                f"Selected {len(cms_probe_modules)} CMS detector module(s).",
                modules=cms_probe_modules,
            )
            self._log_opportunistic_pick("cms-probe", cms_probe_modules, state, tech_hints, set(executed_paths))
            if verbose:
                print_status(f"Phase cms-probe: executing {len(cms_probe_modules)} module(s)")
            cms_probe_results = self._execute_agent_modules(
                state,
                scanner,
                cms_probe_modules,
                state.target_info,
                1 if verbose else max(2, min(threads, 6)),
                False,
                "cms-probe",
            )
            all_results.extend(cms_probe_results)
            selected_paths = [m.get("path") for m in cms_probe_modules if m.get("path")]
            for module in cms_probe_modules:
                path = module.get("path")
                if path:
                    executed_paths.add(path)
            cms_probe_hints = self._extract_tech_hints(cms_probe_results)
            tech_hints.update(cms_probe_hints)
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                cms_probe_results,
                selected_paths,
                cms_probe_hints,
                set(),
            )
            self._record_module_performance_phase(state, kb_pre_cms_probe, cms_probe_results, "cms-probe")
            self._append_timeline_event(
                state,
                "cms-probe",
                "CMS probe phase completed.",
                modules=cms_probe_modules,
                results=cms_probe_results,
                extra={"tech_hints": sorted(tech_hints)[:8]},
            )
            if state.campaign_stop_reason:
                state.scan_tech_hints = sorted(tech_hints)
                state.scan_modules_executed = len(executed_paths)
                return all_results
            if self._credential_milestone_reached(state.knowledge_base):
                return self._pivot_scan_campaign_after_credentials(
                    state,
                    modules,
                    scanner,
                    all_results,
                    executed_paths,
                    phase_threads,
                    tech_hints,
                    verbose,
                    "cms-probe",
                )

        # Budget split (adaptive): computed *after* cms-probe so tech_confidence / hints apply.
        budget_plan = self._compute_adaptive_budgets(state)
        recon_budget = min(max(4, int(state.recon_modules)), max_modules, budget_plan["recon"])
        crawl_budget = budget_plan["crawl"]
        inject_budget = budget_plan["inject"]
        specialized_budget = budget_plan["specialized"]
        followup_budget = budget_plan["followup"]

        auth_focus = self._should_prioritize_auth_surface(state.knowledge_base)
        if auth_focus:
            crawl_budget = 0
            inject_budget = min(inject_budget, 3)
            if verbose:
                print_status(
                    "Auth surface detected early: skipping generic crawler and keeping follow-up tight."
                )

        if probable_cms_lock:
            crawl_budget = 0
            if verbose:
                print_status(
                    "CMS hinted during ultra-fingerprint: skipping generic crawler until CMS-specific checks finish."
                )

        spec_after_probe = self._detect_specializations(
            tech_hints, all_results, state.knowledge_base
        )
        cms_lock_after_probe = self._get_cms_lock_specializations(
            state.knowledge_base, spec_after_probe
        )
        effective_cms_lock = cms_lock_after_probe.union(probable_cms_lock)
        if effective_cms_lock:
            crawl_budget = 0
            if verbose:
                print_status(
                    "Crawl phase skipped: CMS identified (structure known; crawler not needed)."
                )

        phase_specs = [
            ("recon", self._pick_recon_modules(modules, state), recon_budget),
            ("crawl", self._pick_crawler_modules(modules), crawl_budget),
        ]

        for phase_name, phase_modules, budget in phase_specs:
            remaining = max_modules - len(executed_paths)
            if remaining <= 0:
                break
            phase_modules = self._prune_modules_for_primary_cms(
                phase_modules,
                state.knowledge_base,
            )
            kb_pre_phase = kb_light_copy(state.knowledge_base)
            selected = self._select_modules_opportunistic(
                phase_modules,
                state,
                tech_hints,
                executed_paths,
                min(budget, remaining),
            )
            if not selected:
                continue
            self._append_timeline_event(
                state,
                phase_name,
                f"Selected {len(selected)} module(s) for {phase_name} phase.",
                modules=selected,
                extra={"budget": min(budget, remaining)},
            )
            self._log_opportunistic_pick(phase_name, selected, state, tech_hints, set(executed_paths))
            snapshot_before = self._snapshot_campaign_state(state, all_results)
            if verbose:
                print_status(f"Phase {phase_name}: executing {len(selected)} module(s)")
            phase_results = self._execute_agent_modules(
                state,
                scanner,
                selected,
                state.target_info,
                phase_threads,
                False,
                phase_name,
            )
            all_results.extend(phase_results)
            selected_paths = [m.get("path") for m in selected if m.get("path")]
            for module in selected:
                path = module.get("path")
                if path:
                    executed_paths.add(path)
            phase_hints = self._extract_tech_hints(phase_results)
            tech_hints.update(phase_hints)
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                phase_results,
                selected_paths,
                phase_hints,
                set(),
            )
            self._record_module_performance_phase(state, kb_pre_phase, phase_results, phase_name)
            self._append_timeline_event(
                state,
                phase_name,
                f"{phase_name.capitalize()} phase completed.",
                modules=selected,
                results=phase_results,
            )
            if state.campaign_stop_reason:
                state.scan_tech_hints = sorted(tech_hints)
                state.scan_modules_executed = len(executed_paths)
                return all_results
            if self._credential_milestone_reached(state.knowledge_base):
                return self._pivot_scan_campaign_after_credentials(
                    state,
                    modules,
                    scanner,
                    all_results,
                    executed_paths,
                    phase_threads,
                    tech_hints,
                    verbose,
                    phase_name,
                )
            stop_now, no_novelty_streak, stop_reason = self._evaluate_campaign_stop(
                phase_name,
                phase_results,
                snapshot_before,
                self._snapshot_campaign_state(state, all_results),
                no_novelty_streak,
            )
            if stop_now:
                state.campaign_stop_reason = stop_reason
                if verbose:
                    print_warning(f"Aggressive stop: {stop_reason}")
                break

        if state.campaign_stop_reason:
            state.scan_tech_hints = sorted(tech_hints)
            state.scan_modules_executed = len(executed_paths)
            return all_results

        # Injection phase is conditional to minimize noise and requests.
        specializations_pre = self._detect_specializations(tech_hints, all_results, state.knowledge_base)
        cms_lock_pre = self._get_cms_lock_specializations(state.knowledge_base, specializations_pre)
        cms_detected = bool(cms_lock_pre)
        if cms_detected:
            if verbose:
                print_status(
                    "Phase injection: skipped (CMS detected; preferring specialized follow-up modules)."
                )
        else:
            remaining = max_modules - len(executed_paths)
            if remaining > 0:
                inject_candidates = self._pick_injection_modules(modules, state.knowledge_base)
                kb_pre_inject = kb_light_copy(state.knowledge_base)
                inject_selected = self._select_modules_opportunistic(
                    inject_candidates,
                    state,
                    tech_hints,
                    executed_paths,
                    min(inject_budget, remaining),
                )
                if inject_selected:
                    self._append_timeline_event(
                        state,
                        "injection",
                        f"Selected {len(inject_selected)} targeted injection module(s).",
                        modules=inject_selected,
                        extra={"budget": min(inject_budget, remaining)},
                    )
                    self._log_opportunistic_pick("injection", inject_selected, state, tech_hints, set(executed_paths))
                    snapshot_before = self._snapshot_campaign_state(state, all_results)
                    if verbose:
                        print_status(f"Phase injection: executing {len(inject_selected)} module(s)")
                    inject_results = self._execute_modules_targeted(
                        scanner,
                        inject_selected,
                        state,
                        verbose=verbose,
                    )
                    all_results.extend(inject_results)
                    selected_paths = [m.get("path") for m in inject_selected if m.get("path")]
                    for module in inject_selected:
                        path = module.get("path")
                        if path:
                            executed_paths.add(path)
                    inject_hints = self._extract_tech_hints(inject_results)
                    tech_hints.update(inject_hints)
                    self._update_knowledge_base_from_results(
                        state.knowledge_base,
                        inject_results,
                        selected_paths,
                        inject_hints,
                        set(),
                    )
                    self._record_module_performance_phase(state, kb_pre_inject, inject_results, "injection")
                    self._append_timeline_event(
                        state,
                        "injection",
                        "Injection phase completed.",
                        modules=inject_selected,
                        results=inject_results,
                    )
                    if self._credential_milestone_reached(state.knowledge_base):
                        return self._pivot_scan_campaign_after_credentials(
                            state,
                            modules,
                            scanner,
                            all_results,
                            executed_paths,
                            phase_threads,
                            tech_hints,
                            verbose,
                            "injection",
                        )
                    stop_now, no_novelty_streak, stop_reason = self._evaluate_campaign_stop(
                        "injection",
                        inject_results,
                        snapshot_before,
                        self._snapshot_campaign_state(state, all_results),
                        no_novelty_streak,
                    )
                    if stop_now:
                        state.campaign_stop_reason = stop_reason
                        if verbose:
                            print_warning(f"Aggressive stop: {stop_reason}")
                        state.scan_tech_hints = sorted(tech_hints)
                        state.scan_modules_executed = len(executed_paths)
                        return all_results

        # Adaptive specialized pass (CMS/framework-specific) based on discovered hints.
        remaining = max_modules - len(executed_paths)
        if remaining > 0:
            specializations = self._detect_specializations(tech_hints, all_results, state.knowledge_base)
            specialized_pool = [m for m in modules if m.get("path") not in executed_paths]
            specialized_pool = self._prune_modules_for_primary_cms(
                specialized_pool,
                state.knowledge_base,
            )
            specialized_modules = self._pick_specialized_modules(
                specialized_pool,
                specializations,
                state.knowledge_base,
            )
            kb_pre_adaptive = kb_light_copy(state.knowledge_base)
            specialized_selected = self._select_modules_opportunistic(
                specialized_modules,
                state,
                tech_hints,
                executed_paths,
                min(specialized_budget, remaining),
            )
            if specialized_selected:
                self._append_timeline_event(
                    state,
                    "adaptive",
                    f"Selected {len(specialized_selected)} specialized module(s).",
                    modules=specialized_selected,
                    extra={"specializations": sorted(specializations)},
                )
                self._log_opportunistic_pick("adaptive", specialized_selected, state, tech_hints, set(executed_paths))
                snapshot_before = self._snapshot_campaign_state(state, all_results)
                if verbose:
                    print_status(
                        f"Phase adaptive: executing {len(specialized_selected)} specialized module(s) "
                        f"for {', '.join(specializations)}"
                    )
                specialized_results = self._execute_agent_modules(
                    state,
                    scanner,
                    specialized_selected,
                    state.target_info,
                    phase_threads,
                    verbose,
                    "adaptive",
                )
                all_results.extend(specialized_results)
                selected_paths = [m.get("path") for m in specialized_selected if m.get("path")]
                for module in specialized_selected:
                    path = module.get("path")
                    if path:
                        executed_paths.add(path)
                specialized_hints = self._extract_tech_hints(specialized_results)
                tech_hints.update(specialized_hints)
                self._update_knowledge_base_from_results(
                    state.knowledge_base,
                    specialized_results,
                    selected_paths,
                    specialized_hints,
                    specializations,
                )
                self._record_module_performance_phase(state, kb_pre_adaptive, specialized_results, "adaptive")
                self._append_timeline_event(
                    state,
                    "adaptive",
                    "Adaptive phase completed.",
                    modules=specialized_selected,
                    results=specialized_results,
                    extra={"specializations": sorted(specializations)},
                )
                if self._credential_milestone_reached(state.knowledge_base):
                    return self._pivot_scan_campaign_after_credentials(
                        state,
                        modules,
                        scanner,
                        all_results,
                        executed_paths,
                        phase_threads,
                        tech_hints,
                        verbose,
                        "adaptive",
                    )
                stop_now, no_novelty_streak, stop_reason = self._evaluate_campaign_stop(
                    "adaptive",
                    specialized_results,
                    snapshot_before,
                    self._snapshot_campaign_state(state, all_results),
                    no_novelty_streak,
                )
                if stop_now:
                    state.campaign_stop_reason = stop_reason
                    if verbose:
                        print_warning(f"Aggressive stop: {stop_reason}")
                    state.scan_tech_hints = sorted(tech_hints)
                    state.scan_modules_executed = len(executed_paths)
                    return all_results
            state.scan_specializations = sorted(specializations)

        # Follow-up pass: when detections occur, chain auxiliary scanners/modules contextually.
        remaining = max_modules - len(executed_paths)
        if remaining > 0:
            followup_pool = [m for m in modules if m.get("path") not in executed_paths]
            followup_pool = self._filter_modules_for_cms_lock(
                followup_pool,
                state.knowledge_base,
                state.scan_specializations,
            )
            followup_pool = self._prune_modules_for_primary_cms(
                followup_pool,
                state.knowledge_base,
            )
            followup_modules = self._pick_followup_modules(
                all_results,
                followup_pool,
                state.knowledge_base,
            )
            kb_pre_followup = kb_light_copy(state.knowledge_base)
            followup_selected = self._select_modules_opportunistic(
                followup_modules,
                state,
                tech_hints,
                executed_paths,
                min(followup_budget, remaining),
            )
            if followup_selected:
                self._append_timeline_event(
                    state,
                    "follow-up",
                    f"Selected {len(followup_selected)} follow-up module(s).",
                    modules=followup_selected,
                    extra={"budget": min(followup_budget, remaining)},
                )
                self._log_opportunistic_pick("follow-up", followup_selected, state, tech_hints, set(executed_paths))
                snapshot_before = self._snapshot_campaign_state(state, all_results)
                if verbose:
                    print_status(f"Phase follow-up: executing {len(followup_selected)} module(s)")
                followup_overrides = self._build_inferred_option_overrides(followup_selected, state)
                followup_results = self._execute_plan_modules_with_options(
                    followup_selected,
                    state,
                    option_overrides=followup_overrides,
                    verbose=verbose,
                )
                all_results.extend(followup_results)
                selected_paths = [m.get("path") for m in followup_selected if m.get("path")]
                for module in followup_selected:
                    path = module.get("path")
                    if path:
                        executed_paths.add(path)
                followup_hints = self._extract_tech_hints(followup_results)
                tech_hints.update(followup_hints)
                self._update_knowledge_base_from_results(
                    state.knowledge_base,
                    followup_results,
                    selected_paths,
                    followup_hints,
                    set(),
                )
                self._record_module_performance_phase(state, kb_pre_followup, followup_results, "follow-up")
                self._append_timeline_event(
                    state,
                    "follow-up",
                    "Follow-up phase completed.",
                    modules=followup_selected,
                    results=followup_results,
                )
                for hint in state.knowledge_base.get("tech_hints", []) or []:
                    tech_hints.add(str(hint).lower())
                if self._credential_milestone_reached(state.knowledge_base):
                    return self._pivot_scan_campaign_after_credentials(
                        state,
                        modules,
                        scanner,
                        all_results,
                        executed_paths,
                        phase_threads,
                        tech_hints,
                        verbose,
                        "follow-up",
                    )
                stop_now, no_novelty_streak, stop_reason = self._evaluate_campaign_stop(
                    "follow-up",
                    followup_results,
                    snapshot_before,
                    self._snapshot_campaign_state(state, all_results),
                    no_novelty_streak,
                )
                if stop_now:
                    state.campaign_stop_reason = stop_reason
                    if verbose:
                        print_warning(f"Aggressive stop: {stop_reason}")
                    state.scan_tech_hints = sorted(tech_hints)
                    state.scan_modules_executed = len(executed_paths)
                    return all_results

            post_auth_budget = min(12, max(3, max_modules - len(executed_paths)))
            self._run_post_auth_methodical_wave(
                state,
                modules,
                scanner,
                all_results,
                executed_paths,
                phase_threads,
                post_auth_budget,
            )
            for hint in state.knowledge_base.get("tech_hints", []) or []:
                tech_hints.add(str(hint).lower())
            if self._credential_milestone_reached(state.knowledge_base):
                return self._pivot_scan_campaign_after_credentials(
                    state,
                    modules,
                    scanner,
                    all_results,
                    executed_paths,
                    phase_threads,
                    tech_hints,
                    verbose,
                    "follow-up",
                )

        # Final targeted pass using collected hints.
        remaining = max_modules - len(executed_paths)
        if remaining > 0:
            targeted_pool = [m for m in modules if m.get("path") not in executed_paths]
            targeted_pool = self._filter_modules_for_cms_lock(
                targeted_pool,
                state.knowledge_base,
                state.scan_specializations,
            )
            targeted_pool = self._prune_modules_for_primary_cms(
                targeted_pool,
                state.knowledge_base,
            )
            targeted = self._rank_targeted_modules(
                targeted_pool,
                tech_hints,
                remaining,
                specializations=state.scan_specializations,
                knowledge_base=state.knowledge_base,
            )
            if targeted:
                self._append_timeline_event(
                    state,
                    "targeted",
                    f"Selected {len(targeted)} target-specific module(s).",
                    modules=targeted,
                    extra={"hints": sorted(tech_hints)[:8]},
                )
                kb_pre_targeted = kb_light_copy(state.knowledge_base)
                snapshot_before = self._snapshot_campaign_state(state, all_results)
                if verbose:
                    hints_display = ", ".join(sorted(tech_hints)) if tech_hints else "none"
                    print_status(f"Phase targeted: {len(targeted)} module(s), hints={hints_display}")
                targeted_results = self._execute_agent_modules(
                    state,
                    scanner,
                    targeted,
                    state.target_info,
                    phase_threads,
                    verbose,
                    "targeted",
                )
                all_results.extend(targeted_results)
                selected_paths = [m.get("path") for m in targeted if m.get("path")]
                for module in targeted:
                    path = module.get("path")
                    if path:
                        executed_paths.add(path)
                targeted_hints = self._extract_tech_hints(targeted_results)
                tech_hints.update(targeted_hints)
                self._update_knowledge_base_from_results(
                    state.knowledge_base,
                    targeted_results,
                    selected_paths,
                    targeted_hints,
                    set(),
                )
                self._record_module_performance_phase(state, kb_pre_targeted, targeted_results, "targeted")
                self._append_timeline_event(
                    state,
                    "targeted",
                    "Targeted phase completed.",
                    modules=targeted,
                    results=targeted_results,
                )
                if self._credential_milestone_reached(state.knowledge_base):
                    return self._pivot_scan_campaign_after_credentials(
                        state,
                        modules,
                        scanner,
                        all_results,
                        executed_paths,
                        phase_threads,
                        tech_hints,
                        verbose,
                        "targeted",
                    )
                stop_now, no_novelty_streak, stop_reason = self._evaluate_campaign_stop(
                    "targeted",
                    targeted_results,
                    snapshot_before,
                    self._snapshot_campaign_state(state, all_results),
                    no_novelty_streak,
                )
                if stop_now:
                    state.campaign_stop_reason = stop_reason
                    if verbose:
                        print_warning(f"Aggressive stop: {stop_reason}")
                    state.scan_tech_hints = sorted(tech_hints)
                    state.scan_modules_executed = len(executed_paths)
                    return all_results

        state.scan_tech_hints = sorted(tech_hints)
        state.scan_modules_executed = len(executed_paths)
        return all_results

    def _compute_adaptive_budgets(self, state: AgentState) -> Dict[str, int]:
        max_modules = int(state.max_modules)
        kb = state.knowledge_base
        confidence = kb.get("tech_confidence", {}) if isinstance(kb, dict) else {}
        info_score = information_score_kb(kb if isinstance(kb, dict) else {})
        endpoint_count = len((kb or {}).get("discovered_endpoints", []) or []) if isinstance(kb, dict) else 0
        hint_count = len((kb or {}).get("tech_hints", []) or []) if isinstance(kb, dict) else 0
        has_auth = self._has_authenticated_session(kb) or self._credential_milestone_reached(kb)
        auth_focus = self._should_prioritize_auth_surface(kb)
        cms_conf = max(
            float(confidence.get("wordpress", 0.0) or 0.0),
            float(confidence.get("drupal", 0.0) or 0.0),
            float(confidence.get("joomla", 0.0) or 0.0),
        )
        cms_high = cms_conf >= 0.75
        if has_auth:
            return {
                "recon": min(max_modules, max(3, max_modules // 6)),
                "crawl": max(1, max_modules // 12),
                "inject": max(2, max_modules // 8),
                "specialized": max(8, max_modules // 2),
                "followup": max(8, max_modules // 2),
            }
        if cms_high:
            return {
                "recon": min(max_modules, max(4, max_modules // 4)),
                "crawl": max(1, max_modules // 10),
                "inject": max(2, max_modules // 10),
                "specialized": max(8, max_modules // 2),
                "followup": max(6, max_modules // 3),
            }
        if auth_focus:
            return {
                "recon": min(max_modules, max(4, max_modules // 4)),
                "crawl": max(1, max_modules // 12),
                "inject": max(2, max_modules // 10),
                "specialized": max(5, max_modules // 4),
                "followup": max(8, max_modules // 3),
            }
        if info_score <= 4.0 and endpoint_count <= 2 and hint_count <= 2:
            return {
                "recon": min(max_modules, max(5, max_modules // 3)),
                "crawl": max(4, max_modules // 4),
                "inject": max(3, max_modules // 6),
                "specialized": max(3, max_modules // 6),
                "followup": max(4, max_modules // 5),
            }
        if info_score >= 18.0 or endpoint_count >= 18:
            return {
                "recon": min(max_modules, max(4, max_modules // 5)),
                "crawl": max(2, max_modules // 8),
                "inject": max(4, max_modules // 4),
                "specialized": max(6, max_modules // 3),
                "followup": max(6, max_modules // 3),
            }
        return {
            "recon": min(max_modules, max(4, int(state.recon_modules))),
            "crawl": max(3, max_modules // 5),
            "inject": max(8, max_modules // 2),
            "specialized": max(4, max_modules // 4),
            "followup": max(5, max_modules // 5),
        }

    def _get_cms_lock_specializations(self, knowledge_base, specializations=None):
        cms = set([str(x).lower() for x in (specializations or [])])
        cms = cms.intersection(set(CMS_LOCK_NAMES))
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        confidence = kb.get("tech_confidence", {}) or {}
        if float(confidence.get("wordpress", 0.0) or 0.0) >= 0.7:
            cms.add("wordpress")
        if float(confidence.get("drupal", 0.0) or 0.0) >= 0.7:
            cms.add("drupal")
        if float(confidence.get("joomla", 0.0) or 0.0) >= 0.7:
            cms.add("joomla")
        return cms

    def _filter_modules_for_cms_lock(self, modules, knowledge_base, specializations=None):
        cms_lock = self._get_cms_lock_specializations(knowledge_base, specializations)
        if not cms_lock:
            return modules

        cms_tokens = {
            "wordpress": ("wordpress", "wp_", "wp-", "xmlrpc", "wpjson", "wp_json", "wpvivid"),
            "drupal": ("drupal",),
            "joomla": ("joomla",),
        }
        common_safe_tokens = (
            "security_headers", "sensitive_files",
            "robots", "sitemap", "cors_misconfig", "csp_bypass",
            "admin_panel_detect", "debug_info_leak",
            # Auth surfaces must stay available under CMS lock (generic login != wrong CMS).
            "login_page_detector", "admin_login_bruteforce",
        )
        generic_fuzz_tokens = (
            "xss_scanner", "sql_injection", "sqli", "lfi_fuzzer", "ssrf_scanner",
            "xxe_scanner", "api_fuzzer", "fuzzer", "smuggling", "nodejs_injection", "django_sqli",
            "auxiliary/scanner/http/wordpress_scanner",
        )

        allowed = []
        for module in modules:
            path = str(module.get("path", "")).lower()
            if any(token in path for token in common_safe_tokens):
                allowed.append(module)
                continue
            cms_match = False
            for cms in cms_lock:
                if any(token in path for token in cms_tokens.get(cms, ())):
                    cms_match = True
                    break
            if cms_match:
                allowed.append(module)
                continue
            if any(token in path for token in generic_fuzz_tokens):
                continue
        return allowed

    def _get_primary_cms_focus(self, knowledge_base):
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        confidence = kb.get("tech_confidence", {}) or {}
        hints = set([str(x).lower() for x in kb.get("tech_hints", [])])

        cms_scores = {
            "wordpress": float(confidence.get("wordpress", 0.0) or 0.0),
            "drupal": float(confidence.get("drupal", 0.0) or 0.0),
            "joomla": float(confidence.get("joomla", 0.0) or 0.0),
        }
        if "wordpress" in hints:
            cms_scores["wordpress"] += 0.2
        if "drupal" in hints:
            cms_scores["drupal"] += 0.2
        if "joomla" in hints:
            cms_scores["joomla"] += 0.2

        winner = max(cms_scores, key=cms_scores.get)
        best = cms_scores[winner]
        second = max([v for k, v in cms_scores.items() if k != winner] or [0.0])
        # Dominant single-CMS mode: enough evidence and clear lead.
        if best >= 0.6 and (best - second) >= 0.2:
            return winner
        return None

    def _prune_modules_for_primary_cms(self, modules, knowledge_base):
        primary = self._get_primary_cms_focus(knowledge_base)
        if not primary:
            return modules

        banned_by_primary = {
            "wordpress": (
                "drupal", "joomla", "spa_scanner", "api_fuzzer", "graphql_detect",
                "nodejs_injection", "django_sqli",
            ),
            "drupal": (
                "wordpress", "joomla", "spa_scanner", "api_fuzzer", "graphql_detect",
            ),
            "joomla": (
                "wordpress", "drupal", "spa_scanner", "api_fuzzer", "graphql_detect",
            ),
        }
        allow_core_tokens = (
            "security_headers", "sensitive_files",
            "cors_misconfig", "csp_bypass",
            "login_page_detector", "admin_login_bruteforce",
        )
        primary_tokens = {
            "wordpress": ("wordpress", "wp_", "wp-", "xmlrpc"),
            "drupal": ("drupal", "sites/default"),
            "joomla": ("joomla", "administrator"),
        }

        filtered = []
        for module in modules:
            path = str(module.get("path", "")).lower()
            if any(token in path for token in allow_core_tokens):
                filtered.append(module)
                continue
            if any(token in path for token in primary_tokens.get(primary, ())):
                filtered.append(module)
                continue
            if any(token in path for token in banned_by_primary.get(primary, ())):
                continue
            filtered.append(module)
        return filtered

    def _snapshot_campaign_state(self, state: AgentState, all_results):
        kb = state.knowledge_base
        return {
            "endpoints": len(kb.get("discovered_endpoints", [])),
            "params": len(kb.get("discovered_params", [])),
            "hints": len(kb.get("tech_hints", [])),
            "vulns": len([r for r in all_results if r.get("vulnerable")]),
        }

    def _evaluate_campaign_stop(self, phase_name, phase_results, before, after, no_novelty_streak):
        novelty = (
            (after.get("endpoints", 0) - before.get("endpoints", 0))
            + (after.get("params", 0) - before.get("params", 0))
            + (after.get("hints", 0) - before.get("hints", 0))
            + (after.get("vulns", 0) - before.get("vulns", 0))
        )
        if novelty <= 0:
            no_novelty_streak += 1
        else:
            no_novelty_streak = 0

        status_codes = []
        waf_markers = 0
        for row in phase_results or []:
            blob = " ".join([
                str(row.get("message", "")),
                str(row.get("details", "")),
            ]).lower()
            status_codes.extend([int(code) for code in HTTP_STATUS_IN_TEXT_RE.findall(blob)])
            if any(marker in blob for marker in WAF_BODY_MARKERS):
                waf_markers += 1

        if no_novelty_streak >= 2:
            return True, no_novelty_streak, f"{phase_name}: low novelty for 2 consecutive phases"

        if status_codes:
            noisy = [c for c in status_codes if c in HTTP_STATUS_RISK_SIGNALS]
            noisy_ratio = len(noisy) / max(1, len(status_codes))
            if len(status_codes) >= 20 and noisy_ratio >= 0.85:
                return True, no_novelty_streak, (
                    f"{phase_name}: excessive redirect/forbidden/rate-limit noise ({len(noisy)}/{len(status_codes)})"
                )
            waf_codes = [c for c in status_codes if c in WAF_RISK_HTTP_STATUS_CODES]
            if len(waf_codes) >= 3 or waf_markers >= 2:
                return True, no_novelty_streak, (
                    f"{phase_name}: repeated blocking/WAF signals ({len(waf_codes)} status, {waf_markers} marker)"
                )

        return False, no_novelty_streak, ""

    def _update_knowledge_base_from_results(self, knowledge_base, results, module_paths, tech_hints, specializations):
        if not isinstance(knowledge_base, dict):
            return

        observed_modules = set(knowledge_base.get("observed_modules", []))
        discovered_endpoints = set(knowledge_base.get("discovered_endpoints", []))
        discovered_params = set(knowledge_base.get("discovered_params", []))
        login_paths = set(knowledge_base.get("login_paths", []))
        kb_hints = set(knowledge_base.get("tech_hints", []))
        kb_specializations = set(knowledge_base.get("specializations", []))
        risk_signals = set(knowledge_base.get("risk_signals", []))
        tech_confidence = dict(knowledge_base.get("tech_confidence", {}))
        post_auth_catalog_paths = set(knowledge_base.get("post_auth_catalog_paths", []))
        post_auth_exploit_paths = set(knowledge_base.get("post_auth_exploit_paths", []))

        for path in module_paths or []:
            if path:
                observed_modules.add(str(path))
        for hint in tech_hints or []:
            hint_lower = str(hint).lower()
            kb_hints.add(hint_lower)
            if hint_lower in ("wordpress", "drupal", "joomla", "django", "flask", "nodejs", "api"):
                tech_confidence[hint_lower] = round(
                    max(float(tech_confidence.get(hint_lower, 0.0) or 0.0), 0.45),
                    3,
                )
        for sp in specializations or []:
            kb_specializations.add(str(sp).lower())

        for result in results or []:
            details = result.get("details", {}) or {}
            detail_blob = ""
            if isinstance(details, dict):
                for key in ("post_login_snippet", "post_login_final_url", "authenticated_as"):
                    val = details.get(key)
                    if isinstance(val, str) and val:
                        detail_blob += " " + val[:8000]
            msg_raw = str(result.get("message", "") or "")
            msg_lower = msg_raw.lower()
            mod_path_low = str(result.get("path", "") or "").lower()
            blob = " ".join([
                str(result.get("path", "")),
                str(result.get("module", "")),
                msg_raw,
                detail_blob,
            ])
            lower_blob = blob.lower()
            evidence_blob = self._result_evidence_blob(result)

            if result.get("vulnerable"):
                risk_signals.add("vulnerability_detected")
            if "error" in lower_blob:
                risk_signals.add("scanner_errors")
            if "sql" in lower_blob:
                risk_signals.add("sql_signal")
            if "xss" in lower_blob:
                risk_signals.add("xss_signal")
            if "lfi" in lower_blob:
                risk_signals.add("lfi_signal")
            if "ssrf" in lower_blob:
                risk_signals.add("ssrf_signal")
            if any(
                x in lower_blob
                for x in (
                    "interactive shell",
                    "meterpreter session",
                    "session opened",
                    "command shell",
                    "shell access",
                    "reverse shell",
                    "opening a shell",
                )
            ):
                risk_signals.add("interactive_shell")
                risk_signals.add("shell_obtained")

            is_positive = self._result_indicates_positive_detection(result)
            if is_positive:
                if "wordpress" in evidence_blob or "wp-content" in evidence_blob or "wp-includes" in evidence_blob:
                    tech_confidence["wordpress"] = round(min(1.0, float(tech_confidence.get("wordpress", 0.0) or 0.0) + 0.08), 3)
                if "drupal" in evidence_blob or "sites/default" in evidence_blob:
                    tech_confidence["drupal"] = round(min(1.0, float(tech_confidence.get("drupal", 0.0) or 0.0) + 0.08), 3)
                if "joomla" in evidence_blob or "com_content" in evidence_blob:
                    tech_confidence["joomla"] = round(min(1.0, float(tech_confidence.get("joomla", 0.0) or 0.0) + 0.08), 3)
                if "graphql" in evidence_blob or "swagger" in evidence_blob or "/api" in evidence_blob:
                    tech_confidence["api"] = round(min(1.0, float(tech_confidence.get("api", 0.0) or 0.0) + 0.06), 3)
            else:
                # Decay over-confident CMS hypotheses when scanners repeatedly
                # report explicit negative outcomes.
                if ("wordpress" in evidence_blob or "wp-" in evidence_blob or "wp_" in evidence_blob) and any(
                    marker in evidence_blob for marker in ("not detected", "found: 0", "no wordpress plugins", "not vulnerable")
                ):
                    tech_confidence["wordpress"] = round(max(0.0, float(tech_confidence.get("wordpress", 0.0) or 0.0) - 0.12), 3)
                if "drupal" in evidence_blob and any(marker in evidence_blob for marker in ("not detected", "found: 0", "not vulnerable")):
                    tech_confidence["drupal"] = round(max(0.0, float(tech_confidence.get("drupal", 0.0) or 0.0) - 0.12), 3)
                if "joomla" in evidence_blob and any(marker in evidence_blob for marker in ("not detected", "found: 0", "not vulnerable")):
                    tech_confidence["joomla"] = round(max(0.0, float(tech_confidence.get("joomla", 0.0) or 0.0) - 0.12), 3)

            for endpoint in self._extract_endpoint_candidates(blob):
                discovered_endpoints.add(endpoint)
                endpoint_lower = str(endpoint).lower()
                if any(token in endpoint_lower for token in ("/login", "signin", "auth", "wp-login.php")):
                    login_paths.add(str(endpoint).split("?", 1)[0])

            for param in self._extract_param_candidates(blob):
                discovered_params.add(param)

            # e.g. admin_panel_detect: "Login panel(s): /login.php, /admin"
            if "login panel" in msg_lower and ":" in msg_raw:
                try:
                    tail = msg_raw.split(":", 1)[1]
                    for part in COMMA_SEMICOLON_SPLIT_RE.split(tail):
                        part = part.strip().strip(").")
                        if part.startswith("/"):
                            login_paths.add(part.split()[0].split("?", 1)[0])
                except Exception:
                    pass

            if isinstance(details, dict):
                paths_value = details.get("paths")
                if isinstance(paths_value, str):
                    for raw_path in paths_value.split(","):
                        candidate = raw_path.strip()
                        if candidate.startswith("/"):
                            login_paths.add(candidate.split("?", 1)[0])
                login_path_hint = details.get("login_path")
                if isinstance(login_path_hint, str) and login_path_hint.startswith("/"):
                    login_paths.add(login_path_hint.split("?", 1)[0])
                    risk_signals.add("login_surface_detected")

            # simple_login_scanner: path only in free-text reason
            if "login page detected on" in msg_lower:
                m = LOGIN_PAGE_PATH_IN_MESSAGE_RE.search(msg_raw)
                if m:
                    login_paths.add(m.group(1).split("?", 1)[0])
                    risk_signals.add("login_surface_detected")

            if "admin_login_bruteforce" in mod_path_low:
                lp_hint = None
                if isinstance(details, dict):
                    lp_hint = details.get("login_path") or details.get("target_path")
                if not isinstance(lp_hint, str) or not lp_hint.startswith("/"):
                    lp_hint = self._select_best_login_path(knowledge_base)
                if isinstance(lp_hint, str) and lp_hint.startswith("/"):
                    lp_norm = lp_hint.split("?", 1)[0]
                    auth_in_details = isinstance(details, dict) and (
                        details.get("post_login_snippet")
                        or details.get("post_login_final_url")
                        or details.get("authenticated_as")
                    )
                    strong_success = auth_in_details or (
                        "valid credential" in msg_lower
                        or "authenticated as" in msg_lower
                    )
                    if not strong_success and any(
                        x in msg_lower
                        for x in (
                            "no valid",
                            "no credential",
                            "exhausted",
                            "could not find",
                            "failed after",
                            "attempts exhausted",
                        )
                    ):
                        lst = knowledge_base.setdefault("auth_bruteforce_exhausted_login_paths", [])
                        if lp_norm not in lst:
                            lst.append(lp_norm)

            if result.get("vulnerable") and any(
                token in mod_path_low
                for token in ("login_page_detector", "simple_login_scanner", "admin_panel_detect")
            ):
                risk_signals.add("login_surface_detected")

            auth_context = self._extract_auth_context_from_details(
                str(result.get("path", "")),
                details,
            )
            if auth_context:
                self._merge_auth_context(knowledge_base, auth_context)
                risk_signals.add("credentials_obtained")
                if auth_context.get("cookies"):
                    risk_signals.add("session_cookie_obtained")

            if isinstance(details, dict) and (
                details.get("post_login_snippet") or details.get("post_login_final_url")
            ):
                risk_signals.add("authenticated_session")
                context = self._get_active_auth_context(knowledge_base)
                excerpt = (
                    context.get("post_login_snippet")
                    or str(details.get("post_login_snippet") or "")[:12000]
                )
                knowledge_base["authenticated_page_excerpt"] = excerpt
                knowledge_base["auth_milestone"] = {
                    "stage": "post_login",
                    "source": "credential_probe",
                    "module": str(result.get("path", ""))[:200],
                    "login_path": context.get("login_path", ""),
                    "landing_path": context.get("final_path", ""),
                }
                resolved_catalog = self._resolve_catalog_paths_from_text(
                    knowledge_base, excerpt, max_paths=30
                )
                for candidate_path in resolved_catalog:
                    post_auth_catalog_paths.add(candidate_path)
                    low = str(candidate_path).lower()
                    if low.startswith("exploit/") or low.startswith("exploits/"):
                        post_auth_exploit_paths.add(candidate_path)
                explicit_apps = self._detect_app_stack_markers(
                    " ".join([
                        excerpt,
                        str(context.get("final_path", "") or ""),
                        str(context.get("final_url", "") or ""),
                        str(result.get("message", "") or ""),
                    ])
                )
                for app in explicit_apps:
                    kb_hints.add(app)
                    if app == "dvwa":
                        tech_confidence["dvwa"] = round(
                            max(float(tech_confidence.get("dvwa", 0.0) or 0.0), 0.95),
                            3,
                        )
                        allowed = set(knowledge_base.get("module_capability_catalog", {}).get("all_paths", []) or [])
                        for path in (
                            "exploits/ctf/dvwa_rce",
                            "exploits/ctf/dvwa_file_upload",
                        ):
                            if path in allowed:
                                post_auth_catalog_paths.add(path)
                                post_auth_exploit_paths.add(path)
                dynamic_keywords = self._extract_adaptive_keywords(blob)
                for keyword in self._match_keywords_to_catalog(knowledge_base, dynamic_keywords):
                    kb_hints.add(keyword)

            if is_positive:
                dynamic_keywords = self._extract_adaptive_keywords(evidence_blob)
                for keyword in self._match_keywords_to_catalog(knowledge_base, dynamic_keywords):
                    kb_hints.add(keyword)

            self._merge_module_produces_into_kb(
                knowledge_base,
                str(result.get("path", "") or ""),
                details,
            )

        knowledge_base["observed_modules"] = sorted(observed_modules)
        knowledge_base["discovered_endpoints"] = sorted(discovered_endpoints)
        knowledge_base["discovered_params"] = sorted(discovered_params)
        knowledge_base["login_paths"] = sorted(login_paths)[:40]
        knowledge_base["tech_hints"] = sorted(kb_hints)
        knowledge_base["tech_confidence"] = tech_confidence
        knowledge_base["specializations"] = sorted(kb_specializations)
        knowledge_base["risk_signals"] = sorted(risk_signals)
        knowledge_base["post_auth_catalog_paths"] = sorted(post_auth_catalog_paths)[:40]
        knowledge_base["post_auth_exploit_paths"] = sorted(post_auth_exploit_paths)[:20]

    def _select_best_login_path(self, knowledge_base):
        return self._auth_ops.select_best_login_path(knowledge_base)

    def _build_inferred_option_overrides(self, modules, state: AgentState):
        return self._auth_ops.build_inferred_option_overrides(modules, state)

    def _extract_endpoint_candidates(self, text):
        candidates = set()
        # Pull absolute URLs and keep only path/query part for dedup.
        for match in ABSOLUTE_URL_RE.findall(text or ""):
            try:
                parsed = urllib.parse.urlparse(match)
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                candidates.add(path[:200])
            except Exception:
                continue

        # Pull path-looking tokens.
        for match in ENDPOINT_RE.findall(text or ""):
            endpoint = match.strip()
            if len(endpoint) >= 2:
                candidates.add(endpoint[:200])
        return candidates

    def _extract_param_candidates(self, text):
        params = set()
        for key, _ in PARAM_RE.findall(text or ""):
            params.add(key.lower())
        return params

    def _take_unseen_modules(self, modules, executed_paths, limit):
        selected = []
        for module in modules:
            path = module.get("path")
            if not path or path in executed_paths:
                continue
            selected.append(module)
            if len(selected) >= limit:
                break
        return selected

    def _score_module_by_rules(self, module: dict, rules: ModuleScoreRules) -> int:
        """Sum weights for rules where any token appears in the module metadata blob (lowercased)."""
        return score_rules(module_blob_lower(module), rules)

    def _select_modules_opportunistic(
        self,
        candidates,
        state: AgentState,
        tech_hints: set,
        executed_paths: set,
        limit: int,
    ):
        """
        Rank unseen modules by utility (expected information gain / estimated network cost),
        instead of static pool order alone.
        """
        return select_opportunistic_batch(
            candidates,
            state.knowledge_base,
            tech_hints,
            executed_paths,
            limit,
            self._module_perf,
            self._module_ctx,
        )

    def _log_opportunistic_pick(
        self,
        phase_label: str,
        selected: list,
        state: AgentState,
        tech_hints: set,
        executed_paths_before: set,
    ) -> None:
        if not selected or not state.verbose:
            return
        parts = []
        for m in selected[:6]:
            path = m.get("path", "") or ""
            tail = path.split("/")[-1] if path else "?"
            u = unified_module_score(
                m,
                state.knowledge_base,
                tech_hints,
                executed_paths_before,
                self._module_perf,
                self._module_ctx,
            )
            parts.append(f"{tail}={u:.2f}")
        kb_s = information_score_kb(state.knowledge_base)
        print_info(
            f"[{phase_label}] opportunistic utility order | KB info≈{kb_s:.2f} | " + ", ".join(parts)
        )

    def _pick_crawler_modules(self, modules):
        crawler_keywords = (
            "crawler", "crawl", "spider", "robots", "sitemap", "spa_scanner",
            "directory_listing", "admin_panel_detect",
        )
        rules = [(1, crawler_keywords)]
        picked = []
        for module in modules:
            blob = module_blob_lower(module)
            if score_rules(blob, rules) > 0:
                picked.append(module)
        return picked

    def _pick_injection_modules(self, modules, knowledge_base=None):
        cms_lock = self._get_cms_lock_specializations(knowledge_base or {})
        if cms_lock:
            # Hard block: when CMS is confidently identified, avoid generic
            # injection fuzzers and rely on CMS-specific scanners/follow-ups.
            return []
        injection_keywords = (
            "sql_injection", "sqli", "django_sqli", "xss", "lfi", "rfi", "ssrf",
            "xxe", "injection", "fuzzer", "smuggling", "cors", "csp_bypass",
            "bypass_403", "bypass_404",
        )
        injection_rules = [(1, injection_keywords)]
        param_profile = self._build_param_profile(knowledge_base or {})
        picked = []
        ranked = []
        strong_wp = self._has_tech_evidence(knowledge_base or {}, "wordpress", threshold=0.65)
        for module in modules:
            path = module_path_lower(module)
            blob = module_blob_lower(module)
            if score_rules(blob, injection_rules) <= 0:
                continue
            if not strong_wp and (
                "wordpress_madara" in path
                or "wordpress_madara" in blob
                or "wp_plugin_exclusive" in path
                or "wp_plugin_exclusive" in blob
            ):
                continue
            picked.append(module)
            score = self._score_injection_module_by_profile(blob, param_profile)
            ranked.append((score, module))

        # Keep context-relevant modules first, but do not drop all generic fallbacks.
        ranked.sort(key=lambda item: item[0], reverse=True)
        prioritized = [module for score, module in ranked if score > 0]
        fallback = [module for score, module in ranked if score <= 0]
        return prioritized + fallback

    def _build_param_profile(self, knowledge_base):
        params = set([str(p).lower() for p in knowledge_base.get("discovered_params", [])])
        endpoints = [str(e).lower() for e in knowledge_base.get("discovered_endpoints", [])]

        profile = {
            "params": params,
            "has_query": any("?" in endpoint for endpoint in endpoints),
            "has_api": any("/api" in endpoint or "graphql" in endpoint for endpoint in endpoints),
            "id_like": any(p in params for p in ("id", "user_id", "uid", "item", "product", "post")),
            "search_like": any(p in params for p in ("q", "query", "search", "term", "keyword", "filter")),
            "url_like": any(p in params for p in ("url", "uri", "redirect", "callback", "endpoint", "link")),
            "file_like": any(p in params for p in ("file", "path", "page", "include", "template", "view")),
            "text_like": any(p in params for p in ("message", "comment", "content", "title", "name")),
        }
        return profile

    def _score_injection_module_by_profile(self, blob, profile):
        score = 0
        if "sql" in blob:
            if profile["id_like"] or profile["search_like"]:
                score += 4
            if profile["has_query"]:
                score += 1
        if "xss" in blob:
            if profile["text_like"] or profile["search_like"]:
                score += 4
            if profile["has_query"]:
                score += 1
        if "ssrf" in blob:
            if profile["url_like"]:
                score += 4
        if "lfi" in blob:
            if profile["file_like"]:
                score += 4
        if "api_fuzzer" in blob or "graphql" in blob:
            if profile["has_api"]:
                score += 3
        if any(k in blob for k in ("fuzzer", "injection", "smuggling")):
            score += 1
        return score

    def _detect_specializations(self, tech_hints, results, knowledge_base=None):
        """
        Determine adaptive specialization buckets from hints + scan outcomes.
        """
        corpus = set([str(h).lower() for h in tech_hints])
        for result in results:
            if not self._result_indicates_positive_detection(result):
                continue
            if not self._result_has_explicit_evidence(result):
                continue
            blob = self._result_evidence_blob(result)
            for token in CMS_SPECIALIZATION_BLOB_TOKENS:
                if token in blob:
                    corpus.add(token)

        confidence = {}
        if isinstance(knowledge_base, dict):
            confidence = knowledge_base.get("tech_confidence", {}) or {}

        specializations = set()
        if any(t in corpus for t in ("wordpress", "wp")):
            specializations.add("wordpress")
        if "drupal" in corpus:
            specializations.add("drupal")
        if "joomla" in corpus:
            specializations.add("joomla")
        if float(confidence.get("wordpress", 0.0) or 0.0) >= 0.75:
            specializations.add("wordpress")
        if float(confidence.get("drupal", 0.0) or 0.0) >= 0.75:
            specializations.add("drupal")
        if float(confidence.get("joomla", 0.0) or 0.0) >= 0.75:
            specializations.add("joomla")
        if any(t in corpus for t in ("django", "flask", "fastapi", "python")):
            specializations.add("python_web")
        if any(t in corpus for t in ("nodejs", "react", "angular")):
            specializations.add("node_web")
        if any(t in corpus for t in ("api", "swagger", "graphql")):
            specializations.add("api")
        if float(confidence.get("api", 0.0) or 0.0) >= 0.6:
            specializations.add("api")
        if any(t in corpus for t in ("grafana", "jenkins", "tomcat", "phpmyadmin")):
            specializations.add("admin_surface")
        return specializations

    def _result_indicates_positive_detection(self, result):
        if bool(result.get("vulnerable")):
            return True
        message = str(result.get("message", "")).lower()
        if any(marker in message for marker in NEGATIVE_EVIDENCE_MARKERS):
            return False
        return any(marker in message for marker in POSITIVE_SCAN_MESSAGE_MARKERS)

    def _is_actionable_finding(self, result):
        if not isinstance(result, dict) or not result.get("vulnerable"):
            return False
        if self._is_network_error_result(result):
            return False

        path = str(result.get("path", "")).lower()
        message = str(result.get("message", "")).lower()
        severity = str(result.get("severity", "")).lower()
        details = result.get("details", {}) or {}
        exploit_path = self._catalog.normalize_exploit_module_path(result.get("exploit_module"))

        if exploit_path:
            return True
        if isinstance(details, dict) and (
            details.get("authenticated_as")
            or details.get("post_login_snippet")
            or details.get("post_login_final_url")
        ):
            return True
        if self._catalog.is_pure_technology_detection_module(path, message):
            return False
        if any(token in path for token in (
            "admin_panel_detect",
            "simple_login_scanner",
            "login_page_detector",
            "admin_login_bruteforce",
        )):
            return True
        if severity in ("critical", "high", "medium"):
            return True
        if severity in ("low", "info") and any(token in message for token in (
            "login page detected",
            "login panel",
            "valid credentials",
            "authenticated as",
            "missing headers",
            "exposed:",
            "robots.txt exposed",
            "information leak",
        )):
            return True

        # Drop broad technology enumeration / generic fuzz summaries from exploitation reasoning.
        noisy_detection_tokens = (
            "wordpress_scanner",
            "wordpress_enum_user",
            "wp_plugin_scanner",
            "drupal_scanner",
            "joomla_scanner",
            "api_fuzzer",
            "auxiliary/scanner/http/robots",
            "crawler",
            "cors_misconfig",
            "csp_bypass",
            "debug_info_leak",
        )
        if any(token in path for token in noisy_detection_tokens):
            return False

        return bool(message and severity)

    def _execute_modules_targeted(self, scanner, modules, state, verbose=False):
        """
        Execute injection modules with context-aware option overrides when possible.
        """
        results = []
        target_info = state.target_info
        knowledge_base = state.knowledge_base
        scheme = target_info.get("scheme", "http")
        hostname = target_info.get("hostname", "")
        port = target_info.get("port", 80)
        base_url = f"{scheme}://{hostname}:{port}"
        discovered_endpoints = knowledge_base.get("discovered_endpoints", [])
        discovered_params = knowledge_base.get("discovered_params", [])
        param_profile = self._build_param_profile(knowledge_base)

        preferred_endpoint = "/"
        for endpoint in discovered_endpoints:
            if "?" in endpoint:
                preferred_endpoint = endpoint
                break
        if preferred_endpoint == "/" and discovered_endpoints:
            preferred_endpoint = discovered_endpoints[0]

        preferred_param = "id"
        for candidate in ("id", "q", "query", "search", "url", "file", "path", "page"):
            if candidate in [p.lower() for p in discovered_params]:
                preferred_param = candidate
                break

        for module_info in modules:
            module_path = module_info.get("path")
            result = {
                "module": module_info.get("name", module_path),
                "path": module_path,
                "status": "error",
                "vulnerable": False,
                "message": "",
                "details": {},
            }
            block_reason = self._module_block_reason_for_profile(state, module_path)
            if block_reason:
                result["status"] = "skipped"
                result["message"] = block_reason
                result["details"] = {"safety_profile": self._normalized_safety_profile(state)}
                results.append(result)
                continue

            self._sleep_between_agent_actions(state, f"targeted:{module_path}")
            announced_bruteforce = False
            if "admin_login_bruteforce" in str(module_path).lower():
                login_path = (
                    self._select_best_login_path(state.knowledge_base)
                    or "/admin/login"
                )
                print_status(f"Trying admin login bruteforce on {login_path}")
                announced_bruteforce = True
            set_thread_output_quiet(not verbose)
            try:
                module_instance = self.framework.module_loader.load_module(
                    module_path,
                    load_only=False,
                    framework=self.framework,
                )
                if not module_instance:
                    result["message"] = "Failed to load module"
                    results.append(result)
                    continue

                # Baseline target options
                if hasattr(module_instance, "target"):
                    module_instance.set_option("target", hostname)
                if hasattr(module_instance, "rhost"):
                    module_instance.set_option("rhost", hostname)
                if hasattr(module_instance, "rport"):
                    module_instance.set_option("rport", port)
                if hasattr(module_instance, "port"):
                    module_instance.set_option("port", port)
                if hasattr(module_instance, "ssl"):
                    module_instance.set_option("ssl", scheme == "https")

                self._seed_http_session_from_auth(module_instance, state)
                inferred_bf = {}
                if "admin_login_bruteforce" in str(module_path).lower():
                    inferred_bf = self._build_inferred_option_overrides([module_info], state).get(module_path, {})
                merged_auth = dict(self._infer_auth_option_overrides(module_instance, module_path, state))
                merged_auth.update(inferred_bf)
                self._apply_safe_module_options(module_instance, merged_auth)

                # Context-aware tuning for injection modules
                module_path_lower = str(module_path).lower()
                if hasattr(module_instance, "COMMON_PARAMS") and discovered_params:
                    module_instance.COMMON_PARAMS = list(dict.fromkeys([p.lower() for p in discovered_params]))[:20]
                if hasattr(module_instance, "URL_PARAMS") and discovered_params:
                    url_params = [p.lower() for p in discovered_params if p.lower() in (
                        "url", "uri", "redirect", "callback", "endpoint", "link", "path", "file"
                    )]
                    if url_params:
                        module_instance.URL_PARAMS = list(dict.fromkeys(url_params))[:20]

                # Some modules require a full URL target and parameter option.
                if "lfi_fuzzer" in module_path_lower:
                    lfi_target = preferred_endpoint
                    if lfi_target.startswith("/"):
                        lfi_target = f"{base_url}{lfi_target}"
                    if not lfi_target.startswith("http"):
                        lfi_target = base_url
                    module_instance.set_option("target", lfi_target)
                    if hasattr(module_instance, "parameter"):
                        file_param = preferred_param
                        if not param_profile["file_like"]:
                            file_param = "file"
                        module_instance.set_option("parameter", file_param)

                run_result = module_instance.run()
                result["vulnerable"] = bool(run_result)
                result["status"] = "vulnerable" if result["vulnerable"] else "safe"

                module_meta = getattr(module_instance, "__info__", {})
                dynamic_info = getattr(module_instance, "vulnerability_info", {}) or {}
                result["message"] = dynamic_info.get("reason") or module_meta.get("description", "")
                result["severity"] = dynamic_info.get("severity") or module_meta.get("severity")
                if dynamic_info.get("version"):
                    result["version"] = dynamic_info.get("version")
                exploit_path = self._catalog.normalize_exploit_module_path(module_meta.get("module"))
                if exploit_path:
                    result["exploit_module"] = exploit_path
                linked_modules = self._catalog.normalize_linked_module_paths(module_meta.get("modules"))
                if linked_modules:
                    result["linked_modules"] = linked_modules
                result["details"] = {
                    key: value for key, value in dynamic_info.items()
                    if key not in ("reason", "severity", "version")
                }
            except Exception as exc:
                result["message"] = f"Error: {exc}"
            finally:
                set_thread_output_quiet(False)
            results.append(result)
            if self._record_waf_signals_from_results(state, [result], "targeted"):
                break
            if verbose:
                status_icon = "[+]" if result["vulnerable"] else "[-]"
                print_info(f"{status_icon} {result['path']}: {result.get('message', '')}")
        return results

    def _pick_specialized_modules(self, modules, specializations, knowledge_base=None):
        """
        Pick modules matching adaptive specialization buckets.
        """
        if not specializations:
            return []

        specialization_tokens = {
            "wordpress": ("wordpress", "wp_", "wp-", "wpvivid", "wp_plugin"),
            "drupal": ("drupal",),
            "joomla": ("joomla",),
            "python_web": ("django", "flask", "fastapi", "python", "python_injection"),
            "node_web": ("nodejs", "node", "react", "angular"),
            "api": ("api", "swagger", "graphql"),
            "admin_surface": ("grafana", "jenkins", "tomcat", "phpmyadmin", "admin", "login"),
        }

        tokens = set()
        for key in specializations:
            for token in specialization_tokens.get(key, ()):
                tokens.add(token)

        picked = []
        strong_wordpress = self._has_tech_evidence(knowledge_base or {}, "wordpress", threshold=0.8)
        cms_lock = self._get_cms_lock_specializations(knowledge_base or {}, specializations)
        for module in modules:
            blob = module_blob_lower(module)
            if not cms_lock and any(token in blob for token in CMS_HINT_TOKENS):
                continue
            if "wordpress_madara" in blob and not strong_wordpress:
                continue
            if any(token in blob for token in tokens):
                picked.append(module)
        return picked

    def _pick_followup_modules(self, results, modules, knowledge_base=None):
        """
        Chain additional modules based on concrete detections.
        """
        detection_tokens = set()
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        auth_session = self._has_authenticated_session(kb)
        risk_signals_lower = [str(s).lower() for s in kb.get("risk_signals", [])]
        tech_hints_lower = [str(h).lower() for h in kb.get("tech_hints", [])]
        login_risk = {"login_redirect_detected", "login_form_detected", "login_surface_detected"}
        for s in risk_signals_lower:
            if not auth_session and s in login_risk:
                detection_tokens.add("login_surface")
        for h in tech_hints_lower:
            if not auth_session and h in ("auth_portal", "login"):
                detection_tokens.add("login_surface")

        # Concrete login URLs from fingerprint / parsers: always chain auth follow-ups.
        if not auth_session and any(isinstance(p, str) and p.startswith("/") for p in kb.get("login_paths", [])):
            detection_tokens.add("login_surface")

        wanted = set()
        for result in results:
            if not result.get("vulnerable"):
                continue
            for linked_path in self._catalog.normalize_linked_module_paths(result.get("linked_modules")):
                wanted.add(linked_path)
            det = result.get("details", {}) or {}
            det_piece = ""
            if isinstance(det, dict):
                for key in ("post_login_snippet", "post_login_final_url", "authenticated_as"):
                    val = det.get(key)
                    if isinstance(val, str) and val:
                        det_piece += " " + val[:4000]
            blob = " ".join([str(result.get("message", "")), det_piece]).lower()
            for token in (
                "wordpress", "phpmyadmin", "apache", "nginx", "robots", "sitemap",
                "security headers", "missing headers", "api", "swagger", "graphql",
                "admin panel", "login panel", "wp-login.php", "/admin", "administrator",
                "/login.php", "login.php", "/login", "signin", "auth/login",
            ):
                if token in blob:
                    detection_tokens.add(token)

        token_map = {
            "wordpress": (
                "auxiliary/scanner/http/wp_plugin_scanner",
                "auxiliary/scanner/http/wordpress_enum_user",
                "scanner/http/wordpress_detect",
            ),
            "phpmyadmin": (
                "scanner/http/phpmyadmin_detect",
                "auxiliary/scanner/http/lfi_fuzzer",
            ),
            "apache": (
                "auxiliary/scanner/http/apache_vuln_scanner",
            ),
            "nginx": (
                "auxiliary/scanner/http/nginx_vuln_scanner",
            ),
            "robots": (
                "auxiliary/scanner/http/crawler",
            ),
            "sitemap": (
                "auxiliary/scanner/http/crawler",
            ),
            "security headers": (
                "auxiliary/scanner/http/cors_misconfig",
                "auxiliary/scanner/http/csp_bypass",
            ),
            "missing headers": (
                "auxiliary/scanner/http/cors_misconfig",
                "auxiliary/scanner/http/csp_bypass",
            ),
            "api": ("scanner/http/swagger_detect",),
            "swagger": ("scanner/http/swagger_detect",),
            "graphql": ("scanner/http/graphql_detect",),
            "admin panel": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "login panel": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "wp-login.php": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "/admin": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "administrator": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "login_surface": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "/login.php": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "login.php": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "/login": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "signin": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "auth/login": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
        }

        for token in detection_tokens:
            for path in token_map.get(token, ()):
                wanted.add(path)

        if auth_session:
            auth_skip_tokens = ("login_page_detector", "admin_login_bruteforce")
            wanted = {
                p for p in wanted
                if not any(t in p.lower() for t in auth_skip_tokens)
            }

        if not wanted:
            return []

        # If we already collected login URL paths (including root ``/``), skip re-discovery and run bruteforce first.
        # Note: root ``/`` was previously excluded here, which wrongly treated "login on home page" as unknown surface.
        has_concrete_login_paths = any(
            isinstance(p, str) and p.startswith("/")
            for p in kb.get("login_paths", [])
        )
        if has_concrete_login_paths:
            wanted.discard("auxiliary/scanner/http/login_page_detector")

        selected = []
        for module in modules:
            if module_path_lower(module) in wanted:
                selected.append(module)

        def _followup_auth_order(mod):
            p = module_path_lower(mod)
            # When paths are unknown, probe with login_page_detector before bruteforce; otherwise bruteforce first.
            prefer_bf_first = has_concrete_login_paths
            if p.endswith("login_page_detector"):
                return 2 if prefer_bf_first else 0
            if "admin_login_bruteforce" in p:
                return 0 if prefer_bf_first else 1
            return 5

        selected.sort(key=_followup_auth_order)
        # Enforce CMS lock to avoid generic fuzzing follow-ups.
        cms_specs = set([t for t in detection_tokens if t in CMS_LOCK_NAMES])
        return self._filter_modules_for_cms_lock(selected, knowledge_base or {}, specializations=cms_specs)

    def _smart_select_modules(self, state: AgentState, modules, scanner):
        """
        Two-phase strategy:
        1) quick recon/fingerprinting modules
        2) targeted module subset based on discovered technologies
        """
        verbose = bool(state.verbose)
        max_modules = int(state.max_modules)
        recon_budget = int(state.recon_modules)

        # If protocol is explicit and narrow (non-http), keep deterministic scope.
        forced_protocol = state.protocol
        if forced_protocol and forced_protocol not in ("http", "https"):
            return modules[:max_modules]

        recon_candidates = self._pick_recon_modules(modules, state)
        recon_candidates = recon_candidates[:recon_budget]

        if verbose:
            print_info(
                f"Smart selection: running {len(recon_candidates)} recon module(s) "
                f"before choosing up to {max_modules} modules."
            )

        tech_hints = set()
        if recon_candidates:
            recon_results = self._execute_agent_modules(
                state,
                scanner,
                recon_candidates,
                state.target_info,
                max(2, min(6, int(state.threads))),
                False,
                "smart-recon",
            )
            tech_hints = self._extract_tech_hints(recon_results)

        selected = self._rank_targeted_modules(
            modules,
            tech_hints,
            max_modules,
            knowledge_base=state.knowledge_base,
        )
        if verbose:
            hints_display = ", ".join(sorted(tech_hints)) if tech_hints else "none"
            print_info(f"Technology hints: {hints_display}")
            print_info(f"Selected modules: {len(selected)} / {len(modules)}")

        return selected

    def _select_modules_for_target(self, state: AgentState, modules):
        protocol = state.protocol
        target_info = state.target_info
        raw_target = str(state.raw_target).strip().lower()
        verbose = bool(state.verbose)

        # If user explicitly asked for a protocol, respect it.
        if protocol:
            filtered = self._filter_modules_by_protocol(modules, protocol=protocol)
            if verbose:
                print_info(f"Module profile: forced protocol '{protocol}' ({len(filtered)} modules)")
            return self._merge_expanded_surface_if(state, filtered, modules)

        # Web-first profile for domains/URLs (avoid smb/ldap/etc by default).
        scheme = str(target_info.get("scheme", "")).lower()
        is_url_like = raw_target.startswith("http://") or raw_target.startswith("https://")
        is_host_port = ":" in raw_target and not is_url_like
        if scheme in ("http", "https") and not is_host_port:
            filtered = self._filter_modules_by_protocol(modules, protocol="http")
            if verbose:
                print_info(f"Module profile: web-only default ({len(filtered)} modules)")
            return self._merge_expanded_surface_if(state, filtered, modules)

        # For explicit host:port targets, keep scanner's port-aware behavior.
        port = target_info.get("port")
        if port:
            protocol_guess = self._port_to_protocol(port)
            if protocol_guess:
                filtered = self._filter_modules_by_protocol(modules, protocol=protocol_guess)
                if filtered:
                    if verbose:
                        print_info(f"Module profile: port-aware ({port}) ({len(filtered)} modules)")
                    return self._merge_expanded_surface_if(state, filtered, modules)

        if getattr(state, "expanded_surface", False) and isinstance(state.knowledge_base, dict):
            state.knowledge_base["expanded_surface"] = True
        return modules

    def _is_expanded_surface_module_path(self, path: str) -> bool:
        pl = (path or "").lower().replace("\\", "/")
        return any(pl.startswith(p) for p in EXPANDED_SURFACE_MODULE_PREFIXES)

    def _merge_expanded_surface_modules(self, filtered: List[Any], full_modules: List[Any]) -> List[Any]:
        seen: set = set()
        out: List[Any] = []
        for m in full_modules:
            p = str(m.get("path") or "").strip()
            if not p or p in seen:
                continue
            if not self._is_expanded_surface_module_path(p):
                continue
            seen.add(p)
            out.append(m)
        for m in filtered:
            p = str(m.get("path") or "").strip()
            if not p or p in seen:
                continue
            seen.add(p)
            out.append(m)
        return out

    def _merge_expanded_surface_if(self, state: AgentState, filtered: List[Any], full_modules: List[Any]) -> List[Any]:
        if not getattr(state, "expanded_surface", False):
            return filtered
        kb = state.knowledge_base
        if isinstance(kb, dict):
            kb["expanded_surface"] = True
        return self._merge_expanded_surface_modules(filtered, full_modules)

    def _organization_root_domain(self, hostname: str) -> str:
        h = (hostname or "").lower().strip(".")
        if h.startswith("www."):
            return h[4:]
        return h

    def _hostname_in_seed_family(self, seed: str, candidate: str) -> bool:
        s = self._organization_root_domain(seed)
        c = self._organization_root_domain(candidate)
        if not s or not c or "." not in c:
            return False
        if len(c) > 200:
            return False
        if c == s:
            return True
        return c.endswith("." + s)

    def _collect_strings_from_details_object(self, obj: Any, sink: List[str], depth: int = 0) -> None:
        if depth > 14 or len(sink) > 4000:
            return
        if isinstance(obj, dict):
            for v in obj.values():
                self._collect_strings_from_details_object(v, sink, depth + 1)
        elif isinstance(obj, (list, tuple, set)):
            for v in list(obj)[:900]:
                self._collect_strings_from_details_object(v, sink, depth + 1)
        elif isinstance(obj, (str, int, float, bool)):
            sink.append(str(obj))

    def _hostname_looks_valid(self, host: str) -> bool:
        h = (host or "").strip().lower().strip(".")
        if not h or len(h) > 200 or ".." in h or "/" in h or " " in h or "*" in h:
            return False
        if h in ("localhost", "127.0.0.1", "::1"):
            return False
        if h.endswith((".arpa", ".local")):
            return False
        parts = h.split(".")
        if len(parts) < 2:
            return False
        for p in parts:
            if not p or len(p) > 63:
                return False
            if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", p, re.I):
                return False
        return True

    def _extract_hosts_from_free_text(self, text: str, sink: set) -> None:
        if not text:
            return
        for m in ABSOLUTE_URL_RE.finditer(text):
            try:
                parsed = urllib.parse.urlparse(m.group(0))
                if parsed.hostname:
                    sink.add(parsed.hostname.lower())
            except Exception:
                continue
        for m in re.finditer(
            r"@([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\.(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63})",
            text,
            re.I,
        ):
            sink.add(m.group(1).lower())
        for token in re.findall(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
            text.lower(),
        ):
            sink.add(token)

    def _hosts_from_scan_result(self, result: Dict[str, Any]) -> List[str]:
        sink: set = set()
        strings: List[str] = []
        details = result.get("details") if isinstance(result, dict) else None
        if isinstance(details, dict):
            self._collect_strings_from_details_object(details, strings)
        if isinstance(result, dict):
            strings.append(str(result.get("message", "") or ""))
        blob = " ".join(strings)
        self._extract_hosts_from_free_text(blob, sink)
        return [h for h in sink if self._hostname_looks_valid(h)]

    def _harvest_derived_hosts(self, seed_hostname: str, results: List[Any]) -> List[str]:
        ordered: List[str] = []
        seen: set = set()
        seed_l = (seed_hostname or "").lower().strip(".")
        for row in results or []:
            if not isinstance(row, dict):
                continue
            for h in self._hosts_from_scan_result(row):
                hl = h.lower()
                if hl == seed_l or hl in seen:
                    continue
                if not self._hostname_in_seed_family(seed_hostname, h):
                    continue
                seen.add(hl)
                ordered.append(hl)
        return ordered

    def _derived_scan_limits(self, state: AgentState) -> Tuple[int, int]:
        max_h = min(
            DERIVED_HOST_SCAN_MAX_HOSTS,
            max(2, int(state.max_modules) // 4),
        )
        per = min(
            DERIVED_HOST_SCAN_MODULES_PER_HOST,
            max(4, int(state.max_modules) // 5),
        )
        return max_h, per

    def _run_derived_host_surface_scans(
        self,
        state: AgentState,
        scanner: ScannerCommand,
        all_modules: List[Dict[str, Any]],
        primary_results: List[Any],
    ) -> List[Any]:
        seed = str((state.target_info or {}).get("hostname", "") or "").strip()
        if not seed:
            return primary_results
        hosts = self._harvest_derived_hosts(seed, primary_results)
        kb = state.knowledge_base
        if isinstance(kb, dict):
            kb["derived_target_candidates"] = list(hosts)
            kb.setdefault("derived_host_scans", [])
        if not hosts:
            return primary_results
        max_hosts, per_host = self._derived_scan_limits(state)
        http_pool = self._filter_modules_by_protocol(all_modules, "http")
        if not http_pool:
            return primary_results
        aggregated = list(primary_results)
        visited = {seed.lower()}
        self._append_timeline_event(
            state,
            "scan",
            f"Derived host scans: up to {max_hosts} hostname(s), {per_host} HTTP module(s) each.",
            extra={"candidates": len(hosts)},
        )
        ran = 0
        for host in hosts:
            if ran >= max_hosts:
                break
            hl = host.lower()
            if hl in visited:
                continue
            visited.add(hl)
            sub_target = scanner._parse_target(f"https://{host}/")
            if not sub_target:
                continue
            if bool(state.verbose):
                print_info(f"Derived HTTP scan ({ran + 1}/{max_hosts}): {host}")
            hints = list(kb.get("tech_hints", []) or []) if isinstance(kb, dict) else []
            specs = list(state.scan_specializations or [])
            batch = self._rank_targeted_modules(
                http_pool,
                hints,
                per_host,
                specializations=specs,
                knowledge_base=kb if isinstance(kb, dict) else {},
            )
            if not batch:
                continue
            sub_results = self._execute_agent_modules(
                state,
                scanner,
                batch,
                sub_target,
                max(2, min(int(state.threads), 6)),
                bool(state.verbose),
                f"derived-host:{host}",
            )
            aggregated.extend(sub_results)
            if isinstance(kb, dict):
                paths = [m.get("path") for m in batch if m.get("path")]
                self._update_knowledge_base_from_results(
                    kb,
                    sub_results,
                    paths,
                    hints,
                    specs,
                )
                kb["derived_host_scans"].append({
                    "host": host,
                    "modules": [m.get("path") for m in batch],
                    "count": len(sub_results),
                })
            ran += 1
        return aggregated

    def _filter_modules_by_protocol(self, modules, protocol):
        protocol = str(protocol or "").strip().lower()
        if not protocol:
            return modules
        pfx_scanner = f"scanner/{protocol}/"
        pfx_aux = f"auxiliary/scanner/{protocol}/"
        filtered = []
        for module in modules:
            path = module_path_lower(module)
            if pfx_scanner in path or pfx_aux in path:
                filtered.append(module)
        return filtered

    def _port_to_protocol(self, port):
        mapping = {
            80: "http", 443: "http", 8080: "http", 8443: "http",
            21: "ftp", 22: "ssh", 23: "telnet", 389: "ldap", 636: "ldap",
            445: "smb", 139: "smb", 3306: "mysql", 5432: "postgresql",
        }
        return mapping.get(int(port))

    def _pick_recon_modules(self, modules, state: Optional[AgentState] = None):
        recon = []
        cms_detect_tokens = ("wordpress_detect", "drupal_detect", "joomla_detect")
        expanded = bool(state and getattr(state, "expanded_surface", False))
        for module in modules:
            path = module_path_lower(module)
            blob = module_blob_lower(module)
            is_surface_recon = False
            if expanded and self._is_expanded_surface_module_path(path):
                if not any(skip in path for skip in EXPANDED_SURFACE_RECON_SKIP_SUBSTR):
                    is_surface_recon = True
            # Keep recon lightweight: favor detection/fingerprint modules, avoid heavy vuln scanners.
            is_light_detect = (
                path.startswith("scanner/http/")
                and any(token in path for token in ("_detect", "server_banner", "robots_txt", "security_headers"))
                and "http_methods_detect" not in path
            )
            is_auth_recon = any(token in path for token in ("login_page_detector", "simple_login_scanner"))
            is_discovery_aux = any(token in blob for token in ("robots", "swagger", "graphql"))
            is_heavy_scanner = (
                path.startswith("auxiliary/scanner/")
                and any(token in path for token in ("wordpress_scanner", "drupal_scanner", "joomla_scanner"))
            )
            if (is_light_detect or is_discovery_aux or is_auth_recon or is_surface_recon) and not is_heavy_scanner:
                recon.append(module)
        # Favor quick CMS detectors first so campaign pivots earlier; then expanded-surface modules.
        recon.sort(
            key=lambda m: (
                0 if any(t in module_path_lower(m) for t in cms_detect_tokens) else 1,
                0 if (
                    expanded
                    and self._is_expanded_surface_module_path(str(m.get("path", "")))
                ) else 1,
                str(m.get("path", "")),
            )
        )
        return recon

    def _pick_cms_detector_modules(self, modules):
        picked = []
        wanted = ("wordpress_detect", "drupal_detect", "joomla_detect")
        for module in modules:
            path = module_path_lower(module)
            if any(token in path for token in wanted):
                picked.append(module)
        return picked

    def _extract_tech_hints(self, recon_results):
        hints = set()
        hint_words = [
            "dvwa", "wordpress", "drupal", "joomla", "grafana", "jenkins", "elasticsearch",
            "kibana", "tomcat", "nginx", "apache", "phpmyadmin", "docker", "cloud",
            "api", "swagger", "fastapi", "django", "flask", "nodejs", "react", "angular",
            "php", "python", "java",
        ]
        for result in recon_results:
            if not self._result_indicates_positive_detection(result):
                continue
            if not self._result_has_explicit_evidence(result):
                continue
            blob = self._result_evidence_blob(result)
            for word in hint_words:
                if word in blob:
                    hints.add(word)
        return hints

    def _rank_targeted_modules(self, modules, tech_hints, max_modules, specializations=None, knowledge_base=None):
        """
        Deterministic targeted ranking using technology hints + generic web safety checks.
        """
        generic_web_keywords = (
            "sql", "xss", "lfi", "rfi", "ssrf", "cors", "csrf", "headers", "directory_listing",
            "debug", "injection", "wordpress_scanner", "drupal_scanner", "joomla_scanner",
        )
        core_capability_keywords = (
            "crawler", "crawl", "spider", "fuzzer", "fuzz", "sqli", "sql_injection",
            "xss_scanner", "lfi_fuzzer", "ssrf_scanner", "wordpress_scanner",
            "http_smuggling", "debug_info_leak", "archives",
            "sensitive_files", "security_headers",
        )
        generic_rules = [(2, generic_web_keywords)]
        core_rules = [(3, core_capability_keywords)]
        detect_fingerprint_rules = [(1, ("detect", "fingerprint"))]

        normalized_specializations = set([str(x).lower() for x in (specializations or [])])
        cms_specializations = normalized_specializations.intersection(set(CMS_LOCK_NAMES))
        if not cms_specializations:
            tech_set = set([str(h).lower() for h in tech_hints or []])
            cms_specializations = tech_set.intersection(set(CMS_LOCK_NAMES))

        cms_focus_tokens = {
            "wordpress": (
                "wordpress", "wp_", "wp-", "wp/plugin", "wp_plugin", "wpvivid",
                "wordpress_enum_user", "wordpress_detect",
            ),
            "drupal": ("drupal", "drupal_scanner", "drupal_detect"),
            "joomla": ("joomla", "joomla_scanner", "joomla_detect"),
        }
        cms_tokens = set()
        for cms in cms_specializations:
            for token in cms_focus_tokens.get(cms, ()):
                cms_tokens.add(token)
        strong_wordpress = self._has_tech_evidence(knowledge_base or {}, "wordpress", threshold=0.8)

        ranked = []
        tech_hints_seq = list(tech_hints or [])
        fuzz_penalty_tokens = ("xss", "sql_injection", "sqli", "lfi", "ssrf", "fuzzer")
        for idx, module in enumerate(modules):
            path = module_path_lower(module)
            blob = module_blob_lower(module)
            if "wordpress_madara" in blob and not strong_wordpress:
                continue
            if not strong_wordpress and ("wp_plugin_exclusive" in path or "wp_plugin_exclusive" in blob):
                continue

            score = score_tech_hints_in_blob(blob, tech_hints_seq, weight=4)
            score += score_rules(blob, generic_rules)
            score += score_rules(blob, core_rules)
            score += score_rules(blob, detect_fingerprint_rules)

            kb = knowledge_base or {}
            if isinstance(kb, dict) and kb.get("expanded_surface"):
                if self._is_expanded_surface_module_path(path):
                    score += 2

            if cms_tokens:
                is_cms_module = any(token in blob for token in cms_tokens)
                # In CMS lock mode, strongly prioritize CMS-centric modules and
                # penalize generic fuzzers that create noisy request floods.
                if is_cms_module:
                    score += 8
                elif any(token in blob for token in fuzz_penalty_tokens):
                    score -= 6

            ranked.append((score, -idx, module))

        ranked.sort(reverse=True)
        selected = []
        selected_paths = set()

        # Always seed with a compact baseline of high-value modules.
        baseline = self._select_baseline_modules(modules, cms_specializations)
        for module in baseline:
            path = module.get("path")
            if path and path not in selected_paths:
                selected.append(module)
                selected_paths.add(path)
            if len(selected) >= max_modules:
                return selected

        for score, _, module in ranked:
            if len(selected) >= max_modules:
                break
            if score <= 0 and selected:
                continue
            path = module.get("path")
            if path and path in selected_paths:
                continue
            selected.append(module)
            if path:
                selected_paths.add(path)

        # Ensure non-empty selection.
        if not selected:
            selected = modules[:max_modules]
        return selected

    def _select_baseline_modules(self, modules, cms_specializations=None):
        """
        Baseline modules to keep framework coverage broad but bounded.
        """
        cms_specializations = set([str(x).lower() for x in (cms_specializations or [])])
        if cms_specializations:
            wanted_tokens = [
                "scanner/http/security_headers",
                "scanner/http/sensitive_files",
            ]
            if "wordpress" in cms_specializations:
                wanted_tokens.extend([
                    "scanner/http/wordpress_detect",
                    "auxiliary/scanner/http/wp_plugin_scanner",
                    "auxiliary/scanner/http/wordpress_enum_user",
                ])
            if "drupal" in cms_specializations:
                wanted_tokens.extend([
                    "scanner/http/drupal_detect",
                    "auxiliary/scanner/http/drupal_scanner",
                ])
            if "joomla" in cms_specializations:
                wanted_tokens.extend([
                    "scanner/http/joomla_detect",
                    "auxiliary/scanner/http/joomla_scanner",
                ])
        else:
            wanted_tokens = [
                "auxiliary/scanner/http/crawler",
                "auxiliary/scanner/http/sql_injection",
                "auxiliary/scanner/http/xss_scanner",
                "auxiliary/scanner/http/lfi_fuzzer",
                "auxiliary/scanner/http/ssrf_scanner",
                "scanner/http/security_headers",
                "scanner/http/sensitive_files",
            ]

        selected = []
        for token in wanted_tokens:
            for module in modules:
                if token in module_path_lower(module):
                    selected.append(module)
                    break
        return selected

    def _node_analyze(self, state: AgentState) -> AgentState:
        state.metrics.deterministic_steps += 1
        if state.target_reachable is False:
            print_warning(f"Analysis skipped: {state.reachability_reason or 'target unreachable'}")
            return state
        vulnerable_results = state.vulnerable_results
        knowledge_base = state.knowledge_base
        sql_findings = []
        for item in vulnerable_results:
            text_blob = " ".join([
                str(item.get("module", "")),
                str(item.get("path", "")),
                str(item.get("message", "")),
            ]).lower()
            if "sql" in text_blob or "injection" in text_blob:
                sql_findings.append(item)
        state.sql_findings = sql_findings
        state.contextual_findings = self._build_contextual_findings(vulnerable_results, knowledge_base)
        state.potential_findings = self._identify_potential_findings(vulnerable_results)
        if state.verbose:
            print_info(
                "Context snapshot: "
                f"{len(knowledge_base.get('discovered_endpoints', []))} endpoints, "
                f"{len(knowledge_base.get('discovered_params', []))} params, "
                f"{len(knowledge_base.get('tech_hints', []))} tech hints, "
                f"{len(knowledge_base.get('login_paths', []))} login paths"
            )

        self._print_detection_summary(state)

        exploit_count = len([f for f in state.contextual_findings if f.get("decision_class") == "exploit"])
        followup_count = len([f for f in state.contextual_findings if f.get("decision_class") == "followup"])
        info_count = len([f for f in state.contextual_findings if f.get("decision_class") == "info"])

        if sql_findings:
            print_success(f"High-priority detection: SQL injection ({len(sql_findings)})")
        elif exploit_count:
            print_success(f"Exploitable findings detected: {exploit_count}")
        elif followup_count:
            print_warning(
                f"No direct exploit path yet. Follow-up investigation required on {followup_count} finding(s)."
            )
        elif vulnerable_results:
            print_warning(
                f"Only informational findings detected ({info_count or len(vulnerable_results)}). "
                "No direct exploitation candidate."
            )
        else:
            print_warning("No obvious vulnerabilities found")
        self._append_timeline_event(
            state,
            "analyze",
            (
                f"Analysis classified findings: exploit={exploit_count}, "
                f"followup={followup_count}, info={info_count}."
            ),
            kind="analysis",
            results=state.contextual_findings,
        )
        return state

    def _identify_potential_findings(self, vulnerable_results):
        potential = []
        for finding in vulnerable_results:
            msg = str(finding.get("message", "")).lower()
            sev = str(finding.get("severity", "")).lower()
            if any(token in msg for token in ("potential", "possible", "manual verification")):
                potential.append(finding)
                continue
            if sev in ("info", "low") and not finding.get("exploit_module"):
                potential.append(finding)
        return potential

    def _build_contextual_findings(self, vulnerable_results, knowledge_base):
        contextual = []
        hints = set(knowledge_base.get("tech_hints", []))
        risk_signals = set(knowledge_base.get("risk_signals", []))
        endpoint_count = len(knowledge_base.get("discovered_endpoints", []))
        param_count = len(knowledge_base.get("discovered_params", []))
        history_scores = self._report.load_history_scores()

        severity_weight = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        for item in vulnerable_results:
            path = str(item.get("path", "")).lower()
            message = str(item.get("message", "")).lower()
            severity = str(item.get("severity", "")).lower()
            exploit_path = self._catalog.normalize_exploit_module_path(item.get("exploit_module"))

            matching_hints = [h for h in hints if h and (h in path or h in message)]
            impact = float(severity_weight.get(severity, 2))
            if any(token in message for token in ("rce", "command execution", "admin", "auth bypass")):
                impact += 1.0
            if self._catalog.is_pure_technology_detection_module(path, message):
                impact -= 0.8

            exploitability = 1.2 if exploit_path else 0.8
            if self._catalog.normalize_linked_module_paths(item.get("linked_modules")):
                exploitability += 0.35
            if any(token in path for token in ("sql", "xss", "lfi", "ssrf")):
                exploitability += 0.2
            if any(token in path for token in (
                "simple_login_scanner",
                "login_page_detector",
                "admin_panel_detect",
                "admin_login_bruteforce",
            )):
                exploitability += 0.5

            confidence = 0.9 if item.get("vulnerable") else 0.5
            if matching_hints:
                confidence += 0.2
            if "possible" in message or "potential" in message:
                confidence -= 0.2
            if "scanner_errors" in risk_signals and severity in ("low", "info"):
                confidence -= 0.1
            if "login page detected" in message or "login panel" in message:
                confidence += 0.25
            confidence = max(0.3, min(confidence, 1.2))

            evidence_count = 1.0
            details = item.get("details", {}) if isinstance(item, dict) else {}
            if isinstance(details, dict):
                evidence_count += min(len(details), 4) * 0.2
            evidence_count += min(len(matching_hints), 3) * 0.2
            if endpoint_count >= 10:
                evidence_count += 0.2
            if param_count >= 5:
                evidence_count += 0.2

            history = history_scores.get(path, {})
            detections = int(history.get("detections", 0))
            freshness = max(0.5, 1.0 - (detections * 0.05))

            false_positive_penalty = self._estimate_false_positive_penalty(path, severity, item, history)
            context_score = (impact * exploitability * confidence * evidence_count * freshness) - false_positive_penalty

            annotated = dict(item)
            annotated["context_score"] = round(context_score, 3)
            annotated["risk_factors"] = {
                "impact": round(impact, 3),
                "exploitability": round(exploitability, 3),
                "confidence": round(confidence, 3),
                "evidence_count": round(evidence_count, 3),
                "freshness": round(freshness, 3),
                "false_positive_penalty": round(false_positive_penalty, 3),
            }
            annotated["context_hints"] = matching_hints
            annotated["decision_class"] = self._finding_decision_class(annotated)
            annotated["importance"] = self._finding_importance_label(annotated)
            contextual.append(annotated)

        contextual.sort(key=lambda row: row.get("context_score", 0), reverse=True)
        return contextual

    def _collect_redirect_observation(self, state: AgentState):
        kb = state.knowledge_base
        fingerprint_trace = kb.get("fingerprint_trace", []) or []
        redirect_paths = []
        root_status = None
        root_location = ""

        for row in fingerprint_trace:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", ""))
            try:
                status = int(row.get("status", 0) or 0)
            except Exception:
                status = 0
            location = str(row.get("location", "")).strip()

            if path == "/" and status:
                root_status = status
                root_location = location[:200]
            if status in HTTP_REDIRECT_STATUSES:
                redirect_paths.append({
                    "path": path,
                    "status": status,
                    "location": location[:200],
                })

        endpoint_count = len(kb.get("discovered_endpoints", []))
        return {
            "root_status": root_status,
            "root_location": root_location,
            "redirect_count": len(redirect_paths),
            "redirect_paths": redirect_paths[:8],
            "low_discovery": endpoint_count <= 1,
        }

    def _estimate_false_positive_penalty(self, path, severity, item, history):
        likely_false_positives = int(history.get("likely_false_positives", 0))
        penalty = likely_false_positives * 0.15
        if not item.get("exploit_module") and severity in ("low", "info"):
            penalty += 0.2
        if self._catalog.is_pure_technology_detection_module(path, str(item.get("message", ""))):
            penalty += 0.35
        if "possible" in str(item.get("message", "")).lower():
            penalty += 0.1
        return penalty

    def _finding_decision_class(self, finding: Dict[str, Any]) -> str:
        if not isinstance(finding, dict):
            return "info"
        path = str(finding.get("path", "")).lower()
        message = str(finding.get("message", "")).lower()
        severity = str(finding.get("severity", "")).lower()
        details = finding.get("details", {}) or {}
        exploit_path = self._catalog.normalize_exploit_module_path(finding.get("exploit_module"))

        if exploit_path:
            return "exploit"
        if isinstance(details, dict) and (
            details.get("authenticated_as")
            or details.get("post_login_snippet")
            or details.get("post_login_final_url")
        ):
            return "followup"
        if any(token in path for token in (
            "admin_panel_detect",
            "simple_login_scanner",
            "login_page_detector",
            "admin_login_bruteforce",
        )):
            return "followup"
        if severity in ("critical", "high"):
            return "followup"
        if any(token in message for token in (
            "authenticated as",
            "valid credentials",
            "auth bypass",
            "login page detected",
            "login panel",
        )):
            return "followup"
        return "info"

    def _finding_importance_label(self, finding: Dict[str, Any]) -> str:
        score = float(finding.get("context_score", 0.0) or 0.0)
        decision = str(finding.get("decision_class", self._finding_decision_class(finding)))
        if decision == "exploit":
            return "critical"
        if decision == "followup" and score >= 5.0:
            return "high"
        if decision == "followup":
            return "medium"
        if score >= 3.0:
            return "medium"
        return "low"

    def _shorten_text(self, value: Any, limit: int = 160) -> str:
        text = " ".join(str(value or "").split())
        if len(text) <= limit:
            return text
        return text[: limit - 3].rstrip() + "..."

    def _print_detection_summary(self, state: AgentState) -> None:
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        findings = state.contextual_findings or []
        if state.target_reachable is False:
            print_warning(f"Target summary: unreachable ({state.reachability_reason or 'no reason'})")
            return

        tech_hints = self._display_tech_hints(kb)
        login_paths = [str(x) for x in kb.get("login_paths", []) if str(x).strip()]
        endpoints = kb.get("discovered_endpoints", []) or []
        params = kb.get("discovered_params", []) or []
        risk_signals = [str(x) for x in kb.get("risk_signals", []) if str(x).strip()]
        stack_confidence = self._stack_confidence_rows(kb)

        print_status("Detection summary")
        print_info(
            f"Surface: endpoints={len(endpoints)} params={len(params)} "
            f"tech={len(tech_hints)} login_paths={len(login_paths)}"
        )
        if tech_hints:
            print_info(f"Tech hints: {', '.join(tech_hints[:6])}")
        if stack_confidence:
            print_info(
                "Stack confidence: "
                + ", ".join([f"{name}={score:.2f}" for name, score in stack_confidence[:5]])
            )
        if login_paths:
            print_info(f"Login paths: {', '.join(login_paths[:4])}")
        if risk_signals:
            print_info(f"Signals: {', '.join(risk_signals[:6])}")

        if not findings:
            return

        important = [f for f in findings if f.get("importance") in ("critical", "high", "medium")]
        exploit = [f for f in findings if f.get("decision_class") == "exploit"]
        followup = [f for f in findings if f.get("decision_class") == "followup"]
        info_only = [f for f in findings if f.get("decision_class") == "info"]
        print_info(
            f"Decision buckets: exploit={len(exploit)} "
            f"followup={len(followup)} info={len(info_only)}"
        )

        top_rows = important[:5] if important else findings[:5]
        print_status("Important findings")
        for row in top_rows:
            badge = str(row.get("decision_class", "info")).upper()
            importance = str(row.get("importance", "low")).upper()
            path = str(row.get("path", "")).strip()
            message = self._shorten_text(row.get("message", ""), 145)
            score = float(row.get("context_score", 0.0) or 0.0)
            print_info(f"[{importance}/{badge}] {path} | score={score:.2f}")
            if message:
                print_info(f"  -> {message}")

    def _print_decision_summary(self, state: AgentState) -> None:
        plan = state.execution_plan or {}
        llm_plan = state.llm_plan or {}
        source = "LLM" if state.decision_source == "llm_local" else "Heuristic"
        print_status("Decision summary")
        print_info(f"Source: {source}")
        if state.campaign_goal:
            print_info(f"Goal: {state.campaign_goal}")

        nba = llm_plan.get("next_best_action")
        if isinstance(nba, dict) and nba.get("type"):
            print_info(
                f"Next action: {nba.get('type')} {nba.get('path', '')} "
                f"| {self._shorten_text(nba.get('reason', ''), 120)}"
            )

        actions = [a for a in (plan.get("next_actions") or []) if isinstance(a, dict)]
        run_actions = [
            a for a in actions
            if str(a.get("type", "")).lower() in ("run_followup", "run_exploit")
        ][:4]
        if run_actions:
            print_info("Planned actions:")
            for row in run_actions:
                reason = self._action_reason_for_path(
                    str(row.get("path", "") or ""),
                    state,
                    state.contextual_findings or state.vulnerable_results,
                )
                print_info(f"- {row.get('type')} {row.get('path', '')}")
                print_info(f"  because: {self._shorten_text(reason, 120)}")

        rationale = llm_plan.get("rationale")
        if rationale:
            print_info(f"Rationale: {self._shorten_text(rationale, 180)}")

    def _refresh_compressed_context_summary(self, state: AgentState) -> str:
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        timeline = state.decision_timeline if isinstance(state.decision_timeline, list) else []
        findings = state.vulnerable_results or state.contextual_findings or []
        top_findings = []
        for item in findings[:8]:
            if not isinstance(item, dict):
                continue
            top_findings.append(
                f"{item.get('path', '')}: {self._shorten_text(item.get('message', ''), 90)}"
            )
        recent_events = []
        for row in timeline[-8:]:
            if isinstance(row, dict):
                recent_events.append(
                    f"{row.get('phase', '?')}: {self._shorten_text(row.get('summary', ''), 100)}"
                )
        summary = {
            "goal": state.campaign_goal,
            "stop_reason": state.campaign_stop_reason,
            "tech": kb.get("tech_hints", [])[:12],
            "risk": kb.get("risk_signals", [])[:12],
            "login_paths": kb.get("login_paths", [])[:6],
            "endpoints": len(kb.get("discovered_endpoints", []) or []),
            "params": len(kb.get("discovered_params", []) or []),
            "top_findings": top_findings,
            "recent_events": recent_events,
        }
        state.compressed_context_summary = self._shorten_text(json.dumps(summary, ensure_ascii=False), 3000)
        return state.compressed_context_summary

    def _node_reason(self, state: AgentState) -> AgentState:
        if state.target_reachable is False:
            state.metrics.deterministic_steps += 1
            state.decision_source = "heuristic"
            return state
        vulnerable_results = state.vulnerable_results
        contextual_findings = state.contextual_findings
        decision_findings = contextual_findings if contextual_findings else vulnerable_results
        knowledge_base = state.knowledge_base
        self._sync_campaign_goal(state)
        if state.verbose and state.campaign_goal:
            print_info(f"Campaign goal: {state.campaign_goal}")

        if state.campaign_stop_reason and "blocking/WAF" in str(state.campaign_stop_reason):
            state.llm_plan = {
                "selected_paths": [],
                "rationale": state.campaign_stop_reason,
                "next_best_action": {"type": "skip", "path": "", "reason": state.campaign_stop_reason},
            }
            state.execution_plan = {
                "next_actions": [],
                "max_requests_next_phase": 0,
                "stop_conditions": ["waf_or_blocking_detected"],
                "reasoning_confidence": 1.0,
                "skip_exploitation": True,
                "campaign_goal": state.campaign_goal,
            }
            state.decision_source = "heuristic"
            return state

        if state.campaign_goal == CAMPAIGN_GOAL_SHELL_STOP:
            state.llm_plan = {
                "selected_paths": [],
                "rationale": "Strategic stop: shell or interactive session milestone.",
                "next_best_action": self._next_best_action_for_goal(state, decision_findings),
            }
            state.execution_plan = {
                "next_actions": [],
                "max_requests_next_phase": 0,
                "stop_conditions": ["shell_obtained"],
                "reasoning_confidence": 1.0,
                "skip_exploitation": True,
                "campaign_goal": state.campaign_goal,
            }
            state.decision_source = "heuristic"
            self._append_timeline_event(
                state,
                "reason",
                "Strategic stop: shell milestone already reached.",
                kind="decision",
                extra={"goal": state.campaign_goal},
            )
            self._log_strategic_next_action(state)
            return state

        if not vulnerable_results:
            state.llm_plan = {
                "selected_paths": [],
                "rationale": "No vulnerabilities to prioritize.",
                "next_best_action": None,
            }
            state.execution_plan = {
                "next_actions": [],
                "max_requests_next_phase": 0,
                "stop_conditions": ["no_vulnerabilities"],
                "reasoning_confidence": 1.0,
                "skip_exploitation": True,
            }
            self._append_timeline_event(
                state,
                "reason",
                "No actionable vulnerabilities available for prioritization.",
                kind="decision",
                extra={"goal": state.campaign_goal},
            )
            return state

        complexity = self._get_complexity_details(vulnerable_results)
        decision_classes = {
            self._finding_decision_class(f) for f in decision_findings if isinstance(f, dict)
        }
        validation_only = bool(decision_findings) and decision_classes <= {"info"}
        if state.verbose:
            self._print_reasoning_context(state, complexity)

        if validation_only:
            state.metrics.deterministic_steps += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings, "Heuristic validation plan (informational findings only).", state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            nba = self._infer_next_best_action_from_execution_plan(state.execution_plan)
            if nba:
                nba["reason"] = self._action_reason_for_path(str(nba.get("path", "") or ""), state, decision_findings)
            state.llm_plan["next_best_action"] = nba or self._next_best_action_for_goal(state, decision_findings)
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "Informational findings only; using deterministic validation plan.",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            return state

        # Deterministic-first: if the decision is simple, keep it rule-based.
        if not complexity["is_complex"] and not state.llm_local:
            state.metrics.deterministic_steps += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings, "Heuristic plan (simple case).", state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            nba = self._infer_next_best_action_from_execution_plan(state.execution_plan)
            if nba:
                nba["reason"] = self._action_reason_for_path(str(nba.get("path", "") or ""), state, decision_findings)
            state.llm_plan["next_best_action"] = nba or self._next_best_action_for_goal(state, decision_findings)
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "Heuristic planner selected next actions (simple case).",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            if state.verbose:
                print_info("Decision source: heuristic (simple case, LLM skipped).")
            self._log_strategic_next_action(state)
            return state

        if not state.llm_local:
            state.metrics.deterministic_steps += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings, "Heuristic plan (LLM disabled).", state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            nba = self._infer_next_best_action_from_execution_plan(state.execution_plan)
            if nba:
                nba["reason"] = self._action_reason_for_path(str(nba.get("path", "") or ""), state, decision_findings)
            state.llm_plan["next_best_action"] = nba or self._next_best_action_for_goal(state, decision_findings)
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "Heuristic planner selected next actions (LLM disabled).",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            if state.verbose:
                print_info("Decision source: heuristic (complex case, LLM disabled).")
            self._log_strategic_next_action(state)
            return state

        print_status("Reasoning with local LLM...")
        state.metrics.llm_calls += 1
        redirect_observation = self._collect_redirect_observation(state)
        risk_signals_list = knowledge_base.get("risk_signals", []) or []
        auth_session = "authenticated_session" in [str(x).lower() for x in risk_signals_list]
        auth_context = self._get_active_auth_context(knowledge_base)
        auth_first = self._auth_first_mode(state)
        compressed_context = self._refresh_compressed_context_summary(state)
        prompt_payload = {
            "target": state.raw_target,
            "strategy": {
                "campaign_goal": state.campaign_goal,
                "auth_first_mode": auth_first,
            },
            "knowledge_context": {
                "compressed_summary": compressed_context,
                "tech_hints": knowledge_base.get("tech_hints", []),
                "specializations": knowledge_base.get("specializations", []),
                "risk_signals": risk_signals_list,
                "endpoint_count": len(knowledge_base.get("discovered_endpoints", [])),
                "parameter_count": len(knowledge_base.get("discovered_params", [])),
                "login_paths": knowledge_base.get("login_paths", [])[:10],
                "redirect_observation": redirect_observation,
                "module_catalog": {
                    "total_modules": knowledge_base.get("module_capability_catalog", {}).get("total_modules", 0),
                    "by_family": knowledge_base.get("module_capability_catalog", {}).get("by_family", {}),
                    "notable_modules": knowledge_base.get("module_capability_catalog", {}).get("notable_modules", [])[:80],
                },
            },
            "post_auth_context": {
                "authenticated_session": auth_session,
                "auth_milestone": knowledge_base.get("auth_milestone", {}),
                "credential_reuse_ready": bool(auth_context),
                "login_path": auth_context.get("login_path", ""),
                "landing_path": auth_context.get("final_path", ""),
                "has_session_cookie": bool((auth_context.get("cookies") or {})),
                "matched_catalog_paths_from_landing_html": knowledge_base.get("post_auth_catalog_paths", [])[:20],
                "landing_html_excerpt": (knowledge_base.get("authenticated_page_excerpt") or "")[:2500],
            },
            "potential_findings": [
                {
                    "path": item.get("path"),
                    "message": item.get("message"),
                    "severity": item.get("severity"),
                }
                for item in state.potential_findings[:20]
            ],
            "vulnerabilities": [
                {
                    "path": item.get("path"),
                    "module": item.get("module"),
                    "message": item.get("message"),
                    "severity": item.get("severity"),
                    "exploit_module": item.get("exploit_module"),
                    "context_score": item.get("context_score"),
                    "context_hints": item.get("context_hints", []),
                }
                for item in decision_findings
            ],
            "task": (
                (
                    "AUTH-FIRST MODE ACTIVE: login surface confirmed with known login_paths, no authenticated session, no CMS lock. "
                    "Put 'auxiliary/scanner/http/login/admin_login_bruteforce' as the FIRST run_followup (priority 1). "
                    "Do not allocate budget to spa_scanner, security_headers, sensitive_files, robots/crawler, or generic tech detection until auth is resolved or bruteforce is exhausted. "
                )
                if auth_first
                else ""
            )
            + (
                "Your job is to choose the BEST NEXT ACTION for this campaign goal (strategy.campaign_goal), "
                "not to rank vulnerabilities by curiosity. Prefer a single coherent run_followup or run_exploit as priority 1. "
                "Return strict JSON with keys: "
                "selected_paths (array, optional legacy hints), rationale (string), "
                "next_actions (array of objects: {type, path, priority, options}), "
                "max_requests_next_phase (int, keep this low, e.g. 2-4), stop_conditions (array), reasoning_confidence (0..1). "
                "If root response is a redirect (e.g. 301/302) or there is very little discovery surface, assume it is an authentication portal. "
                "In that case, explicitly prioritize 'auxiliary/scanner/http/login/admin_login_bruteforce' for bruteforcing instead of noisy or broad crawler fuzzing. "
                "If post_auth_context.authenticated_session is true, a credential milestone succeeded: use landing_html_excerpt only as evidence "
                "(infer stack from distinctive tokens and structure; do not invent a product unless the HTML supports it). "
                "When credential_reuse_ready is true, prefer authenticated follow-up or exploit paths and keep reusing the known login path/cookies instead of re-running login discovery. "
                "After a valid access, keep pushing toward a session/shell with grounded exploit paths before resuming any generic crawling. "
                "Prefer next_actions that align matched_catalog_paths_from_landing_html with run_followup/run_exploit when paths exist in the catalog. "
                "If matches are empty or low confidence, propose a short crawler pass then narrow XSS/SQLi/LFI only on parameters/endpoints that were actually observed. "
                "Avoid paths tied to outbound email, newsletters, ticketing, or mass messaging (irresponsible / noisy). "
                "Be methodical: one coherent hypothesis per phase, small request budgets."
            ),
        }

        llm_response = self._llm.query_local_llm(
            endpoint=state.llm_endpoint,
            model=state.llm_model,
            payload=prompt_payload,
            timeout=20,
        )

        if not llm_response:
            print_warning("Local LLM unavailable, using heuristic prioritization.")
            if state.verbose and self._llm.last_error:
                print_warning(f"Local LLM error detail: {self._llm.last_error}")
            state.metrics.llm_fallback_count += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings, "Heuristic plan (LLM request failed).", state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            nba = self._infer_next_best_action_from_execution_plan(state.execution_plan)
            if nba:
                nba["reason"] = self._action_reason_for_path(str(nba.get("path", "") or ""), state, decision_findings)
            state.llm_plan["next_best_action"] = nba or self._next_best_action_for_goal(state, decision_findings)
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "LLM unavailable; heuristic planner fallback applied.",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            if state.verbose:
                print_info("Decision source: heuristic (LLM failure fallback).")
            self._log_strategic_next_action(state)
            return state

        selected_paths = llm_response.get("selected_paths", [])
        if not isinstance(selected_paths, list):
            selected_paths = []

        state.llm_plan = {
            "selected_paths": [p for p in selected_paths if isinstance(p, str) and p.strip()],
            "rationale": str(llm_response.get("rationale", "LLM plan generated.")),
        }
        state.execution_plan = self._sanitize_execution_plan(
            llm_response,
            state,
            decision_findings,
        )
        state.execution_plan = self._apply_auth_first_execution_overrides(
            state, state.execution_plan, decision_findings,
        )
        nba = self._infer_next_best_action_from_execution_plan(state.execution_plan)
        if nba:
            nba["reason"] = self._action_reason_for_path(str(nba.get("path", "") or ""), state, decision_findings)
        state.llm_plan["next_best_action"] = nba or self._next_best_action_for_goal(state, decision_findings)
        if (
            not state.llm_plan.get("selected_paths")
            and not state.execution_plan.get("next_actions")
        ):
            state.metrics.llm_fallback_count += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings,
                "Heuristic plan (LLM returned no actionable selection).",
                state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            nba = self._infer_next_best_action_from_execution_plan(state.execution_plan)
            if nba:
                nba["reason"] = self._action_reason_for_path(str(nba.get("path", "") or ""), state, decision_findings)
            state.llm_plan["next_best_action"] = nba or self._next_best_action_for_goal(state, decision_findings)
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "LLM returned no actionable selection; heuristic planner fallback applied.",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            if state.verbose:
                print_info("Decision source: heuristic (LLM returned empty plan).")
            self._log_strategic_next_action(state)
            return state
        state.decision_source = "llm_local"
        self._print_decision_summary(state)
        self._append_timeline_event(
            state,
            "reason",
            "Local LLM produced the execution plan.",
            kind="decision",
            extra={"goal": state.campaign_goal, "source": state.decision_source},
        )
        if state.verbose:
            print_info("Decision source: local LLM (complex case).")
        self._log_strategic_next_action(state)
        return state

    def _is_complex_decision(self, vulnerable_results) -> bool:
        """
        Decide when LLM reasoning is worth the cost/latency.
        """
        vuln_count = len(vulnerable_results)
        if vuln_count >= 4:
            return True

        families = set()
        with_exploit = 0
        without_exploit = 0
        severities = set()

        for item in vulnerable_results:
            path = str(item.get("path", ""))
            parts = path.split("/")
            if len(parts) >= 2:
                families.add(parts[1])  # scanner family like http/cloud/ldap

            if item.get("exploit_module"):
                with_exploit += 1
            else:
                without_exploit += 1

            sev = str(item.get("severity", "")).strip().lower()
            if sev:
                severities.add(sev)

        # Multiple protocols/families means branching strategy.
        if len(families) >= 2:
            return True

        # Mixed exploitability often requires trade-off decisions.
        if with_exploit > 0 and without_exploit > 0:
            return True

        # Conflicting severity labels can benefit from model arbitration.
        if len(severities) >= 2:
            return True

        return False

    def _get_complexity_details(self, vulnerable_results) -> Dict[str, Any]:
        vuln_count = len(vulnerable_results)
        families = set()
        with_exploit = 0
        without_exploit = 0
        severities = set()

        for item in vulnerable_results:
            path = str(item.get("path", ""))
            parts = path.split("/")
            if len(parts) >= 2:
                families.add(parts[1])

            if item.get("exploit_module"):
                with_exploit += 1
            else:
                without_exploit += 1

            sev = str(item.get("severity", "")).strip().lower()
            if sev:
                severities.add(sev)

        reasons = []
        if vuln_count >= 4:
            reasons.append("many_findings")
        if len(families) >= 2:
            reasons.append("multi_families")
        if with_exploit > 0 and without_exploit > 0:
            reasons.append("mixed_exploitability")
        if len(severities) >= 2:
            reasons.append("mixed_severity")

        return {
            "is_complex": bool(reasons),
            "reasons": reasons,
            "vuln_count": vuln_count,
            "families": sorted(families),
            "with_exploit": with_exploit,
            "without_exploit": without_exploit,
            "severities": sorted(severities),
        }

    def _print_reasoning_context(self, state: AgentState, complexity: Dict[str, Any]) -> None:
        print_info("Reasoning context:")
        print_info(f"- Findings count: {complexity['vuln_count']}")
        print_info(f"- Families: {', '.join(complexity['families']) if complexity['families'] else 'none'}")
        print_info(
            f"- Exploitable vs non-exploitable: "
            f"{complexity['with_exploit']} / {complexity['without_exploit']}"
        )
        print_info(f"- Severity labels: {', '.join(complexity['severities']) if complexity['severities'] else 'none'}")
        if complexity["is_complex"]:
            print_info(f"- Decision complexity: complex ({', '.join(complexity['reasons'])})")
            if state.llm_local:
                print_info("- Plan mode: local LLM enabled")
            else:
                print_info("- Plan mode: deterministic only (LLM disabled)")
        else:
            print_info("- Decision complexity: simple")

    def _heuristic_plan(
        self,
        vulnerable_results,
        rationale: str,
        state: Optional[AgentState] = None,
    ) -> Dict[str, Any]:
        """
        Fast deterministic prioritization:
        1) entries with exploit module
        2) severity weight
        3) preserve scanner discovery order
        AUTH-FIRST: boost login-surface findings; demote generic recon modules (headers, spa, etc.).
        """
        severity_weight = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
        }
        decision_weight = {
            "exploit": 120,
            "followup": 55,
            "info": 0,
        }

        auth_first = bool(state and self._auth_first_mode(state))
        scored = []
        for idx, item in enumerate(vulnerable_results):
            has_exploit = 1 if item.get("exploit_module") else 0
            sev = str(item.get("severity", "")).strip().lower()
            sev_score = severity_weight.get(sev, 0)
            context_score = int(item.get("context_score", 0)) if isinstance(item, dict) else 0
            decision_class = self._finding_decision_class(item if isinstance(item, dict) else {})
            goal_bonus = 0
            if auth_first and isinstance(item, dict):
                path_l = str(item.get("path", "") or "").lower()
                if any(
                    t in path_l
                    for t in (
                        "login",
                        "admin_panel",
                        "simple_login",
                        "login_page",
                        "admin_login",
                    )
                ):
                    goal_bonus += 80
                if any(sub in path_l for sub in AUTH_FIRST_DEPRIORITIZE_SUBSTRINGS):
                    goal_bonus -= 60
            scored.append((
                decision_weight.get(decision_class, 0) + context_score + goal_bonus,
                has_exploit,
                sev_score,
                -idx,
                item,
            ))

        scored.sort(reverse=True)
        selected_paths = []
        for _, _, _, _, item in scored[:5]:
            path = item.get("path")
            if path:
                selected_paths.append(path)

        plan = {
            "selected_paths": selected_paths,
            "rationale": rationale,
        }
        if state is not None:
            plan["next_best_action"] = self._next_best_action_for_goal(state, vulnerable_results)
        else:
            plan["next_best_action"] = None
        return plan

    def _build_heuristic_execution_plan(self, state: AgentState, findings):
        selected_paths = state.llm_plan.get("selected_paths", [])
        if not selected_paths:
            selected_paths = [f.get("path") for f in findings[:3] if f.get("path")]
        allow_paths = set([str(f.get("path", "")) for f in findings if f.get("path")])
        potential_findings = state.potential_findings
        knowledge_base = state.knowledge_base
        auth_session = self._has_authenticated_session(knowledge_base)
        auth_surface = self._should_prioritize_auth_surface(knowledge_base)
        cms_lock = self._get_cms_lock_specializations(
            knowledge_base,
            state.scan_specializations,
        ).union(self._get_probable_cms_specializations(knowledge_base))
        max_requests = min(8, max(2, len(selected_paths) + 1))
        if auth_session:
            max_requests = min(10, max_requests + 2)
        elif auth_surface or cms_lock:
            # Enough budget for login bruteforce plus a couple of chained scanners (4 was too tight).
            max_requests = min(max_requests, 8)
        actions = []
        for idx, path in enumerate(selected_paths[:5], start=1):
            if path in allow_paths:
                actions.append({"type": "prioritize", "path": path, "priority": idx, "options": {}})

        bf_path = "auxiliary/scanner/http/login/admin_login_bruteforce"
        if self._login_surface_wants_bruteforce(knowledge_base, findings, auth_session):
            if not any(a.get("path") == bf_path for a in actions):
                actions.append({
                    "type": "run_followup",
                    "path": bf_path,
                    "priority": len(actions) + 1,
                    "options": {},
                })

        # Chain scanner-advertised follow-ups (e.g. admin_panel_detect -> admin_login_bruteforce)
        # for any vulnerable finding, not only when the parent path is in the top-N selected_paths.
        linked_followups = []
        for finding in findings[:16]:
            if not finding.get("vulnerable"):
                continue
            for linked_path in self._catalog.normalize_linked_module_paths(finding.get("linked_modules")):
                linked_followups.append(linked_path)

        prioritized_findings = [
            finding for finding in findings
            if str(finding.get("path", "")) in selected_paths
        ]
        has_grounded_priority = any(
            self._catalog.normalize_exploit_module_path(item.get("exploit_module"))
            or (
                isinstance(item.get("details", {}), dict)
                and (
                    item.get("details", {}).get("authenticated_as")
                    or item.get("details", {}).get("post_login_snippet")
                    or item.get("details", {}).get("post_login_final_url")
                )
            )
            or any(token in str(item.get("path", "")).lower() for token in (
                "admin_panel_detect",
                "simple_login_scanner",
                "login_page_detector",
                "admin_login_bruteforce",
            ))
            for item in prioritized_findings
        )

        # Redirect-first heuristic: if root is redirected and discovery is weak,
        # prioritize following redirect/login discovery before broad verification.
        redirect_followups = []
        if not cms_lock:
            redirect_followups = self._suggest_redirect_followups(state)
        base_priority = len(actions) + 1
        for offset, path in enumerate(redirect_followups, start=0):
            actions.append({
                "type": "run_followup",
                "path": path,
                "priority": base_priority + offset,
                "options": {},
            })
        if auth_surface and not auth_session:
            max_requests = min(max(10, max_requests), 12)

        base_priority = len(actions) + 1
        for offset, path in enumerate(linked_followups, start=0):
            if any(a.get("path") == path for a in actions):
                continue
            action_type = "run_exploit" if path.startswith(("exploit/", "exploits/")) else "run_followup"
            actions.append({
                "type": action_type,
                "path": path,
                "priority": base_priority + offset,
                "options": {},
            })

        post_auth_actions = self._suggest_post_auth_methodical_actions(state, knowledge_base, max_actions=6)
        if auth_session:
            base_priority = len(actions) + 1
            for offset, row in enumerate(post_auth_actions):
                path = row.get("path")
                if not path or any(a.get("path") == path for a in actions):
                    continue
                actions.append({
                    "type": row.get("type", "run_followup"),
                    "path": path,
                    "priority": base_priority + offset,
                    "options": row.get("options") or {},
                })
            if post_auth_actions:
                max_requests = min(28, max_requests + 6)

        # Heuristic manual verification follow-ups for "potential" findings.
        verification_candidates = self._suggest_verification_followups(
            potential_findings,
            knowledge_base,
            max_actions=4,
        )
        if not has_grounded_priority and not auth_surface:
            base_priority = len(actions) + 1
            for offset, path in enumerate(verification_candidates, start=0):
                if any(a.get("path") == path for a in actions):
                    continue
                actions.append({
                    "type": "run_followup",
                    "path": path,
                    "priority": base_priority + offset,
                    "options": {},
                })

        if not auth_session:
            base_priority = len(actions) + 1
            for offset, row in enumerate(post_auth_actions):
                path = row.get("path")
                if not path or any(a.get("path") == path for a in actions):
                    continue
                actions.append({
                    "type": row.get("type", "run_followup"),
                    "path": path,
                    "priority": base_priority + offset,
                    "options": row.get("options") or {},
                })
            if post_auth_actions:
                max_requests = min(28, max_requests + 6)

        actions = self._filter_previously_failed_plan_actions(actions, knowledge_base)
        for idx, row in enumerate(actions, start=1):
            row["priority"] = idx

        plan = {
            "next_actions": actions,
            "max_requests_next_phase": max_requests,
            "stop_conditions": ["stop_if_no_exploit_path"],
            "reasoning_confidence": 0.6,
            "skip_exploitation": False,
        }
        return self._apply_auth_first_execution_overrides(state, plan, findings)

    def _suggest_redirect_followups(self, state: AgentState, max_actions=3):
        kb = state.knowledge_base
        signals = set([str(s).lower() for s in kb.get("risk_signals", [])])
        endpoint_count = len(kb.get("discovered_endpoints", []))
        redirect_obs = self._collect_redirect_observation(state)

        root_status = int(redirect_obs.get("root_status") or 0)
        redirect_heavy = root_status in HTTP_REDIRECT_STATUSES or "http_status_302" in signals
        low_discovery = endpoint_count <= 1 or bool(redirect_obs.get("low_discovery"))

        if not (redirect_heavy and low_discovery):
            return []

        candidates = [
            "auxiliary/scanner/http/login/admin_login_bruteforce",
            "auxiliary/scanner/http/login_page_detector",
        ]
        return candidates[:max_actions]

    def _suggest_verification_followups(self, potential_findings, knowledge_base, max_actions=4):
        candidates = []
        hints = set([str(x).lower() for x in knowledge_base.get("tech_hints", [])])
        cms_lock = self._get_cms_lock_specializations(knowledge_base, hints)
        madara_link_present = any(
            "wordpress_madara_cve_2025_4524" in linked_path
            for finding in potential_findings
            for linked_path in self._catalog.normalize_linked_module_paths(finding.get("linked_modules"))
        )
        madara_positive = any(
            "scanner/http/wordpress_madara_cve_2025_4524" in str(finding.get("path", "")).lower()
            and finding.get("vulnerable")
            for finding in potential_findings
        )
        for finding in potential_findings:
            blob = " ".join([
                str(finding.get("path", "")),
                str(finding.get("module", "")),
                str(finding.get("message", "")),
            ]).lower()
            if "xxe" in blob and not cms_lock:
                candidates.append("auxiliary/scanner/http/xxe_scanner")
            if ("sql" in blob or "sqli" in blob) and not cms_lock:
                candidates.append("auxiliary/scanner/http/sql_injection")
            if "xss" in blob and not cms_lock:
                candidates.append("auxiliary/scanner/http/xss_scanner")
            if "lfi" in blob and not cms_lock:
                candidates.append("auxiliary/scanner/http/lfi_fuzzer")
            if "ssrf" in blob and not cms_lock:
                candidates.append("auxiliary/scanner/http/ssrf_scanner")
            if (
                ("api" in blob or "swagger" in blob or "graphql" in blob)
                and not cms_lock
                and (
                    self._has_tech_evidence(knowledge_base, "api", threshold=0.65)
                    or any(
                        token in str(endpoint).lower()
                        for endpoint in knowledge_base.get("discovered_endpoints", [])
                        for token in ("/api", "swagger", "graphql")
                    )
                )
            ):
                candidates.append("auxiliary/scanner/http/api_fuzzer")

        if "wordpress" in hints and self._has_tech_evidence(knowledge_base, "wordpress", threshold=0.65):
            candidates.extend([
                "auxiliary/scanner/http/wp_plugin_scanner",
                "auxiliary/scanner/http/wordpress_enum_user",
                "scanner/http/wordpress_detect",
            ])
            if (
                self._has_tech_evidence(knowledge_base, "wordpress", threshold=0.8)
                and (madara_link_present or madara_positive)
            ):
                candidates.append("auxiliary/scanner/http/wordpress_madara_cve_2025_4524_lfi")
        if "drupal" in hints and self._has_tech_evidence(knowledge_base, "drupal", threshold=0.65):
            candidates.append("auxiliary/scanner/http/drupal_scanner")
        if "joomla" in hints and self._has_tech_evidence(knowledge_base, "joomla", threshold=0.65):
            candidates.append("auxiliary/scanner/http/joomla_scanner")

        # Hard safety: if CMS lock is active, drop generic fuzzing modules from
        # follow-up verification actions even if suggested by model/heuristics.
        if cms_lock:
            candidates = [
                path for path in candidates
                if path and not any(token in path for token in (
                    "xss_scanner", "sql_injection", "lfi_fuzzer", "ssrf_scanner", "xxe_scanner", "api_fuzzer"
                ))
            ]

        unique = []
        seen = set()
        for path in candidates:
            if path in seen:
                continue
            unique.append(path)
            seen.add(path)
            if len(unique) >= max_actions:
                break
        return unique

    def _sanitize_execution_plan(self, llm_response, state: AgentState, findings):
        allowed_paths = set([str(f.get("path", "")) for f in findings if f.get("path")])
        allowed_paths |= set([
            self._catalog.normalize_exploit_module_path(f.get("exploit_module"))
            for f in findings
            if self._catalog.normalize_exploit_module_path(f.get("exploit_module"))
        ])
        for finding in findings:
            for linked_path in self._catalog.normalize_linked_module_paths(finding.get("linked_modules")):
                allowed_paths.add(linked_path)
        kb = state.knowledge_base
        observed = set([str(p) for p in kb.get("observed_modules", [])])
        allowed_paths |= observed
        catalog_paths = set([str(p) for p in kb.get("module_capability_catalog", {}).get("all_paths", [])])
        allowed_paths |= catalog_paths

        raw_actions = llm_response.get("next_actions", [])
        actions = []
        if isinstance(raw_actions, list):
            for row in raw_actions[:15]:
                if not isinstance(row, dict):
                    continue
                action_type = str(row.get("type", "")).strip().lower()
                path = str(row.get("path", "")).strip()
                priority = int(row.get("priority", 999)) if str(row.get("priority", "")).isdigit() else 999
                if not path or path not in allowed_paths:
                    continue
                if action_type not in SAFE_FOLLOWUP_ACTION_TYPES:
                    continue
                options = self._sanitize_action_options(row.get("options", {}))
                actions.append({
                    "type": action_type,
                    "path": path,
                    "priority": priority,
                    "options": options,
                })
        actions.sort(key=lambda a: a.get("priority", 999))
        actions = self._filter_previously_failed_plan_actions(actions, state.knowledge_base)
        for idx, row in enumerate(actions, start=1):
            row["priority"] = idx

        max_requests_raw = llm_response.get("max_requests_next_phase", 10)
        try:
            max_requests = int(max_requests_raw)
        except Exception:
            max_requests = 10
        kb = state.knowledge_base
        cms_lock = self._get_cms_lock_specializations(
            kb,
            state.scan_specializations,
        ).union(self._get_probable_cms_specializations(kb))
        upper_bound = max(8, min(12, int(state.max_modules or 40)))
        if self._has_authenticated_session(kb):
            upper_bound = max(upper_bound, 6)
        elif self._should_prioritize_auth_surface(kb) or cms_lock:
            # Login/CMS-tight phases still need room for bruteforce + chained scanners (4 was too low).
            upper_bound = min(upper_bound, 10)
        max_requests = max(2, min(max_requests, upper_bound))

        stop_conditions = llm_response.get("stop_conditions", [])
        if not isinstance(stop_conditions, list):
            stop_conditions = []
        stop_conditions = [str(x) for x in stop_conditions[:8]]

        confidence = llm_response.get("reasoning_confidence", 0.7)
        try:
            confidence = float(confidence)
        except Exception:
            confidence = 0.7
        confidence = max(0.0, min(confidence, 1.0))

        skip_exploitation = any(
            cond in ("no_exploit_paths", "stop_if_no_exploit_path")
            for cond in stop_conditions
        )
        return {
            "next_actions": actions,
            "max_requests_next_phase": max_requests,
            "stop_conditions": stop_conditions,
            "reasoning_confidence": confidence,
            "skip_exploitation": skip_exploitation,
        }

    def _sanitize_action_options(self, options):
        if not isinstance(options, dict):
            return {}
        safe = {}
        for key, value in list(options.items())[:12]:
            if not isinstance(key, str):
                continue
            key = key.strip()
            if not key or len(key) > 64:
                continue
            if isinstance(value, (bool, int, float)):
                safe[key] = value
            elif isinstance(value, str):
                safe[key] = value[:256]
        return safe

    def _extract_plan_option_maps(self, execution_plan):
        actions = execution_plan.get("next_actions", [])
        followup_options = {}
        exploit_options = {}
        explicit_exploit_paths = []
        if not isinstance(actions, list):
            return followup_options, exploit_options, explicit_exploit_paths
        for action in actions:
            if not isinstance(action, dict):
                continue
            action_type = action.get("type")
            path = str(action.get("path", "")).strip()
            options = self._sanitize_action_options(action.get("options", {}))
            if action_type == "run_followup" and path:
                followup_options[path] = options
            if action_type == "run_exploit" and path:
                exploit_options[path] = options
                explicit_exploit_paths.append(path)
        return followup_options, exploit_options, explicit_exploit_paths

    def _execute_plan_followups(self, state: AgentState, execution_plan: Dict[str, Any], option_overrides=None):
        """
        Execute safe follow-up scanner/auxiliary actions suggested by LLM plan.
        """
        option_overrides = option_overrides or {}
        actions = execution_plan.get("next_actions", [])
        if not isinstance(actions, list):
            return []

        def _priority_key(row):
            if not isinstance(row, dict):
                return 999
            p = row.get("priority", 999)
            try:
                return int(p)
            except Exception:
                return 999

        actions = sorted(actions, key=_priority_key)

        followup_paths = []
        for action in actions:
            if not isinstance(action, dict):
                continue
            if action.get("type") != "run_followup":
                continue
            path = str(action.get("path", "")).strip()
            if not path:
                continue
            ok_prefix = path.startswith("scanner/") or path.startswith("auxiliary/scanner/")
            if not ok_prefix and getattr(state, "expanded_surface", False):
                ok_prefix = self._is_expanded_surface_module_path(path) and path.startswith(
                    ("auxiliary/osint/", "auxiliary/aws/", "auxiliary/azure/", "auxiliary/gcp/")
                )
            if not ok_prefix:
                continue
            followup_paths.append(path)

        if not followup_paths:
            return []

        available = {
            m.get("path"): m
            for m in self._catalog.discover_campaign_modules(
                expanded=bool(getattr(state, "expanded_surface", False)),
            )
        }
        max_req = int(execution_plan.get("max_requests_next_phase", 10) or 10)
        budget = max(1, min(max_req, 10))

        selected_modules = []
        seen = set()
        for path in followup_paths:
            if path in seen:
                continue
            module_info = available.get(path)
            if module_info:
                selected_modules.append(module_info)
                seen.add(path)
            if len(selected_modules) >= budget:
                break

        if not selected_modules:
            return []

        observed_modules = {
            str(path).strip()
            for path in state.knowledge_base.get("observed_modules", [])
            if str(path).strip()
        }
        selected_modules = [
            module for module in selected_modules
            if str(module.get("path", "")).strip() not in observed_modules
        ]
        if not selected_modules:
            return []

        failed_action_keys = self._get_failed_action_keys(state.knowledge_base)
        if failed_action_keys:
            selected_modules = [
                module for module in selected_modules
                if not self._planner_action_keys(module.get("path", "")).intersection(failed_action_keys)
            ]
        if not selected_modules:
            return []

        # Enforce CMS lock even against LLM-proposed follow-ups.
        selected_modules = self._filter_modules_for_cms_lock(
            selected_modules,
            state.knowledge_base,
            state.scan_specializations,
        )
        selected_modules = self._prune_modules_for_primary_cms(
            selected_modules,
            state.knowledge_base,
        )
        if self._has_authenticated_session(state.knowledge_base):
            selected_modules = [
                module for module in selected_modules
                if not any(token in str(module.get("path", "")).lower() for token in (
                    "login_page_detector",
                    "admin_login_bruteforce",
                ))
            ]
        if not selected_modules:
            return []

        print_status(f"Execution plan follow-up: running {len(selected_modules)} module(s)")
        followup_results = self._execute_plan_modules_with_options(
            selected_modules,
            state,
            option_overrides=option_overrides,
            verbose=bool(state.verbose),
        )

        selected_paths = [m.get("path") for m in selected_modules if m.get("path")]
        failed_paths = set()
        for row in followup_results:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", "")).strip()
            if not path:
                continue
            status = str(row.get("status", "")).strip().lower()
            if status == "error":
                failed_paths.add(path)
                continue
            path_low = path.lower()
            if any(token in path_low for token in ("bruteforce", "login", "auth")) and not row.get("vulnerable"):
                failed_paths.add(path)
        self._remember_planner_actions(state.knowledge_base, selected_paths, failed_paths)
        followup_hints = self._extract_tech_hints(followup_results)
        self._update_knowledge_base_from_results(
            state.knowledge_base,
            followup_results,
            selected_paths,
            followup_hints,
            set(),
        )
        return followup_results

    def _execute_plan_modules_with_options(self, modules, state: AgentState, option_overrides=None, verbose=False):
        option_overrides = dict(option_overrides or {})
        for module_path, inferred in self._build_inferred_option_overrides(modules, state).items():
            merged = dict(inferred)
            merged.update(option_overrides.get(module_path, {}))
            option_overrides[module_path] = merged
        results = []
        target_info = state.target_info
        hostname = target_info.get("hostname")
        port = target_info.get("port")
        scheme = target_info.get("scheme")

        for module_info in modules:
            module_path = module_info.get("path")
            result = {
                "module": module_info.get("name", module_path),
                "path": module_path,
                "status": "error",
                "vulnerable": False,
                "message": "",
                "details": {},
            }
            announced_bruteforce = False
            if "admin_login_bruteforce" in str(module_path).lower():
                hinted_path = (
                    option_overrides.get(module_path, {}).get("path")
                    or option_overrides.get(module_path, {}).get("login_path")
                    or self._select_best_login_path(state.knowledge_base)
                    or "/admin/login"
                )
                print_status(f"Trying admin login bruteforce on {hinted_path}")
                announced_bruteforce = True
            set_thread_output_quiet(not verbose)
            try:
                module_instance = self.framework.module_loader.load_module(
                    module_path,
                    load_only=False,
                    framework=self.framework,
                )
                if not module_instance:
                    result["message"] = "Failed to load module"
                    results.append(result)
                    continue

                self._set_default_target_options(module_instance, hostname, port, scheme)
                self._seed_http_session_from_auth(module_instance, state)
                merged_options = dict(self._infer_auth_option_overrides(module_instance, module_path, state))
                merged_options.update(option_overrides.get(module_path, {}))
                self._apply_safe_module_options(module_instance, merged_options)

                run_result = module_instance.run()
                result["vulnerable"] = bool(run_result)
                result["status"] = "vulnerable" if result["vulnerable"] else "safe"

                module_meta = getattr(module_instance, "__info__", {}) or {}
                dynamic_info = getattr(module_instance, "vulnerability_info", {}) or {}
                result["message"] = dynamic_info.get("reason") or module_meta.get("description", "")
                result["severity"] = dynamic_info.get("severity") or module_meta.get("severity")
                exploit_path = self._catalog.normalize_exploit_module_path(module_meta.get("module"))
                if exploit_path:
                    result["exploit_module"] = exploit_path
                linked_modules = self._catalog.normalize_linked_module_paths(module_meta.get("modules"))
                if linked_modules:
                    result["linked_modules"] = linked_modules
                result["details"] = {
                    key: value for key, value in dynamic_info.items()
                    if key not in ("reason", "severity", "version")
                }
            except Exception as exc:
                result["message"] = f"Error: {exc}"
            finally:
                set_thread_output_quiet(False)
            results.append(result)
            if announced_bruteforce and not verbose and result.get("message"):
                print_info(f"Bruteforce result: {result.get('message')}")
            if verbose:
                icon = "[+]" if result["vulnerable"] else "[-]"
                print_info(f"{icon} {result['path']}: {result.get('message', '')}")
        return results

    def _set_default_target_options(self, module_instance, hostname, port, scheme):
        if hasattr(module_instance, "target"):
            module_instance.set_option("target", hostname)
        elif hasattr(module_instance, "rhost"):
            module_instance.set_option("rhost", hostname)
        elif hasattr(module_instance, "rhosts"):
            module_instance.set_option("rhosts", hostname)

        if hasattr(module_instance, "port"):
            module_instance.set_option("port", port)
        elif hasattr(module_instance, "rport"):
            module_instance.set_option("rport", port)

        if hasattr(module_instance, "ssl"):
            module_instance.set_option("ssl", (scheme == "https"))

        # Reverse payloads/listeners often default to 127.0.0.1. When agent mode
        # attacks a remote target, prefer a routable local IP unless user/plan
        # already provided an explicit lhost override.
        if hasattr(module_instance, "lhost"):
            try:
                current_lhost = str(getattr(module_instance, "lhost", "") or "").strip()
            except Exception:
                current_lhost = ""
            if self._is_loopback_or_unspecified_host(current_lhost):
                resolved_lhost = ""
                if self._is_loopback_or_unspecified_host(hostname):
                    resolved_lhost = self._resolve_docker_gateway_lhost(hostname, port)
                if not resolved_lhost:
                    resolved_lhost = self._resolve_routable_lhost(hostname)
                if resolved_lhost:
                    module_instance.set_option("lhost", resolved_lhost)

    def _is_loopback_or_unspecified_host(self, value: str) -> bool:
        raw = str(value or "").strip().lower()
        if not raw:
            return True
        if raw in {"localhost", "::1", "0.0.0.0", "::"}:
            return True
        return raw.startswith("127.")

    def _resolve_routable_lhost(self, target_host: Any) -> str:
        target = str(target_host or "").strip()
        if not target:
            return ""
        if self._is_loopback_or_unspecified_host(target):
            # Local targets can legitimately use loopback callbacks.
            return ""

        # Infer the outbound interface used to reach the target.
        for probe_host, probe_port in ((target, 80), ("8.8.8.8", 53)):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.connect((probe_host, int(probe_port)))
                local_ip = str(sock.getsockname()[0] or "").strip()
                sock.close()
            except Exception:
                local_ip = ""
            if local_ip and not self._is_loopback_or_unspecified_host(local_ip):
                return local_ip
        return ""

    def _resolve_docker_gateway_lhost(self, target_host: Any, target_port: Any) -> str:
        target = str(target_host or "").strip()
        if not self._is_loopback_or_unspecified_host(target):
            return ""

        try:
            port = int(target_port)
        except Exception:
            return ""

        try:
            import docker  # type: ignore
        except Exception:
            return ""

        try:
            client = docker.from_env()
            containers = client.containers.list()
        except Exception:
            return ""

        for container in containers:
            try:
                container.reload()
                ports = container.attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
            except Exception:
                continue

            matched_binding = False
            for _container_port, bindings in ports.items():
                if not bindings:
                    continue
                for binding in bindings:
                    if not isinstance(binding, dict):
                        continue
                    host_port = str(binding.get("HostPort") or "").strip()
                    host_ip = str(binding.get("HostIp") or "").strip()
                    if host_port != str(port):
                        continue
                    if host_ip in ("", "0.0.0.0", "::", "127.0.0.1", "::1", "localhost"):
                        matched_binding = True
                        break
                if matched_binding:
                    break

            if not matched_binding:
                continue

            try:
                networks = container.attrs.get("NetworkSettings", {}).get("Networks", {}) or {}
            except Exception:
                networks = {}

            for _network_name, network in networks.items():
                if not isinstance(network, dict):
                    continue
                gateway = str(network.get("Gateway") or "").strip()
                if gateway and not self._is_loopback_or_unspecified_host(gateway):
                    return gateway

        return ""

    def _reverse_callback_diagnostic(self, module_instance, target_info: Optional[Dict[str, Any]]) -> str:
        if getattr(module_instance, "payload_type", None) != "reverse":
            return ""
        if not hasattr(module_instance, "lhost"):
            return ""

        try:
            lhost = str(getattr(module_instance, "lhost", "") or "").strip()
        except Exception:
            lhost = ""
        if not self._is_loopback_or_unspecified_host(lhost):
            return ""

        info = target_info or {}
        scheme = str(info.get("scheme", "http") or "http").strip().lower()
        hostname = str(info.get("hostname", "") or "").strip()
        port = info.get("port")
        port_label = ""
        if port not in (None, ""):
            port_label = f":{port}"
        target_label = f"{scheme}://{hostname}{port_label}" if hostname else "the current target"

        return (
            "Reverse payload still points to a loopback lhost "
            f"({lhost or '127.0.0.1'}) for {target_label}. "
            "If the service is exposed from Docker, WSL, a VM, or another network namespace, "
            "the callback will loop back inside the target instead of reaching Kittysploit."
        )

    def _apply_safe_module_options(self, module_instance, options):
        if not isinstance(options, dict):
            return
        for key, value in options.items():
            if not hasattr(module_instance, key):
                continue
            try:
                module_instance.set_option(key, value)
            except Exception:
                continue

    def _safe_option_value(self, module_instance, option_name: str) -> Any:
        if not hasattr(module_instance, option_name):
            return None
        if option_name == "payload":
            try:
                option_descriptor = getattr(type(module_instance), option_name, None)
                if option_descriptor and hasattr(option_descriptor, "to_dict"):
                    payload_info = option_descriptor.to_dict(module_instance)
                    return payload_info.get("display_value") or payload_info.get("value")
            except Exception:
                return None
        try:
            value = getattr(module_instance, option_name)
        except Exception:
            return None
        text = str(value or "")
        if option_name.lower() in ("password", "pass", "passwd", "token", "api_key", "apikey"):
            return "***" if text else ""
        return value

    def _module_runtime_option_snapshot(self, module_instance) -> Dict[str, Any]:
        keys = (
            "target",
            "rhost",
            "rhosts",
            "port",
            "rport",
            "ssl",
            "path",
            "base_path",
            "payload",
            "lhost",
            "lport",
            "username",
            "password",
        )
        snap: Dict[str, Any] = {}
        for key in keys:
            value = self._safe_option_value(module_instance, key)
            if value is None:
                continue
            snap[key] = value
        return snap

    def _execute_exploit_results_with_options(
        self,
        selected_results,
        target_info,
        state=None,
        exploit_option_overrides=None,
        explicit_exploit_paths=None,
        verbose=False,
    ):
        exploit_option_overrides = exploit_option_overrides or {}
        explicit_exploit_paths = explicit_exploit_paths or []
        hostname = target_info.get("hostname")
        port = target_info.get("port")
        scheme = target_info.get("scheme")

        exploit_paths = set([
            self._catalog.normalize_exploit_module_path(r.get("exploit_module"))
            for r in selected_results
            if self._catalog.normalize_exploit_module_path(r.get("exploit_module"))
        ])
        exploit_paths.update([
            p for p in explicit_exploit_paths
            if p and (p.startswith("exploit/") or p.startswith("exploits/"))
        ])
        if not exploit_paths:
            return

        print_status("Exploiting...")
        failed_paths = set()
        attempted_paths = set()
        for exploit_path in sorted(exploit_paths):
            attempted_paths.add(exploit_path)
            try:
                set_thread_output_quiet(not verbose)
                exploit_instance = self.framework.module_loader.load_module(
                    exploit_path,
                    load_only=False,
                    framework=self.framework,
                )
                if not exploit_instance:
                    failed_paths.add(exploit_path)
                    continue
                self._set_default_target_options(exploit_instance, hostname, port, scheme)
                inferred_auth = {}
                if isinstance(state, AgentState):
                    self._seed_http_session_from_auth(exploit_instance, state)
                    inferred_auth = self._infer_auth_option_overrides(
                        exploit_instance, exploit_path, state
                    )
                    auth_context = self._get_active_auth_context(state.knowledge_base)
                    login_candidates = [
                        str(path) for path in state.knowledge_base.get("login_paths", [])
                        if isinstance(path, str) and path.startswith("/")
                    ][:6]
                    selected_login_path = (
                        str(auth_context.get("login_path") or "").strip()
                        or self._select_best_login_path(state.knowledge_base)
                    )
                    selected_final_path = str(auth_context.get("final_path") or "").strip()
                    set_thread_output_quiet(False)
                    print_info(
                        f"Exploit auth inference [{exploit_path}]: "
                        f"active_auth={bool(auth_context)} "
                        f"selected_login_path={selected_login_path or '-'} "
                        f"selected_final_path={selected_final_path or '-'} "
                        f"login_candidates={login_candidates}"
                    )
                    print_info(
                        f"Exploit inferred overrides [{exploit_path}]: "
                        f"{inferred_auth if inferred_auth else 'none'}"
                    )
                    set_thread_output_quiet(not verbose)
                merged_options = dict(inferred_auth)
                merged_options.update(exploit_option_overrides.get(exploit_path, {}))
                self._apply_safe_module_options(
                    exploit_instance, merged_options
                )
                runtime_snapshot = self._module_runtime_option_snapshot(exploit_instance)
                if runtime_snapshot:
                    set_thread_output_quiet(False)
                    print_info(
                        f"Exploit runtime options [{exploit_path}]: {runtime_snapshot}"
                    )
                    set_thread_output_quiet(not verbose)
                sessions_before = set()
                browser_before = set()
                if hasattr(self.framework, "session_manager"):
                    sessions_before = set(self.framework.session_manager.sessions.keys())
                    browser_before = set(self.framework.session_manager.browser_sessions.keys())
                self.framework.current_module = exploit_instance
                # Important: exploit modules must go through ``_exploit()`` so payload
                # handling can start the correct listener/handler before ``run()``.
                if hasattr(exploit_instance, "_exploit"):
                    success = exploit_instance._exploit()
                else:
                    success = self.framework.execute_module()
                sessions_after = set()
                browser_after = set()
                if hasattr(self.framework, "session_manager"):
                    sessions_after = set(self.framework.session_manager.sessions.keys())
                    browser_after = set(self.framework.session_manager.browser_sessions.keys())
                new_standard = sorted(sessions_after - sessions_before)
                new_browser = sorted(browser_after - browser_before)
                reverse_callback_missing = False
                set_thread_output_quiet(False)
                if new_standard or new_browser:
                    print_info(
                        f"Exploit session delta [{exploit_path}]: "
                        f"standard+={new_standard}, browser+={new_browser}"
                    )
                else:
                    print_info(
                        f"Exploit session delta [{exploit_path}]: no new session "
                        f"(standard={len(sessions_after)}, browser={len(browser_after)})"
                    )
                    reverse_listener_timeout = (
                        getattr(exploit_instance, "payload_type", None) == "reverse"
                        and not bool(getattr(exploit_instance, "_session_received", False))
                    )
                    if reverse_listener_timeout:
                        listener_connections = 0
                        active_listener = getattr(exploit_instance, "active_listener", None)
                        if active_listener is not None and hasattr(active_listener, "connections"):
                            try:
                                listener_connections = len(active_listener.connections)
                            except Exception:
                                listener_connections = 0
                        print_warning(
                            f"Exploit reverse callback not observed [{exploit_path}] "
                            f"(listener_connections={listener_connections})"
                        )
                        diagnostic = self._reverse_callback_diagnostic(
                            exploit_instance,
                            target_info,
                        )
                        if diagnostic:
                            print_warning(diagnostic)
                        reverse_callback_missing = True
                set_thread_output_quiet(False)
                if success and reverse_callback_missing:
                    failed_paths.add(exploit_path)
                    print_warning(
                        f"Exploit completed but no reverse session was established: {exploit_path}"
                    )
                elif success:
                    print_success(f"Exploit succeeded: {exploit_path}")
                else:
                    failed_paths.add(exploit_path)
                    print_warning(f"Exploit failed: {exploit_path}")
            except Exception as exc:
                failed_paths.add(exploit_path)
                set_thread_output_quiet(False)
                print_warning(f"Error launching {exploit_path}: {exc}")
            finally:
                set_thread_output_quiet(False)
        if isinstance(state, AgentState):
            self._remember_planner_actions(state.knowledge_base, attempted_paths, failed_paths)

    def _node_exploit(self, state: AgentState) -> AgentState:
        state.metrics.deterministic_steps += 1
        if state.target_reachable is False:
            print_info("Exploitation skipped: target unreachable.")
            state.new_sessions = []
            self._append_timeline_event(
                state,
                "exploit",
                "Exploitation skipped because target is unreachable.",
                kind="execution",
            )
            return state
        shell_stop = self._has_shell_milestone(state)
        if shell_stop:
            self._sync_campaign_goal(state)
            if state.verbose:
                print_info("Strategic stop: shell or interactive session; skipping follow-ups and exploit launches.")

        if not shell_stop and not state.no_exploit and state.vulnerable_results:
            decision_source = state.decision_source
            execution_plan = state.execution_plan or {}
            followup_options, exploit_options, explicit_exploit_paths = self._extract_plan_option_maps(
                execution_plan
            )
            next_best_action = (state.llm_plan or {}).get("next_best_action", {})
            if isinstance(next_best_action, dict):
                nba_type = str(next_best_action.get("type", "")).strip().lower()
                nba_path = str(next_best_action.get("path", "")).strip()
                if nba_type == "run_exploit" and nba_path:
                    normalized_nba = self._catalog.normalize_exploit_module_path(nba_path)
                    if normalized_nba and normalized_nba not in explicit_exploit_paths:
                        explicit_exploit_paths.append(normalized_nba)

            # Execute LLM-proposed follow-up scanner actions before exploitation.
            followup_results = self._execute_plan_followups(
                state,
                execution_plan,
                option_overrides=followup_options,
            )
            if followup_results:
                state.results.extend(followup_results)
                state.vulnerable_results = [
                    r for r in state.results
                    if self._is_actionable_finding(r)
                ]
                state.contextual_findings = self._build_contextual_findings(
                    state.vulnerable_results,
                    state.knowledge_base,
                )

            # Follow-ups may have just obtained a session (e.g. bruteforce); run post-auth scanners once.
            if self._has_authenticated_session(state.knowledge_base):
                post_rows = self._suggest_post_auth_methodical_actions(
                    state, state.knowledge_base, max_actions=6
                )
                if post_rows:
                    post_plan = {
                        "next_actions": post_rows,
                        "max_requests_next_phase": min(12, max(6, len(post_rows) + 2)),
                    }
                    post_followups = self._execute_plan_followups(
                        state,
                        post_plan,
                        option_overrides={},
                    )
                    if post_followups:
                        state.results.extend(post_followups)
                        state.vulnerable_results = [
                            r for r in state.results
                            if self._is_actionable_finding(r)
                        ]
                        state.contextual_findings = self._build_contextual_findings(
                            state.vulnerable_results,
                            state.knowledge_base,
                        )

            selected_paths = state.llm_plan.get("selected_paths", [])
            selected_set = set(selected_paths)
            contextual_findings = state.contextual_findings or state.vulnerable_results
            selected_results = list(contextual_findings)
            plan_actions = execution_plan.get("next_actions", [])
            plan_paths = [
                action.get("path") for action in plan_actions
                if isinstance(action, dict) and action.get("type") in ("prioritize", "run_followup", "run_exploit")
            ]
            if plan_paths:
                selected_set.update([p for p in plan_paths if p])

            if selected_set:
                prioritized = [
                    r for r in contextual_findings
                    if r.get("path") in selected_set and r.get("vulnerable")
                ]
                if prioritized:
                    selected_results = prioritized

            exploit_candidates = [
                r for r in selected_results
                if str(r.get("decision_class", self._finding_decision_class(r))) == "exploit"
            ]
            followup_candidates = [
                r for r in selected_results
                if str(r.get("decision_class", self._finding_decision_class(r))) == "followup"
            ]
            info_candidates = [
                r for r in selected_results
                if str(r.get("decision_class", self._finding_decision_class(r))) == "info"
            ]

            if selected_results:
                source_label = "LLM" if decision_source == "llm_local" else "Heuristic plan"
                if exploit_candidates:
                    print_info(
                        f"{source_label} selected {len(exploit_candidates)} exploitation candidate(s) "
                        f"from {len(selected_results)} prioritized finding(s)."
                    )
                elif followup_candidates:
                    print_info(
                        f"{source_label} found no direct exploit path. "
                        f"{len(followup_candidates)} finding(s) require follow-up validation."
                    )
                elif info_candidates:
                    print_info(
                        f"{source_label} retained only informational findings "
                        f"({len(info_candidates)}); exploitation skipped."
                    )

            max_req = execution_plan.get("max_requests_next_phase", 0)
            if isinstance(max_req, int) and max_req > 0 and len(selected_results) > max_req:
                selected_results = selected_results[:max_req]

            if execution_plan.get("skip_exploitation"):
                exploit_paths = [r for r in selected_results if r.get("exploit_module")]
                if not exploit_paths:
                    print_info("Execution plan requested exploit skip (no exploitable paths).")
                    selected_results = []

            rationale = state.llm_plan.get("rationale")
            if rationale:
                rationale_label = "LLM" if decision_source == "llm_local" else "Plan"
                print_info(f"{rationale_label} rationale: {rationale}")

            selected_results = [
                r for r in selected_results
                if str(r.get("decision_class", self._finding_decision_class(r))) == "exploit"
            ]

            self._append_timeline_event(
                state,
                "exploit",
                (
                    f"Execution stage prepared {len(selected_results)} exploit candidate(s), "
                    f"{len(followup_candidates)} follow-up candidate(s), "
                    f"{len(info_candidates)} informational candidate(s)."
                ),
                kind="execution",
                results=selected_results or followup_candidates or info_candidates,
            )

            if selected_results or explicit_exploit_paths:
                self._execute_exploit_results_with_options(
                    selected_results,
                    state.target_info,
                    state=state,
                    exploit_option_overrides=exploit_options,
                    explicit_exploit_paths=explicit_exploit_paths,
                    verbose=bool(state.verbose),
                )
            else:
                print_info("No exploitable module selected by execution plan.")
        elif state.no_exploit:
            print_info("Exploitation skipped (--no-exploit).")

        sessions_before = state.sessions_before
        current_standard_sessions = set(self.framework.session_manager.sessions.keys())
        current_browser_sessions = set(self.framework.session_manager.browser_sessions.keys())
        new_standard = sorted(current_standard_sessions - sessions_before["standard"])
        new_browser = sorted(current_browser_sessions - sessions_before["browser"])
        new_sessions = new_standard + new_browser
        state.new_sessions = new_sessions

        if new_sessions:
            print_success("Got shell")
        else:
            print_warning("No new shell/session detected")
        self._append_timeline_event(
            state,
            "exploit",
            f"Execution finished with {len(new_sessions)} new session(s).",
            kind="execution",
            extra={"new_sessions": list(new_sessions)},
        )
        return state

    def _node_report(self, state: AgentState) -> AgentState:
        state.metrics.deterministic_steps += 1
        print_status("Generating report...")
        self._append_timeline_event(
            state,
            "report",
            "Generating Markdown and JSON campaign reports.",
            kind="report",
        )
        state.report_path = self._report.generate_report(
            state.raw_target,
            state.target_info,
            state.results,
            state.sql_findings,
            state.new_sessions,
            state.llm_plan,
            state.knowledge_base,
            state.execution_plan,
            state.contextual_findings,
            state.decision_timeline,
        )
        self._report.update_history_scores(
            state.contextual_findings,
            state.new_sessions,
        )
        self._update_host_profile_cache(state)
        self._print_timeline_preview(state)
        return state

    def _print_scoreboard(self, state: AgentState) -> None:
        metrics = state.metrics
        deterministic_steps = int(metrics.deterministic_steps)
        llm_calls = int(metrics.llm_calls)
        llm_fallback_count = int(metrics.llm_fallback_count)
        total = deterministic_steps + llm_calls
        det_ratio = 100.0 if total == 0 else (deterministic_steps / total) * 100.0
        llm_ratio = 0.0 if total == 0 else (llm_calls / total) * 100.0

        print_info("Agent Decision Scoreboard:")
        print_info(f"- deterministic_steps: {deterministic_steps}")
        print_info(f"- llm_calls: {llm_calls}")
        print_info(f"- llm_fallback_count: {llm_fallback_count}")
        print_info(f"- deterministic_ratio: {det_ratio:.1f}%")
        print_info(f"- llm_ratio: {llm_ratio:.1f}%")
