#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Safety profile, request budget, WAF pause, and campaign stop gates."""

from interfaces.command_system.builtin.agent.workflow.imports import *  # noqa: F403


class RuntimeGateMixin:
    """Safety profile, request budget, WAF pause, and campaign stop gates."""

    def _normalized_safety_profile(self, state: AgentState) -> str:
        profile = str(getattr(state, "safety_profile", "normal") or "normal").strip().lower()
        if profile not in {"safe", "discreet", "normal", "aggressive"}:
            return "normal"
        return profile

    def _discreet_mode(self, state: AgentState) -> bool:
        return self._normalized_safety_profile(state) == "discreet"

    def _request_budget_remaining(self, state: AgentState) -> Optional[int]:
        budget = getattr(state, "network_budget", None)
        if budget is not None and budget.bounded:
            return budget.remaining
        try:
            limit = int(getattr(state, "request_budget", 0) or 0)
        except Exception:
            limit = 0
        if limit <= 0:
            return None
        used = int(getattr(state.metrics, "network_units_used", 0) or 0)
        return max(0, limit - used)

    def _consume_network_units(
        self,
        state: AgentState,
        units: int = 1,
        *,
        reason: str = "non-HTTP agent network operation",
        module: Any = None,
        module_path: str = "",
    ) -> bool:
        if module is not None or module_path:
            units = module_budget_units(module if module is not None else {"path": module_path}, module_path, units)
        return try_consume_budget(
            state,
            units,
            reason=reason,
            phase=state.current_phase,
        )

    @staticmethod
    def _module_uses_http_client(module: Any) -> bool:
        return AgentModuleRunner.module_uses_http_client(module)

    def _budget_skip_result(self, module: Dict[str, Any], phase_name: str) -> Dict[str, Any]:
        return self._module_runner.budget_skip_result(module, phase_name)

    def _limit_modules_by_request_budget(
        self,
        state: AgentState,
        modules: List[Dict[str, Any]],
        phase_name: str,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        return self._module_runner.limit_modules_by_request_budget(state, modules, phase_name)

    def _module_block_reason_for_profile(
        self,
        state: AgentState,
        module_path: Any,
        module_info: Optional[Dict[str, Any]] = None,
    ) -> str:
        path = str(module_path or "")
        info = module_info if isinstance(module_info, dict) else {}
        if not info:
            try:
                info = dict(self._catalog._get_module_catalog().get(path) or {})
            except Exception:
                info = {}
        policy = getattr(state, "runtime_policy", None)
        if policy is None:
            return ""
        block = evaluate_module_catalog_policy(
            policy,
            info or {"path": path},
            path,
            phase=str(getattr(state, "current_phase", "") or "catalog"),
            knowledge_base=state.knowledge_base if isinstance(state.knowledge_base, dict) else {},
        )
        if block is not None:
            return block.reason
        return ""

    def _remember_policy_rejection(
        self,
        state: AgentState,
        module_path: str,
        reason: str,
        *,
        phase: str = "catalog",
        module_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not reason or not isinstance(getattr(state, "knowledge_base", None), dict):
            return
        path = str(module_path or "").strip()
        if not path:
            return
        risk = assess_module_risk(module_info or {"path": path}, path)
        kb = state.knowledge_base
        rows = list(kb.get("policy_rejections") or [])
        row = {
            "phase": str(phase or getattr(state, "current_phase", "") or "catalog"),
            "path": path,
            "risk": risk.level,
            "reason": str(reason)[:260],
            "mission_profile": str(getattr(getattr(state, "runtime_policy", None), "mission_profile", "") or ""),
            "safety_profile": self._normalized_safety_profile(state),
        }
        key = (row["phase"], row["path"], row["reason"])
        existing = {
            (str(item.get("phase", "")), str(item.get("path", "")), str(item.get("reason", "")))
            for item in rows
            if isinstance(item, dict)
        }
        if key not in existing:
            rows.append(row)
        kb["policy_rejections"] = rows[-80:]

    def _filter_modules_for_safety_profile(
        self,
        state: AgentState,
        modules: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        allowed: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        for module in modules or []:
            path = module.get("path") if isinstance(module, dict) else ""
            reason = self._module_block_reason_for_profile(state, path, module)
            if reason:
                self._remember_policy_rejection(
                    state,
                    str(path or ""),
                    reason,
                    phase="catalog",
                    module_info=module if isinstance(module, dict) else None,
                )
                skipped.append({
                    "module": module.get("name", path) if isinstance(module, dict) else str(path),
                    "path": path,
                    "status": "skipped",
                    "vulnerable": False,
                    "message": reason,
                    "details": {"safety_profile": self._normalized_safety_profile(state)},
                })
                continue
            stack_reason = self._module_hard_stack_skip_reason(str(path or ""), kb)
            if stack_reason:
                skipped.append({
                    "module": module.get("name", path) if isinstance(module, dict) else str(path),
                    "path": path,
                    "status": "skipped",
                    "vulnerable": False,
                    "message": stack_reason,
                    "details": {"reason": "stack_mismatch"},
                })
                continue
            allowed.append(module)
        if skipped and getattr(state, "verbose", False):
            print_warning(f"Safety/stack profile skipped {len(skipped)} module(s)")
        return allowed, skipped

    def _abort_module_batch_early(
        self,
        state: AgentState,
        results: List[Any],
        phase_name: str,
    ) -> bool:
        """
        True when remaining modules in this wave should be skipped (goal already met).

        Lightweight: folds positive auth/shell evidence into the KB, then checks milestones.
        """
        if not results:
            return False
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else None
        if kb is None:
            return False
        risk = {str(x).lower() for x in (kb.get("risk_signals") or [])}
        blob = " ".join(
            f"{row.get('message', '')} {row.get('details', '')} {row.get('path', '')}".lower()
            for row in results
            if isinstance(row, dict)
        )
        added = False
        if any(tok in blob for tok in ("authenticated as", "valid credentials", "session cookie", "login success")):
            if "credentials_obtained" not in risk:
                risk.add("credentials_obtained")
                added = True
            if "authenticated" in blob or "session" in blob:
                if "authenticated_session" not in risk:
                    risk.add("authenticated_session")
                    added = True
        if any(tok in blob for tok in ("interactive shell", "meterpreter", "shell opened", "got a shell")):
            if "shell_obtained" not in risk:
                risk.add("shell_obtained")
                added = True
        if added:
            kb["risk_signals"] = sorted(risk)

        operator = self._operator_campaign_goal(state)
        if is_auth_operator_goal(operator) and self._credential_milestone_reached(kb):
            state.campaign_stop_reason = (
                f"{phase_name}: auth milestone reached — goal obtain-auth complete"
            )
            return True
        if (
            is_shell_operator_goal(operator) or bool(getattr(state, "shell_hunter", False))
        ) and self._has_shell_milestone(state):
            state.campaign_stop_reason = f"{phase_name}: shell_obtained"
            return True
        if self._has_shell_milestone(state) and not is_shell_operator_goal(operator):
            # Shell is a terminal win even for non-shell goals.
            state.campaign_stop_reason = f"{phase_name}: shell_obtained"
            return True
        return False

    def _filter_catalog_candidates_for_policy(
        self,
        state: AgentState,
        modules: List[Dict[str, Any]],
        *,
        phase: str = "catalog",
    ) -> List[Dict[str, Any]]:
        if not modules:
            return []
        allowed: List[Dict[str, Any]] = []
        for module in modules:
            if not isinstance(module, dict):
                continue
            path = str(module.get("path", "") or "").strip()
            reason = self._module_block_reason_for_profile(state, path, module)
            if reason:
                self._remember_policy_rejection(
                    state,
                    path,
                    reason,
                    phase=phase,
                    module_info=module,
                )
                continue
            allowed.append(module)
        return allowed

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
        if self._discreet_mode(state):
            state.request_delay_min = max(delay_min, 5.0)
            state.request_delay_max = max(delay_max, 15.0)
        else:
            state.request_delay_min = max(delay_min, 2.0)
            state.request_delay_max = max(delay_max, 6.0)
        if getattr(state, "verbose", False):
            print_warning("Rate limit signal detected; increasing agent delay window")

    def _result_waf_signal(self, result: Any) -> bool:
        return is_actionable_waf_signal(result)

    def _should_pause_campaign_for_waf(self, state: AgentState) -> bool:
        if self._normalized_safety_profile(state) == "aggressive":
            return False
        if approved_to_continue_through_waf(state):
            return False
        return True

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
        threshold = 1 if self._normalized_safety_profile(state) in ("safe", "discreet") else 3
        if int(kb.get("waf_signal_count", 0) or 0) < threshold:
            return False

        delay_min, delay_max = self._action_delay_bounds(state)
        state.request_delay_min = max(delay_min, 5.0)
        state.request_delay_max = max(delay_max, 15.0)

        if not self._should_pause_campaign_for_waf(state):
            if getattr(state, "verbose", False) or approved_to_continue_through_waf(state):
                print_warning(
                    f"{phase_name}: WAF/CDN signals detected ({len(signals)}); "
                    "continuing with throttling (--approve-risk intrusive)"
                )
            return False

        state.campaign_stop_reason = (
            f"{phase_name}: blocking/WAF signals detected; pausing campaign to avoid target overload"
        )
        if getattr(state, "verbose", False):
            print_warning(state.campaign_stop_reason)
        return True

    def _shell_sensitive_probes_allowed(self, state: AgentState) -> bool:
        """True when shell-tier probe paths (/.env, /phpinfo, …) are explicitly approved."""
        shell_mode = (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or bool(getattr(state, "shell_hunter", False))
        )
        if not shell_mode:
            return False
        policy = getattr(state, "runtime_policy", None)
        if policy is None:
            return False
        from interfaces.command_system.builtin.agent.runtime_policy import ModuleRisk

        risk = ModuleRisk(
            "intrusive",
            ("active_exploitation",),
            1,
            False,
            True,
            False,
            "shell-tier active web probes",
        )
        return bool(policy.risk_approved(risk))

    def _filter_plan_actions_for_policy(
        self,
        state: AgentState,
        actions: List[Dict[str, Any]],
        *,
        phase: str = "plan",
    ) -> List[Dict[str, Any]]:
        filtered: List[Dict[str, Any]] = []
        for row in actions or []:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", "") or "").strip()
            if not path:
                filtered.append(row)
                continue
            reason = self._module_block_reason_for_profile(state, path)
            if reason:
                self._remember_policy_rejection(state, path, reason, phase=phase)
                continue
            filtered.append(row)
        for idx, row in enumerate(filtered, start=1):
            if isinstance(row, dict):
                row["priority"] = idx
        return filtered

    def _is_soft_campaign_stop_reason(self, reason: Optional[str]) -> bool:
        """Non-terminal stops that shell-hunter finalization may override."""
        text = str(reason or "").lower()
        if not text:
            return False
        return any(
            token in text
            for token in (
                "low novelty",
                "no remaining shell pivots",
                "no pivot",
            )
        )

    def _product_shell_chain_pending(self, state: AgentState) -> bool:
        """True when a known lab/product auth→shell ladder is still incomplete."""
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        if self._has_shell_milestone(state):
            return False
        pending = list(product_auth_shell_followups(kb, state) or []) + list(
            suggest_shell_plan_followups(kb, state) or []
        )
        return bool(pending)

    def _maybe_extend_budget_for_shell_chain(self, state: AgentState) -> bool:
        """
        When obtain-shell hits the hard budget but a DVWA/lab chain is still pending,
        grant a one-shot extension so auth→shell can finish.
        """
        if not (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or bool(getattr(state, "shell_hunter", False))
        ):
            return False
        if not self._product_shell_chain_pending(state):
            return False
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        if kb.get("_shell_chain_budget_extended"):
            return False
        budget = getattr(state, "network_budget", None)
        if budget is None or not getattr(budget, "bounded", False):
            return False
        extend_by = 60
        try:
            new_limit = budget.extend(extend_by, reason="shell-chain budget extension")
        except Exception:
            return False
        kb["_shell_chain_budget_extended"] = True
        state.campaign_stop_reason = None
        if getattr(state, "request_budget", 0):
            try:
                state.request_budget = int(new_limit)
            except Exception:
                pass
        if bool(getattr(state, "verbose", False)):
            print_status(
                f"Extended request budget by {extend_by} for pending product shell chain "
                f"(new limit={new_limit})."
            )
        return True

    def _is_hard_campaign_stop_reason(self, reason: Optional[str]) -> bool:
        """Terminal stops: WAF/policy/budget/unreachable — do not run shell-hunter macro."""
        text = str(reason or "").strip().lower()
        if not text:
            return False
        if self._is_soft_campaign_stop_reason(reason):
            return False
        hard_tokens = (
            "blocking/waf",
            "waf_or_blocking",
            "target_unreachable",
            "dry_run",
            "deadline_reached",
            "budget_exhausted",
            "request_budget_exhausted",
            "operator_cancelled",
            "phase_timeout",
            "profile blocks",
            "requires explicit",
            "requires approval",
            "excessive redirect",
            "rate-limit noise",
            "goal obtain-auth complete",
            "auth milestone reached",
            "auth goal complete",
        )
        return any(token in text for token in hard_tokens)

    def _is_low_novelty_stop_reason(self, reason: Optional[str]) -> bool:
        return self._is_soft_campaign_stop_reason(reason) and "low novelty" in str(reason or "").lower()

    def _should_run_shell_hunter_finalization(self, state: AgentState) -> bool:
        if self._has_shell_milestone(state):
            return False
        if is_auth_operator_goal(self._operator_campaign_goal(state)):
            return False
        stop = state.campaign_stop_reason
        if self._is_hard_campaign_stop_reason(stop):
            # Budget exhaustion mid lab-chain: extend once and continue.
            text = str(stop or "").lower()
            if "budget" in text and self._maybe_extend_budget_for_shell_chain(state):
                return True
            return False
        return (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or bool(getattr(state, "shell_hunter", False))
        )

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
            "login_page_detector", "admin_login_bruteforce", "drupal_login_bruteforce",
            # Co-located panels often share the same vhost as WordPress/Drupal.
            "phpmyadmin", "roundcube", "webmail_portal", "mysql_config",
            "exposed_mysql", "mysqld_exporter",
            # Lab apps co-hosted with CMS must remain reachable under CMS lock.
            "dvwa", "mutillidae", "bwapp", "webgoat",
            "grafana", "jenkins", "tomcat",
        )
        generic_fuzz_tokens = (
            "xss_scanner", "sqli_engine", "sql_injection", "sqli", "lfi_fuzzer", "ssrf_scanner",
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

    def _evaluate_campaign_stop(self, phase_name, phase_results, before, after, no_novelty_streak, state=None):
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
            if self._result_waf_signal(row):
                waf_markers += 1
            blob = " ".join([
                str(row.get("message", "")),
                str(row.get("details", "")),
            ]).lower()
            status_codes.extend([int(code) for code in HTTP_STATUS_IN_TEXT_RE.findall(blob)])

        novelty_limit = 1 if state is not None and self._discreet_mode(state) else 2
        exploit_pressure = self._has_exploit_pressure(state)
        if exploit_pressure and state is not None and not is_shell_operator_goal(self._operator_campaign_goal(state)):
            novelty_limit += 1
        if no_novelty_streak >= novelty_limit:
            kb = state.knowledge_base if state is not None and isinstance(state.knowledge_base, dict) else {}
            campaign_goal = self._operator_campaign_goal(state) if state is not None else ""
            defer, pivots = should_defer_shell_low_novelty_stop(
                kb,
                campaign_goal=campaign_goal,
                stack_mismatch_fn=self._module_stack_mismatch_reason if state is not None else None,
            )
            if defer:
                if state is not None and state.verbose and pivots:
                    print_status(
                        "Low novelty ignored (shell goal): "
                        + ", ".join(pivots[:5])
                    )
                return False, 0, ""
            if exploit_pressure and not is_shell_operator_goal(campaign_goal):
                return False, no_novelty_streak, ""
            stop_detail = f"{phase_name}: low novelty for {novelty_limit} consecutive phase(s)"
            if is_shell_operator_goal(campaign_goal):
                stop_detail += "; no remaining shell pivots"
            elif pivots:
                stop_detail += f" (pivots exhausted: {', '.join(pivots[:3])})"
            return True, no_novelty_streak, stop_detail

        if status_codes:
            noisy = [c for c in status_codes if c in HTTP_STATUS_RISK_SIGNALS]
            noisy_ratio = len(noisy) / max(1, len(status_codes))
            status_floor = 8 if state is not None and self._discreet_mode(state) else 20
            ratio_floor = 0.65 if state is not None and self._discreet_mode(state) else 0.85
            if len(status_codes) >= status_floor and noisy_ratio >= ratio_floor:
                return True, no_novelty_streak, (
                    f"{phase_name}: excessive redirect/forbidden/rate-limit noise ({len(noisy)}/{len(status_codes)})"
                )
            waf_codes = [c for c in status_codes if c in WAF_RISK_HTTP_STATUS_CODES]
            waf_floor = 1 if state is not None and self._discreet_mode(state) else 3
            marker_floor = 1 if state is not None and self._discreet_mode(state) else 2
            pause_for_waf = state is None or self._should_pause_campaign_for_waf(state)
            if pause_for_waf and (len(waf_codes) >= waf_floor or waf_markers >= marker_floor):
                return True, no_novelty_streak, (
                    f"{phase_name}: repeated blocking/WAF signals ({len(waf_codes)} status, {waf_markers} marker)"
                )

        return False, no_novelty_streak, ""

    def _filter_modules_by_protocol(self, modules, protocol):
        protocol = str(protocol or "").strip().lower()
        if not protocol:
            return modules
        if protocol == "ics":
            filtered = []
            for module in modules:
                path = module_path_lower(module)
                if "/ics/" in path or "ics" in str(module.get("tags") or "").lower():
                    filtered.append(module)
            return filtered
        pfx_scanner = f"scanner/{protocol}/"
        pfx_aux = f"auxiliary/scanner/{protocol}/"
        filtered = []
        for module in modules:
            path = module_path_lower(module)
            if pfx_scanner in path or pfx_aux in path:
                filtered.append(module)
        return filtered
