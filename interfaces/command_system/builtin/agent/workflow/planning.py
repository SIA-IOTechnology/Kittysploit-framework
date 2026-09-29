#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Goal selection, heuristic plans, and next-action ranking."""

from interfaces.command_system.builtin.agent.workflow.imports import *  # noqa: F403


class PlanningMixin:
    """Goal selection, heuristic plans, and next-action ranking."""

    def _action_reason_for_path(self, path: str, state: AgentState, findings: Optional[List[Any]] = None) -> str:
        low = str(path or "").lower()
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        conf_rows = self._stack_confidence_rows(kb, threshold=0.4)
        top_stack = conf_rows[0][0] if conf_rows else ""
        top_stack_score = conf_rows[0][1] if conf_rows else 0.0
        # Prefer concrete CMS evidence over a generic "api" top-stack when choosing follow-ups.
        if top_stack == "api" and conf_rows:
            for name, score in conf_rows[1:4]:
                if name in {"drupal", "wordpress", "joomla", "phpmyadmin"} and float(score or 0.0) >= 0.45:
                    top_stack = name
                    top_stack_score = float(score or 0.0)
                    break
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
        if "sqli_engine" in low or "sql_injection" in low:
            return "Crawl-driven surface: validate SQLi with sqli_engine (minimal probes)."
        if "xss_scanner" in low:
            return "Parameter-rich surface detected; validate reflected/stored XSS paths."
        if "lfi_fuzzer" in low:
            return "File/path-like parameters detected; validate LFI risk."
        if top_stack:
            return f"Best next validation step for probable stack `{top_stack}` ({top_stack_score:.2f})."
        if findings:
            return "Best low-noise validation step from current evidence."
        return "Best next low-noise validation step."

    def _action_matching_findings(self, path: str, findings: Optional[List[Any]] = None) -> List[Dict[str, Any]]:
        """Return findings that directly justify a planned action path."""
        low = str(path or "").strip().lower()
        if not low:
            return []

        exact: List[Dict[str, Any]] = []
        fuzzy: List[Dict[str, Any]] = []
        base = low.rstrip("/").split("/")[-1]
        for item in findings or []:
            if not isinstance(item, dict):
                continue
            finding_path = str(item.get("path", "") or "").strip().lower()
            exploit_path = str(self._catalog.normalize_exploit_module_path(item.get("exploit_module")) or "").lower()
            linked_paths = [
                str(p).strip().lower()
                for p in self._catalog.normalize_linked_module_paths(item.get("linked_modules"))
            ]
            if low == finding_path or low == exploit_path or low in linked_paths:
                exact.append(item)
                continue
            if len(base) >= 8:
                blob = " ".join([
                    finding_path,
                    exploit_path,
                    " ".join(linked_paths),
                    str(item.get("module", "") or "").lower(),
                    str(item.get("message", "") or "").lower(),
                ])
                if base in blob:
                    fuzzy.append(item)

        rows = exact or fuzzy
        return sorted(rows, key=lambda row: float(row.get("context_score", 0.0) or 0.0), reverse=True)

    def _action_decision_explanation(
        self,
        action: Dict[str, Any],
        state: AgentState,
        findings: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """Build an auditable explanation for a planner action."""
        action_type = str(action.get("type", "") or "").strip().lower()
        path = str(action.get("path", "") or "").strip()
        low = path.lower()
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        matching = self._action_matching_findings(path, findings)
        top = matching[0] if matching else {}
        reason = self._action_reason_for_path(path, state, findings)

        evidence: List[str] = []
        tradeoffs: List[str] = []
        goal = str(getattr(state, "campaign_goal", "") or "").strip()
        if goal:
            evidence.append(f"campaign_goal={goal}")

        if top:
            msg = self._shorten_text(top.get("message", ""), 150)
            if msg:
                evidence.append(f"matched_finding={msg}")
            decision_class = str(top.get("decision_class", "") or "").strip()
            if decision_class:
                evidence.append(f"decision_class={decision_class}")
            context_hints = [str(x) for x in (top.get("context_hints", []) or []) if str(x).strip()]
            if context_hints:
                evidence.append("context_hints=" + ",".join(context_hints[:4]))
            if self._catalog.normalize_exploit_module_path(top.get("exploit_module")):
                evidence.append("direct_exploit_link=true")

        conf_rows = self._stack_confidence_rows(kb, threshold=0.4)
        if conf_rows:
            evidence.append(f"stack={conf_rows[0][0]}:{conf_rows[0][1]:.2f}")

        login_paths = [str(p) for p in kb.get("login_paths", []) or [] if str(p).startswith("/")]
        if login_paths and any(token in low for token in ("login", "auth", "bruteforce")):
            evidence.append(f"login_paths={len(login_paths)}")

        signals = [str(x).lower() for x in kb.get("risk_signals", []) or [] if str(x).strip()]
        useful_signals = [
            s for s in signals
            if s in (
                "authenticated_session",
                "credentials_obtained",
                "login_surface_detected",
                "login_form_detected",
                "waf_or_blocking_detected",
                "dom_xss_signal",
                "sqli_engine",
                "sql_injection",
            )
        ]
        if useful_signals:
            evidence.append("signals=" + ",".join(useful_signals[:5]))

        request_intel = kb.get("request_intel", {}) if isinstance(kb.get("request_intel", {}), dict) else {}
        if int(request_intel.get("analyzed_flows", 0) or 0) > 0:
            evidence.append(f"http_flows={request_intel.get('analyzed_flows', 0)}")

        memory_evidence, memory_tradeoffs = self._module_memory_decision_notes(path, state)
        evidence.extend(memory_evidence)
        tradeoffs.extend(memory_tradeoffs)

        expected_gain = 1.0
        if action_type == "run_exploit":
            expected_gain += 2.2
        elif action_type == "run_followup":
            expected_gain += 1.2
        elif action_type == "prioritize":
            expected_gain += 0.5

        if top:
            expected_gain += min(3.0, max(0.0, float(top.get("context_score", 0.0) or 0.0)) / 3.0)
            if top.get("decision_class") == "exploit":
                expected_gain += 1.0
            elif top.get("decision_class") == "followup":
                expected_gain += 0.45
        if "authenticated_session" in signals and action_type == "run_exploit":
            expected_gain += 0.8
        if any(token in low for token in ("rce", "shell", "upload", "command")):
            expected_gain += 0.7
        if any(token in low for token in ("login", "bruteforce")) and login_paths:
            expected_gain += 0.55

        signals_lower = {str(x).lower() for x in kb.get("risk_signals", []) or []}
        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            if "sqli_confirmed" in signals_lower or "sql_signal" in signals_lower or parked_sqli_branches(kb):
                if "sqli_shell" in low:
                    expected_gain += 4.5
                    evidence.append("sqli_confirmed_resume_deep=true")
                elif any(token in low for token in ("sql_injection", "sqli_engine", "sqli")):
                    expected_gain += 1.5
                if "bruteforce" in low or "admin_login" in low:
                    expected_gain -= 1.2
                    tradeoffs.append("sqli confirmed — deprioritized vs shell-from-sqli path")
        if action_type == "run_post" and "sqli_shell" in low:
            expected_gain += 2.5

        risk_cost = float(estimate_network_cost(low))
        if action_type == "run_exploit":
            risk_cost += 1.25
        if "bruteforce" in low:
            risk_cost += 1.1
        if any(token in low for token in ("crawler", "fuzzer", "fuzz")):
            risk_cost += 0.8
        profile = self._normalized_safety_profile(state)
        if profile in ("safe", "discreet"):
            risk_cost += 0.35
            tradeoffs.append(f"safety_profile={profile}")
        if "waf_or_blocking_detected" in signals:
            risk_cost += 1.2
            tradeoffs.append("blocking/WAF signal increases execution risk")

        block_reason = self._module_block_reason_for_profile(state, path)
        if block_reason:
            risk_cost += 2.0
            tradeoffs.append(block_reason)

        if top:
            factors = top.get("risk_factors", {}) if isinstance(top.get("risk_factors", {}), dict) else {}
            confidence = float(factors.get("confidence", 0.72) or 0.72)
        elif evidence:
            confidence = 0.64
        else:
            confidence = 0.46
        if action_type == "run_exploit" and not any("direct_exploit_link=true" == e for e in evidence):
            confidence -= 0.12
            tradeoffs.append("exploit path is inferred rather than directly linked")
        if "possible" in " ".join(evidence).lower() or "potential" in " ".join(evidence).lower():
            confidence -= 0.1
        confidence = max(0.1, min(1.0, confidence))

        score = max(0.0, (expected_gain * confidence * 2.0) - (risk_cost * 0.35))
        if not tradeoffs and action_type == "run_followup":
            tradeoffs.append("validation-first step before higher-risk exploitation")

        base = {
            "reason": reason,
            "score": round(score, 3),
            "confidence": round(confidence, 3),
            "expected_gain": round(expected_gain, 3),
            "risk_cost": round(risk_cost, 3),
            "evidence": evidence[:8],
            "tradeoffs": tradeoffs[:5],
        }
        report = build_action_decision_report(
            path,
            action_type,
            kb,
            campaign_goal=str(getattr(state, "campaign_goal", "") or ""),
            phase=str(getattr(state, "current_phase", "") or "plan"),
            reason=reason,
            matching_finding=top or None,
            stack_mismatch_fn=self._module_stack_mismatch_reason,
            evidence=evidence[:8],
            tradeoffs=tradeoffs[:5],
            score=base["score"],
            confidence=base["confidence"],
            expected_gain=base["expected_gain"],
            risk_cost=base["risk_cost"],
        )
        base.update(report)
        return base

    def _enrich_execution_plan_actions(
        self,
        state: AgentState,
        plan: Dict[str, Any],
        findings: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """Attach decision explanations to every planner action."""
        out = dict(plan or {})
        actions = []
        raw_actions = [
            row for row in (out.get("next_actions", []) or [])
            if isinstance(row, dict)
        ]
        raw_actions = self._filter_plan_actions_for_policy(
            state,
            raw_actions,
            phase=str(getattr(state, "current_phase", "") or "plan"),
        )
        for row in raw_actions:
            if not isinstance(row, dict):
                continue
            enriched = dict(row)
            explanation = self._action_decision_explanation(enriched, state, findings)
            enriched["decision_explanation"] = explanation
            enriched["decision_score"] = explanation["score"]
            enriched["confidence"] = explanation["confidence"]
            enriched.setdefault("reason", explanation["reason"])
            actions.append(enriched)
        out["next_actions"] = actions
        return out

    def _post_auth_vector_is_disallowed(self, path_lower):
        """
        Responsible triage: avoid auto-chaining noisy / abuse-prone surfaces (email, mass messaging).
        """
        return any(b in path_lower for b in DISALLOWED_POST_AUTH_TOKENS)

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
        self._ingest_sessions_from_scan_results(state, all_results)
        if self._has_shell_milestone(state):
            if verbose:
                print_status(
                    f"{phase_label}: shell/session already obtained — skipping HTTP post-auth pivot."
                )
            return self._finalize_scan_campaign(
                state,
                modules,
                scanner,
                all_results,
                executed_paths,
                phase_threads,
                tech_hints,
            )

        operator = self._operator_campaign_goal(state)
        # obtain-auth: credentials/session are the goal — stop without post-auth / shell chase.
        if is_auth_operator_goal(operator):
            state.campaign_stop_reason = (
                f"{phase_label}: auth milestone reached — goal obtain-auth complete"
            )
            if verbose:
                print_status(
                    "Auth goal complete: halting recon/injection and post-auth waves."
                )
            for hint in state.knowledge_base.get("tech_hints", []) or []:
                tech_hints.add(str(hint).lower())
            state.scan_tech_hints = sorted(tech_hints)
            state.scan_modules_executed = len(executed_paths)
            return self._finalize_scan_campaign(
                state,
                modules,
                scanner,
                all_results,
                executed_paths,
                phase_threads,
                tech_hints,
            )

        state.campaign_stop_reason = (
            f"{phase_label}: credentials obtained — halting broad scan; pivot to post-auth / privilege escalation"
        )
        if self._should_run_post_auth_methodical_wave(state.knowledge_base):
            post_auth_budget = min(12, max(3, int(state.max_modules) - len(executed_paths)))
            if self._discreet_mode(state):
                post_auth_budget = min(5, max(2, int(state.max_modules) - len(executed_paths)))
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
        return self._finalize_scan_campaign(
            state,
            modules,
            scanner,
            all_results,
            executed_paths,
            phase_threads,
            tech_hints,
        )

    def _has_shell_milestone(self, state: AgentState) -> bool:
        """True when a neutral-verified interactive shell session exists."""
        verified = [str(s).strip() for s in (getattr(state, "verified_sessions", None) or []) if str(s).strip()]
        if verified:
            return True
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        broker_ids = kb.get("verified_session_ids") or []
        if broker_ids:
            return True
        blob = kb.get("session_broker")
        if isinstance(blob, dict):
            sessions = blob.get("sessions")
            if isinstance(sessions, dict):
                for row in sessions.values():
                    if (
                        isinstance(row, dict)
                        and row.get("verified")
                        and str(row.get("status") or "") == "verified"
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
        inferred = self._derive_exploit_paths_from_findings(
            state.vulnerable_results or state.results or [],
            kb,
            limit=1,
        )
        if inferred:
            return True
        operator = operator_goal_from_mapping(kb)
        if is_shell_operator_goal(operator):
            return True
        return False

    def _has_weaponizable_campaign_pressure(self, state: Optional[AgentState]) -> bool:
        """True when confirmed injection-class signals should drive exploit/follow-up."""
        if state is None:
            return False
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        signals = {str(x).lower() for x in (kb.get("risk_signals") or []) if str(x).strip()}
        if signals.intersection({
            "sql_signal",
            "sqli_confirmed",
            "lfi_signal",
            "xss_signal",
            "ssrf_signal",
            "rce_signal",
        }):
            return True
        if getattr(state, "sql_findings", None):
            return True
        for row in (
            state.contextual_findings
            or state.vulnerable_results
            or state.results
            or []
        ):
            if isinstance(row, dict) and self._is_weaponizable_vuln_finding(row):
                return True
        return False

    def _sqli_resume_goal(self, state: AgentState) -> str:
        """Goal token used for SQLi deep-resume (campaign exploit or operator shell)."""
        return str(
            getattr(state, "campaign_goal", None)
            or self._operator_campaign_goal(state)
            or ""
        )

    def _suggest_sqli_chain_action(
        self,
        state: AgentState,
        kb: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Prefer parked sqli_shell, else light sqli_engine probe when SQLi pressure exists."""
        knowledge = kb if isinstance(kb, dict) else (
            state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        )
        sync_branches_from_kb_signals(knowledge)
        state.knowledge_base = knowledge
        if not has_sqli_shell_pressure(knowledge) and not getattr(state, "sql_findings", None):
            return None
        resume_goal = self._sqli_resume_goal(state)
        if not goal_allows_sqli_deep_resume(resume_goal):
            # Auto-escalated exploit path: treat as exploit for resume eligibility.
            resume_goal = CAMPAIGN_GOAL_EXPLOIT
        resumed = pick_resumed_deep_action(knowledge, operator_goal=resume_goal)
        if resumed:
            return resumed
        if parked_sqli_branches(knowledge):
            return None
        light = pick_light_sqli_probe(knowledge)
        if light:
            return light
        observed = {str(x) for x in knowledge.get("observed_modules") or []}
        if HTTP_SQLI_POST_MODULE not in observed and (
            "sqli_confirmed" in {str(s).lower() for s in knowledge.get("risk_signals") or []}
            or getattr(state, "sql_findings", None)
        ):
            return {
                "type": action_type_for_module_path(HTTP_SQLI_POST_MODULE),
                "path": HTTP_SQLI_POST_MODULE,
                "reason": "High-priority SQLi detection: escalate to sqli_shell.",
            }
        if (
            HTTP_SQLI_SCANNER_MODULE not in observed
            and HTTP_SQLI_SCANNER_MODULE_LEGACY not in observed
        ):
            return {
                "type": "run_followup",
                "path": HTTP_SQLI_SCANNER_MODULE,
                "reason": "High-priority SQLi detection: confirm with sqli_engine.",
            }
        return None

    def _has_exploit_pressure(self, state: Optional[AgentState]) -> bool:
        """
        True when campaign should keep exploit-oriented momentum instead of stopping early.
        """
        if state is None:
            return False
        if self._has_shell_milestone(state):
            return False
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        if self._credential_milestone_reached(kb):
            return True
        if self._has_weaponizable_campaign_pressure(state):
            return True

        candidate_findings = (
            state.contextual_findings
            or state.vulnerable_results
            or state.results
            or []
        )
        actionable = [
            row for row in candidate_findings
            if isinstance(row, dict) and self._is_actionable_finding(row)
        ]
        if any(
            self._finding_decision_class(row) in ("exploit", "followup")
            for row in actionable
        ):
            return True
        inferred = self._derive_exploit_paths_from_findings(
            actionable or candidate_findings,
            kb,
            limit=1,
        )
        if inferred:
            return True
        operator = self._operator_campaign_goal(state)
        return is_shell_operator_goal(operator)

    def _derive_exploit_paths_from_findings(
        self,
        findings: List[Any],
        knowledge_base: Dict[str, Any],
        limit: int = 6,
    ) -> List[str]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        catalog_paths = [
            str(p).strip()
            for p in (kb.get("module_capability_catalog", {}).get("all_paths", []) or [])
            if isinstance(p, str) and str(p).strip()
        ]
        exploit_catalog = [
            p for p in catalog_paths
            if p.startswith(("exploit/", "exploits/"))
        ]
        if not exploit_catalog:
            return []

        failed_tokens = self._get_failed_action_keys(kb)
        scores: Dict[str, float] = {}
        stop_tokens = {
            "scanner",
            "auxiliary",
            "http",
            "detect",
            "scanner",
            "exploit",
            "exploits",
            "module",
            "vuln",
            "vulnerability",
            "cve",
        }

        def _add(path: str, score: float) -> None:
            if not path or score <= 0:
                return
            if self._planner_action_keys(path).intersection(failed_tokens):
                return
            if self._module_hard_stack_skip_reason(path, kb):
                return
            prev = scores.get(path, 0.0)
            if score > prev:
                scores[path] = score

        focus_product = product_chain_still_pending(kb)
        if focus_product:
            for path in product_shell_chain_paths(focus_product, include_sqli_shell=False):
                if path.startswith(("exploit/", "exploits/")):
                    _add(path, 500.0)

        for row in findings or []:
            if not isinstance(row, dict):
                continue
            path_raw = str(row.get("path", "") or "").strip()
            path_low = path_raw.lower()
            if not path_low:
                continue

            direct = self._catalog.normalize_exploit_module_path(row.get("exploit_module"))
            if direct:
                _add(direct, 300.0)
            for linked in self._catalog.normalize_linked_module_paths(row.get("linked_modules")):
                if linked.startswith(("exploit/", "exploits/")):
                    _add(linked, 260.0)

            details = row.get("details", {})
            details_blob = ""
            if isinstance(details, dict):
                details_blob = " ".join(
                    str(v) for v in details.values()
                    if isinstance(v, (str, int, float, bool))
                ).lower()
            message_blob = str(row.get("message", "") or "").lower()
            blob = " ".join((path_low, message_blob, details_blob))

            cve_tokens = {
                f"cve_{year}_{num}"
                for year, num in re.findall(r"cve[_-]?(\d{4})[_-](\d{3,7})", blob)
            }
            basename = path_low.split("/")[-1]
            basename_core = basename
            for suffix in (
                "_detect",
                "_scanner",
                "_check",
                "_probe",
                "_fuzzer",
            ):
                if basename_core.endswith(suffix):
                    basename_core = basename_core[: -len(suffix)]
            row_tokens = {
                token for token in re.split(r"[/_.-]", path_low)
                if len(token) >= 4 and token not in stop_tokens and not token.isdigit()
            }

            for exploit_path in exploit_catalog:
                exploit_low = exploit_path.lower()
                score = 0.0
                if basename_core and basename_core in exploit_low:
                    score += 42.0
                if any(cve in exploit_low for cve in cve_tokens):
                    score += 160.0
                token_overlap = sum(1 for token in row_tokens if token in exploit_low)
                if token_overlap:
                    score += min(48.0, token_overlap * 8.0)
                if row.get("vulnerable"):
                    score *= 1.15
                if score >= 28.0:
                    _add(exploit_path, score)

        for path in kb.get("post_auth_exploit_paths", []) or []:
            if isinstance(path, str) and path.startswith(("exploit/", "exploits/")):
                _add(path, 220.0)

        ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        ranked_paths = [path for path, _ in ranked[: max(1, int(limit or 1))]]
        return filter_paths_for_product_focus(ranked_paths, kb)[: max(1, int(limit or 1))]

    def _fallback_exploit_candidates_from_kb(
        self,
        knowledge_base: Dict[str, Any],
        limit: int = 6,
    ) -> List[str]:
        """
        Exploit-path fallback when findings are mostly informational.
        Uses strong tech confidence/hints + exploit catalog tokens.
        """
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        all_paths = [
            str(p).strip()
            for p in (kb.get("module_capability_catalog", {}).get("all_paths", []) or [])
            if isinstance(p, str) and str(p).strip()
        ]
        exploit_paths = [p for p in all_paths if p.startswith(("exploit/", "exploits/"))]
        if not exploit_paths:
            return []

        conf = kb.get("tech_confidence", {}) or {}
        strong_hints = {
            k for k, v in conf.items()
            if str(k).strip() and float(v or 0.0) >= 0.55
        }
        strong_hints |= {
            str(h).lower().strip()
            for h in (kb.get("tech_hints", []) or [])
            if str(h).strip()
        }
        failed_tokens = self._get_failed_action_keys(kb)
        scored: List[Tuple[float, str]] = []
        focus_product = product_chain_still_pending(kb)
        if focus_product:
            # Product-first: only return the pending lab chain exploits.
            focused = filter_paths_for_product_focus(
                [p for p in exploit_paths if focus_product in p.lower() or p.startswith(("exploit/", "exploits/"))],
                kb,
            )
            focused = [
                p for p in focused
                if p.startswith(("exploit/", "exploits/"))
                and not self._planner_action_keys(p).intersection(failed_tokens)
                and not self._module_hard_stack_skip_reason(p, kb)
            ]
            if focused:
                return focused[: max(1, int(limit or 1))]
        for path in exploit_paths:
            low = path.lower()
            if self._planner_action_keys(path).intersection(failed_tokens):
                continue
            if self._module_hard_stack_skip_reason(path, kb):
                continue
            score = 0.0
            overlap = sum(1 for h in strong_hints if h in low)
            if overlap:
                score += min(6.0, overlap * 1.2)
            if any(tok in low for tok in ("cve_", "rce", "inject", "deserialization", "traversal")):
                score += 2.2
            if any(tok in low for tok in ("joomla", "wordpress", "drupal", "phpmyadmin", "graphql", "api")):
                score += 1.4
            if score > 0:
                scored.append((score, path))
        scored.sort(key=lambda row: (-row[0], row[1]))
        return [p for _, p in scored[: max(1, int(limit or 1))]]

    def _operator_campaign_goal(self, state: AgentState) -> str:
        """North-star goal from CLI/profile (not the tactical phase goal)."""
        raw = getattr(state, "operator_goal", None) or ""
        if str(raw).strip():
            return operator_goal_from_mapping({"operator_goal": raw})
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        return operator_goal_from_mapping(kb)

    def _module_path_observed(self, kb: Dict[str, Any], *needles: str) -> bool:
        observed = [str(p).lower() for p in (kb.get("observed_modules") or []) if p]
        return any(any(n in p for n in needles) for p in observed)

    def _api_surface_ready_for_testing(self, kb: Dict[str, Any]) -> bool:
        return kb_api_surface_ready(kb)

    def _subdomain_surface_expandable(self, kb: Dict[str, Any]) -> bool:
        return kb_subdomain_surface_expandable(kb)

    def _next_best_action_for_shell_goal(
        self,
        state: AgentState,
        kb: Dict[str, Any],
        findings: List[Any],
    ) -> Optional[Dict[str, Any]]:
        """Opportunistic ladder toward shell: exploit → API → subdomains → crawl → injections."""
        pending_product = product_chain_still_pending(kb if isinstance(kb, dict) else {})
        if pending_product:
            wrapper_attempts = {
                str(x).strip().lower()
                for x in (kb.get("product_shell_wrapper_attempts") or [])
                if str(x).strip()
            }
            wrapper_leaves = {a.rsplit("/", 1)[-1] for a in wrapper_attempts}
            for path in product_shell_chain_paths(pending_product, include_sqli_shell=False):
                low = path.lower()
                leaf = low.rsplit("/", 1)[-1]
                if low.startswith(("exploit/", "exploits/")):
                    if low in wrapper_attempts or leaf in wrapper_leaves:
                        continue
                elif self._module_path_observed(kb, leaf) or self._module_path_observed(kb, path):
                    continue
                if self._module_block_reason_for_profile(state, path):
                    continue
                return {
                    "type": action_type_for_module_path(path),
                    "path": path,
                    "reason": (
                        f"Product-focus `{pending_product}`: finish auth→RCE chain "
                        "before broader hunting."
                    ),
                }

        preferred_paths = self._preferred_post_auth_exploit_paths(kb)
        for path in preferred_paths:
            return {
                "type": "run_exploit",
                "path": path,
                "reason": "Goal obtain-shell: weaponize authenticated context.",
            }
        for f in findings:
            if not isinstance(f, dict):
                continue
            ex = self._catalog.normalize_exploit_module_path(f.get("exploit_module"))
            if ex:
                return {
                    "type": "run_exploit",
                    "path": ex,
                    "reason": "Goal obtain-shell: linked exploit module from finding.",
                }
        for p in kb.get("post_auth_exploit_paths") or []:
            if isinstance(p, str) and (p.startswith("exploit/") or p.startswith("exploits/")):
                return {
                    "type": "run_exploit",
                    "path": p,
                    "reason": "Goal obtain-shell: catalog exploit from auth context.",
                }
        inferred_paths = self._derive_exploit_paths_from_findings(findings, kb, limit=2)
        for path in inferred_paths:
            return {
                "type": "run_exploit",
                "path": path,
                "reason": "Goal obtain-shell: inferred exploit from scanner evidence.",
            }

        for f in findings:
            if not isinstance(f, dict) or not f.get("vulnerable"):
                continue
            decision = self._finding_decision_class(f)
            mod_path = str(f.get("path", "") or "").strip()
            if decision in ("exploit", "followup") and mod_path:
                action_type = "run_exploit" if decision == "exploit" else "run_followup"
                return {
                    "type": action_type,
                    "path": mod_path,
                    "reason": "Goal obtain-shell: weaponize confirmed finding.",
                }

        nxt = kb.get("attack_graph_next_action")
        if isinstance(nxt, dict):
            graph_path = str(nxt.get("action") or "").strip()
            observed = set(kb.get("observed_modules") or [])
            stale = set(kb.get("attack_graph_stale_modules") or [])
            if (
                graph_path
                and graph_path not in observed
                and graph_path not in stale
                and not self._module_block_reason_for_profile(state, graph_path)
                and not self._module_stack_mismatch_reason(graph_path, kb)
            ):
                action_type = (
                    "run_exploit"
                    if graph_path.startswith(("exploit/", "exploits/"))
                    else "run_followup"
                )
                return {
                    "type": action_type,
                    "path": graph_path,
                    "reason": "Attack graph: next highest-confidence step toward shell.",
                }

        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            sync_branches_from_kb_signals(kb)
            resumed = pick_resumed_deep_action(
                kb,
                operator_goal=str(self._operator_campaign_goal(state) or ""),
            )
            if resumed:
                return resumed
            light_sqli = pick_light_sqli_probe(kb)
            if light_sqli:
                return light_sqli

        for path in suggest_shell_plan_followups(
            kb,
            state,
            self._catalog.discover_campaign_modules(expanded=True),
        ):
            return {
                "type": action_type_for_module_path(path),
                "path": path,
                "reason": "Goal obtain-shell: strategic surface expansion toward RCE.",
            }

        if self._login_surface_wants_bruteforce(kb, findings, False) and not self._has_authenticated_session(kb):
            bf = ADMIN_LOGIN_BRUTEFORCE_MODULE
            if not self._module_block_reason_for_profile(state, bf) and not self._module_path_observed(kb, "admin_login_bruteforce"):
                return {
                    "type": "run_followup",
                    "path": bf,
                    "reason": "Goal obtain-shell: credential path toward post-auth exploitation.",
                }

        return {
            "type": "run_followup",
            "path": "auxiliary/scanner/http/crawler",
            "reason": "Goal obtain-shell: keep widening attack surface until a weaponizable vector appears.",
        }

    def _sync_campaign_goal(self, state: AgentState) -> None:
        """
        Set ``state.campaign_goal`` from KB + results.

        Rule chain: shell → stop; authenticated → exploit or post_auth;
        operator obtain-shell → pursue_shell; weaponizable SQLi/LFI → exploit
        (beats auth-first); login surface → obtain_auth; else recon.
        """
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        operator = self._operator_campaign_goal(state)
        if is_shell_operator_goal(operator):
            kb["shell_hunter_mode"] = True
            state.knowledge_base = kb
        if self._has_shell_milestone(state):
            state.campaign_goal = CAMPAIGN_GOAL_SHELL_STOP
            return
        if self._credential_milestone_reached(kb):
            if self._goal_should_prioritize_exploit(state):
                state.campaign_goal = CAMPAIGN_GOAL_EXPLOIT
            else:
                state.campaign_goal = CAMPAIGN_GOAL_POST_AUTH
            return
        if is_shell_operator_goal(operator):
            state.campaign_goal = CAMPAIGN_GOAL_OBTAIN_SHELL
            if self._auth_first_mode(state):
                kb["auth_pressure"] = True
                state.knowledge_base = kb
            return
        # Soft-target / injection pressure: leave recon (and skip auth-first)
        # so planners chase SQLi/LFI instead of parking on OSINT or login spray.
        if self._has_weaponizable_campaign_pressure(state):
            state.campaign_goal = CAMPAIGN_GOAL_EXPLOIT
            if has_sqli_shell_pressure(kb) or getattr(state, "sql_findings", None):
                sync_branches_from_kb_signals(kb)
                state.knowledge_base = kb
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

        if goal == CAMPAIGN_GOAL_OBTAIN_SHELL:
            shell_action = self._next_best_action_for_shell_goal(state, kb, findings)
            if shell_action:
                return shell_action

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
            sqli_action = self._suggest_sqli_chain_action(state, kb)
            if sqli_action:
                return sqli_action
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
            inferred_paths = self._derive_exploit_paths_from_findings(findings, kb, limit=2)
            for path in inferred_paths:
                return {
                    "type": "run_exploit",
                    "path": path,
                    "reason": "Goal exploit: inferred exploit candidate from scanner evidence.",
                }
            # Weaponizable scanner findings (LFI/SQLi) before generic crawl.
            for f in findings:
                if not isinstance(f, dict) or not self._is_weaponizable_vuln_finding(f):
                    continue
                mod_path = str(f.get("path", "") or "").strip()
                if not mod_path:
                    continue
                return {
                    "type": "run_followup",
                    "path": mod_path,
                    "reason": "Goal exploit: deepen confirmed weaponizable finding.",
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
                    "wordpress": "auxiliary/scanner/http/wp_plugin_scanner",
                    "drupal": "auxiliary/scanner/http/drupal_scanner",
                    "joomla": "auxiliary/scanner/http/joomla_scanner",
                    "nextjs": "auxiliary/osint/js_endpoint_extractor",
                    "react": "auxiliary/osint/js_endpoint_extractor",
                    "nodejs": "auxiliary/osint/js_endpoint_extractor",
                    "phpmyadmin": "auxiliary/scanner/http/lfi_fuzzer",
                }
                chosen = stack_map.get(top_stack, "")
                if chosen:
                    return {
                        "type": "run_followup",
                        "path": chosen,
                        "reason": (
                            f"Validation-only state: push stack-specific attack surface for `{top_stack}` "
                            f"instead of passive confirmation."
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
                out = {
                    "type": t,
                    "path": p,
                    "reason": str(a.get("reason") or "Planner next action (from execution plan)."),
                }
                if "decision_score" in a:
                    out["decision_score"] = a.get("decision_score")
                if "confidence" in a:
                    out["confidence"] = a.get("confidence")
                if isinstance(a.get("decision_explanation"), dict):
                    out["decision_explanation"] = a.get("decision_explanation")
                return out
        return None

    def _resolve_next_best_action(
        self,
        state: AgentState,
        findings: Optional[List[Any]] = None,
        *,
        execution_plan: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prefer resumed SQLi deep path on shell/exploit before login or OSINT."""
        self._sync_campaign_goal(state)
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        sync_branches_from_kb_signals(kb)
        state.knowledge_base = kb
        operator = str(self._operator_campaign_goal(state) or "")
        resume_goal = self._sqli_resume_goal(state)
        sqli_pressure = has_sqli_shell_pressure(kb) or bool(getattr(state, "sql_findings", None))
        if sqli_pressure and (
            goal_allows_sqli_deep_resume(resume_goal)
            or is_shell_operator_goal(operator)
            or state.campaign_goal == CAMPAIGN_GOAL_EXPLOIT
        ):
            sqli_action = self._suggest_sqli_chain_action(state, kb)
            if sqli_action:
                path = str(sqli_action.get("path") or "")
                sqli_action["reason"] = str(
                    sqli_action.get("reason")
                    or self._action_reason_for_path(path, state, findings)
                )
                sqli_action.setdefault("decision_score", 9.5)
                sqli_action.setdefault("confidence", 0.82)
                return sqli_action
        plan = execution_plan if execution_plan is not None else state.execution_plan
        nba = self._infer_next_best_action_from_execution_plan(plan)
        if nba:
            path = str(nba.get("path") or "")
            # Do not let login bruteforce / OSINT beat a confirmed SQLi path.
            if sqli_pressure and any(
                token in path.lower()
                for token in ("admin_login_bruteforce", "js_sourcemap", "js_endpoint", "webhook_api")
            ):
                nba = None
            else:
                nba["reason"] = self._action_reason_for_path(path, state, findings)
                return nba
        return self._next_best_action_for_goal(state, findings or [])

    def _prepend_sqli_shell_resume(self, state: AgentState, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Put deep SQLi shell / engine first when SQLi is confirmed (shell or exploit)."""
        out = dict(plan or {})
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        sync_branches_from_kb_signals(kb)
        state.knowledge_base = kb
        sqli_action = self._suggest_sqli_chain_action(state, kb)
        if not sqli_action:
            return out
        path = str(sqli_action.get("path") or "")
        if not path:
            return out
        actions = [
            a for a in (out.get("next_actions") or [])
            if isinstance(a, dict) and a.get("path") != path
        ]
        actions.insert(0, {
            "type": sqli_action.get("type", "run_post"),
            "path": path,
            "priority": 0,
            "options": sqli_action.get("options") or {},
            "reason": sqli_action.get("reason"),
            "resume_branch": bool(sqli_action.get("resume_branch")),
        })
        out["next_actions"] = actions
        return out

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

        if len(actions) < 2 and not self._discreet_mode(state):
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
            HTTP_SQLI_SCANNER_MODULE,
            "auxiliary/scanner/http/lfi_fuzzer",
        ):
            if self._discreet_mode(state) and not kb.get("discovered_params"):
                break
            if inj in allowed and len(actions) < max_actions:
                low = inj.lower()
                if self._post_auth_vector_is_disallowed(low):
                    continue
                actions.append({"type": "run_followup", "path": inj, "priority": priority, "options": {}})
                priority += 1
        return actions[:max_actions]

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
        if self._has_exploit_pressure(state):
            max_requests = max(max_requests, 12)
        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            max_requests = max(max_requests, 18)
        if auth_session:
            max_requests = min(10, max_requests + 2)
        elif auth_surface or cms_lock:
            # Enough budget for login bruteforce plus a couple of chained scanners (4 was too tight).
            max_requests = min(max_requests, 8)
        if self._discreet_mode(state):
            if auth_session:
                max_requests = min(max_requests, 5)
            elif auth_surface or cms_lock:
                max_requests = min(max_requests, 4)
            else:
                max_requests = min(max_requests, 3)
        actions = []
        for idx, path in enumerate(selected_paths[:5], start=1):
            if path in allow_paths:
                actions.append({"type": "prioritize", "path": path, "priority": idx, "options": {}})

        # Prefer exploit-queue handoff when analyze already gated items.
        queue_actions = queue_to_execution_actions(
            load_exploit_queue(knowledge_base),
            limit=6,
        )
        if queue_actions:
            existing_paths = {str(a.get("path", "")).strip() for a in actions if isinstance(a, dict)}
            prepended = []
            for row in queue_actions:
                path = str(row.get("path") or "").strip()
                if not path or path in existing_paths:
                    continue
                prepended.append(row)
                existing_paths.add(path)
            if prepended:
                actions = prepended + actions
                max_requests = max(max_requests, min(16, len(prepended) + 4))

        # Confirmed / high-priority SQLi must beat OSINT and login spray.
        sqli_action = self._suggest_sqli_chain_action(state, knowledge_base)
        if sqli_action and sqli_action.get("path"):
            path = str(sqli_action["path"])
            actions = [a for a in actions if isinstance(a, dict) and a.get("path") != path]
            actions.insert(0, {
                "type": sqli_action.get("type", "run_followup"),
                "path": path,
                "priority": 0,
                "options": sqli_action.get("options") or {},
                "reason": sqli_action.get("reason"),
                "resume_branch": bool(sqli_action.get("resume_branch")),
            })
            max_requests = max(max_requests, 12)

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
            or self._is_weaponizable_vuln_finding(item)
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

        # Do not bury confirmed injection findings under SPA/OSINT follow-ups.
        if not self._has_weaponizable_campaign_pressure(state) and (
            kb_client_js_surface_ready(knowledge_base)
            or self._has_nextjs_evidence(knowledge_base)
            or any(
                self._has_tech_evidence(knowledge_base, tech, threshold=0.65)
                for tech in ("react", "nodejs", "javascript")
            )
        ):
            base_priority = len(actions) + 1
            for offset, path in enumerate(CLIENT_JS_INTEL_MODULES):
                if any(a.get("path") == path for a in actions):
                    continue
                actions.append({
                    "type": "run_followup",
                    "path": path,
                    "priority": base_priority + offset,
                    "options": {},
                })
            max_requests = min(16, max(max_requests, 8))

        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            base_priority = len(actions) + 1
            for offset, path in enumerate(
                suggest_shell_plan_followups(
                    knowledge_base,
                    state,
                    self._catalog.discover_campaign_modules(expanded=True),
                )
            ):
                if any(a.get("path") == path for a in actions):
                    continue
                action_type = "run_exploit" if path.startswith(("exploit/", "exploits/")) else "run_followup"
                actions.append({
                    "type": action_type,
                    "path": path,
                    "priority": base_priority + offset,
                    "options": {},
                })

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

        inferred_exploits = self._derive_exploit_paths_from_findings(findings, knowledge_base, limit=4)
        if inferred_exploits:
            existing_paths = {str(a.get("path", "")).strip() for a in actions if isinstance(a, dict)}
            inferred_rows = []
            for path in inferred_exploits:
                if not path or path in existing_paths:
                    continue
                inferred_rows.append({
                    "type": "run_exploit",
                    "path": path,
                    "priority": 0,
                    "options": {},
                })
            if inferred_rows:
                actions = inferred_rows + actions

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
        actions = self._filter_plan_actions_by_protocol(state, actions)
        for idx, row in enumerate(actions, start=1):
            row["priority"] = idx

        stop_conditions = []
        if not self._has_exploit_pressure(state):
            stop_conditions = ["stop_if_no_exploit_path"]
        plan = {
            "next_actions": actions,
            "max_requests_next_phase": max_requests,
            "stop_conditions": stop_conditions,
            "reasoning_confidence": 0.6,
            "skip_exploitation": False,
        }
        plan = self._apply_auth_first_execution_overrides(state, plan, findings)
        self._enrich_execution_plan_with_playbook(state, findings, plan)
        # Playbooks may reintroduce foreign-protocol steps; re-apply the operator constraint.
        if isinstance(plan, dict) and isinstance(plan.get("next_actions"), list):
            plan["next_actions"] = self._filter_plan_actions_by_protocol(
                state, list(plan.get("next_actions") or [])
            )
            for idx, row in enumerate(plan["next_actions"], start=1):
                if isinstance(row, dict):
                    row["priority"] = idx
        return plan

    def _filter_plan_actions_by_protocol(
        self,
        state: AgentState,
        actions: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Drop planned modules that conflict with campaign protocol / web target."""
        from interfaces.command_system.builtin.agent.goal_planner import (
            path_matches_forced_protocol,
            resolve_campaign_protocol,
        )

        protocol = resolve_campaign_protocol(
            state,
            state.knowledge_base if isinstance(state.knowledge_base, dict) else {},
        )
        if not protocol:
            return actions
        filtered: List[Dict[str, Any]] = []
        for row in actions or []:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", "") or "").strip()
            if path and not path_matches_forced_protocol(path, protocol):
                continue
            filtered.append(row)
        return filtered

    def _enrich_execution_plan_with_playbook(
        self,
        state: AgentState,
        findings,
        plan: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Merge reachable playbook next steps into the active execution plan."""
        if state.dry_run or state.plan_only or state.no_exploit:
            return
        if plan is None:
            plan = state.execution_plan if isinstance(state.execution_plan, dict) else None
        if not isinstance(plan, dict):
            return
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        snapshot = kb.get("campaign_findings_snapshot") or findings or []
        playbook_plan = build_playbook_execution_plan(kb, snapshot, max_steps=2)
        if not playbook_plan:
            return
        merge_playbook_into_execution_plan(plan, playbook_plan)
        if plan is not state.execution_plan:
            state.execution_plan = plan
        if state.verbose:
            print_info(
                "Playbook executor: merged "
                f"{playbook_plan.get('playbook_id')} "
                f"({playbook_plan.get('playbook_coverage')}) "
                f"with {len(playbook_plan.get('next_actions') or [])} step(s)."
            )
        self._append_timeline_event(
            state,
            "reason",
            (
                f"Playbook chain armed: {playbook_plan.get('playbook_name')} "
                f"[{playbook_plan.get('playbook_id')}]"
            ),
            kind="decision",
            extra={
                "playbook_id": playbook_plan.get("playbook_id"),
                "coverage": playbook_plan.get("playbook_coverage"),
            },
        )

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
        risk_signals = set([str(x).lower() for x in knowledge_base.get("risk_signals", [])])
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
                candidates.append(HTTP_SQLI_SCANNER_MODULE)
                if "sqli_confirmed" in risk_signals or "vulnerability_detected" in risk_signals:
                    candidates.append(HTTP_SQLI_POST_MODULE)
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
        if "dom_xss_signal" in risk_signals and not cms_lock:
            candidates.extend([
                "auxiliary/scanner/http/xss_scanner",
            ])
            # Framework-specific XSS probes only when that stack was fingerprinted.
            if self._has_tech_evidence(knowledge_base, "react", threshold=0.55) or "react" in hints:
                candidates.append("auxiliary/scanner/http/react_xss")
            if (
                self._has_tech_evidence(knowledge_base, "angular", threshold=0.55)
                or self._has_tech_evidence(knowledge_base, "angularjs", threshold=0.55)
                or "angular" in hints
                or "angularjs" in hints
            ):
                candidates.append("auxiliary/scanner/http/angular_xss")
        if kb_client_js_surface_ready(knowledge_base) or self._has_nextjs_evidence(knowledge_base) or any(
            h in hints for h in ("nextjs", "react", "nodejs", "javascript")
        ):
            candidates.extend(CLIENT_JS_INTEL_MODULES)
            if "api_surface_detected" in risk_signals or "graphql_surface_detected" in risk_signals or any(
                "/api" in str(endpoint).lower() or "graphql" in str(endpoint).lower()
                for endpoint in knowledge_base.get("discovered_endpoints", [])
            ):
                candidates.append("scanner/http/graphql_detect")
                candidates.append("scanner/http/swagger_detect")

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
