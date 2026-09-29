#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reason phase: build the execution plan for the next act."""

from interfaces.command_system.builtin.agent.workflow.imports import *  # noqa: F403


class ReasonPhaseMixin:
    """Reason phase: build the execution plan for the next act."""

    def _node_reason(self, state: AgentState) -> AgentState:
        if state.replan_pending and state.replan_count < 1:
            state.replan_count += 1
            state.replan_pending = False
        if state.target_reachable is False and not self._has_proxy_request_intel(state):
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
            if approved_to_continue_through_waf(state):
                state.campaign_stop_reason = None
            elif getattr(state, "llm_local", False):
                print_info("WAF/blocking detected — strategic LLM may propose bypass variants.")
                state.campaign_stop_reason = None
            else:
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
            if is_shell_operator_goal(state.campaign_goal) and kb_ssh_surface_ready(knowledge_base, state):
                ssh_login = "auxiliary/scanner/ssh/ssh_login"
                if not self._module_block_reason_for_profile(state, ssh_login):
                    state.llm_plan = {
                        "selected_paths": [ssh_login],
                        "rationale": "SSH surface detected — attempt credential login toward shell.",
                        "next_best_action": {
                            "type": "run_followup",
                            "path": ssh_login,
                            "reason": "Goal obtain-shell: SSH authentication surface.",
                        },
                    }
                    state.execution_plan = {
                        "next_actions": [{
                            "type": "run_followup",
                            "path": ssh_login,
                            "priority": 1,
                            "reason": "Goal obtain-shell: SSH authentication surface.",
                        }],
                        "max_requests_next_phase": max(12, int(state.request_budget or 0) // 4 or 12),
                        "stop_conditions": ["shell_obtained"],
                        "reasoning_confidence": 0.72,
                        "skip_exploitation": False,
                        "campaign_goal": state.campaign_goal,
                    }
                    state.decision_source = "heuristic"
                    self._append_timeline_event(
                        state,
                        "reason",
                        "SSH surface ready — queued ssh_login for obtain-shell.",
                        kind="decision",
                        extra={"goal": state.campaign_goal, "path": ssh_login},
                    )
                    return state
            # HTTP login surface with no scanner "vulnerable" finding (e.g. DVWA login page):
            # credential access is the reachable next step, so queue the bruteforce toward an
            # authenticated session instead of skipping exploitation. Respects risk policy — a
            # policy-blocked bruteforce falls through to the generic skip below.
            login_bf = "auxiliary/scanner/http/login/admin_login_bruteforce"
            login_paths_present = {
                p for p in knowledge_base.get("login_paths", []) or []
                if isinstance(p, str) and p.startswith("/")
            }
            if (
                login_paths_present
                and not self._has_authenticated_session(knowledge_base)
                and self._login_surface_wants_bruteforce(knowledge_base, decision_findings, False)
                and not self._module_block_reason_for_profile(state, login_bf)
            ):
                bf_action = {
                    "type": "run_followup",
                    "path": login_bf,
                    "reason": "Login surface detected — credential path toward post-auth exploitation.",
                }
                state.llm_plan = {
                    "selected_paths": [login_bf],
                    "rationale": "Login surface detected — attempt credential bruteforce toward authenticated session.",
                    "next_best_action": bf_action,
                }
                state.execution_plan = {
                    "next_actions": [{
                        "type": "run_followup",
                        "path": login_bf,
                        "priority": 1,
                        "options": {},
                        "reason": bf_action["reason"],
                    }],
                    "max_requests_next_phase": max(12, int(state.request_budget or 0) // 4 or 12),
                    "stop_conditions": ["authenticated_session", "shell_obtained"],
                    "reasoning_confidence": 0.7,
                    "skip_exploitation": False,
                    "campaign_goal": state.campaign_goal,
                }
                state.decision_source = "heuristic"
                self._append_timeline_event(
                    state,
                    "reason",
                    "Login surface ready — queued admin_login_bruteforce toward authenticated session.",
                    kind="decision",
                    extra={"goal": state.campaign_goal, "path": login_bf},
                )
                self._log_strategic_next_action(state)
                return state
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
        force_strategic_llm = should_force_strategic_llm(
            state,
            knowledge_base,
            complexity,
            findings=decision_findings,
        )
        if state.llm_local and int(getattr(state, "llm_budget", 0) or 0) <= 0:
            state.llm_budget = resolve_effective_llm_budget(state)
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
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
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
        if not complexity["is_complex"] and not state.llm_local and not force_strategic_llm:
            state.metrics.deterministic_steps += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings, "Heuristic plan (simple case).", state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            self._enrich_execution_plan_with_playbook(state, decision_findings)
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
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

        if not state.llm_local and not force_strategic_llm:
            state.metrics.deterministic_steps += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings, "Heuristic plan (LLM disabled).", state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
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

        if llm_budget_exhausted(state):
            state.metrics.llm_fallback_count += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings,
                "Heuristic plan (LLM budget reached).",
                state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "LLM budget reached; heuristic planner fallback applied.",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            return state

        print_status("Reasoning with local LLM...")
        redirect_observation = self._collect_redirect_observation(state)
        risk_signals_list = knowledge_base.get("risk_signals", []) or []
        auth_session = "authenticated_session" in [str(x).lower() for x in risk_signals_list]
        auth_context = self._get_active_auth_context(knowledge_base)
        auth_first = self._auth_first_mode(state)
        compressed_context = self._refresh_compressed_context_summary(state)
        request_intel = (
            knowledge_base.get("request_intel", {})
            if isinstance(knowledge_base.get("request_intel", {}), dict)
            else {}
        )
        strategic_context = strategic_llm_context(
            state,
            knowledge_base,
            complexity,
            findings=decision_findings,
        )
        try:
            from interfaces.command_system.builtin.agent.vuln_specialists import collect_specialist_hints

            specialist_hints = collect_specialist_hints(
                decision_findings,
                max_hints=3,
            )
        except Exception:
            specialist_hints = []
        packed_knowledge = strategic_context.get("packed_knowledge") or {}
        prompt_payload = build_reason_prompt_payload(
            raw_target=state.raw_target,
            campaign_goal=state.campaign_goal or "",
            auth_first=auth_first,
            strategic_context=strategic_context,
            packed_knowledge=packed_knowledge,
            specialist_hints=specialist_hints,
            compressed_context=compressed_context,
            knowledge_base=knowledge_base,
            redirect_observation=redirect_observation,
            auth_session=auth_session,
            auth_context=auth_context,
            potential_findings=state.potential_findings,
            decision_findings=decision_findings,
            strategic_instruction_extension=strategic_llm_instruction_extension(strategic_context),
        )

        llm_model = resolve_llm_model(state)
        cache_hit = {"value": False}

        def _mark_cache_hit() -> None:
            cache_hit["value"] = True

        llm_response = self._planner.query_agent_reason(
            endpoint=state.llm_endpoint,
            model=llm_model,
            payload=prompt_payload,
            timeout=25,
            goal=str(state.campaign_goal or ""),
            strategic=bool(strategic_context.get("strategic_triggers")),
            on_cache_hit=_mark_cache_hit,
        )
        if not cache_hit["value"]:
            state.metrics.llm_calls += 1

        if not llm_response:
            detail = str(getattr(self._llm, "last_error", "") or "").strip()
            print_warning(
                "Local LLM unavailable, using heuristic prioritization "
                f"(endpoint={state.llm_endpoint}, model={llm_model}"
                f"{'; ' + detail if detail else ''})."
            )
            state.metrics.llm_fallback_count += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings, "Heuristic plan (LLM request failed).", state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
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
        self._enrich_execution_plan_with_playbook(state, decision_findings)
        state.llm_plan["next_best_action"] = self._resolve_next_best_action(
            state, decision_findings, execution_plan=state.execution_plan,
        )
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
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
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
