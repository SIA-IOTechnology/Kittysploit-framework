#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Report phase, operator timeline, and end-of-run debrief."""

from interfaces.command_system.builtin.agent.workflow.imports import *  # noqa: F403


class ReportPhaseMixin:
    """Report phase, operator timeline, and end-of-run debrief."""

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
        self._lifecycle.append_timeline_event(
            state,
            phase,
            summary,
            kind=kind,
            modules=modules,
            results=results,
            extra=extra,
            is_actionable_finding=self._is_actionable_finding,
        )

    def _apply_refutation_panel(self, state: AgentState, findings: List[Any]) -> List[Any]:
        """Run skeptic refutation panel on high-severity contextual findings."""
        if not findings:
            return findings
        try:
            from interfaces.command_system.builtin.agent.refutation_panel import refute_findings_batch
            from interfaces.command_system.builtin.agent.strategic_llm_policy import resolve_llm_model
        except Exception:
            return findings

        llm = self._llm if getattr(state, "llm_local", False) else None
        refuted = refute_findings_batch(
            findings,
            llm_service=llm,
            llm_endpoint=str(getattr(state, "llm_endpoint", "") or ""),
            llm_model=resolve_llm_model(state),
            refuters=3,
            min_severity="medium",
            max_findings=6,
            llm_budget_remaining=lambda: llm_budget_remaining(state),
            on_llm_call=lambda: setattr(
                state.metrics,
                "llm_calls",
                int(getattr(state.metrics, "llm_calls", 0) or 0) + 1,
            ),
        )
        refuted_count = sum(1 for row in refuted if row.get("refutation_blocked"))
        if refuted_count:
            print_warning(f"Refutation panel blocked {refuted_count} overclaimed finding(s).")
        self._append_timeline_event(
            state,
            "analyze",
            f"Refutation panel: {len(refuted)} reviewed, {refuted_count} downgraded.",
            kind="finding",
            extra={"refuted_count": refuted_count, "reviewed": len(refuted)},
        )
        by_key = {
            (str(r.get("path") or ""), str(r.get("message") or "")[:120]): r
            for r in refuted
        }
        merged: List[Any] = []
        for row in findings:
            if not isinstance(row, dict):
                merged.append(row)
                continue
            key = (str(row.get("path") or ""), str(row.get("message") or "")[:120])
            merged.append(by_key.get(key, row))
        return merged

    def _emit_phase_operator_event(self, state: AgentState, phase: str) -> None:
        """Record which operator archetype is active for a workflow phase."""
        try:
            from interfaces.command_system.builtin.agent.operator_archetypes import (
                operator_context_for_phase,
            )

            op = operator_context_for_phase(
                phase,
                campaign_goal=str(getattr(state, "campaign_goal", "") or ""),
            )
            self._append_timeline_event(
                state,
                phase,
                f"Operator active: {op.get('name', 'Coordinator')} ({op.get('archetype', '')})",
                kind="phase_start",
                extra={"operator": op},
            )
        except Exception:
            pass

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

    _DEBRIEF_NOISE_SIGNALS = frozenset({
        "vulnerability_detected",
        "scanner_errors",
        "active_web_probe_completed",
    })

    _DEBRIEF_ENDPOINT_MARKERS: Tuple[Tuple[str, int], ...] = (
        ("phpmyadmin", 50),
        ("/pma", 45),
        ("roundcube", 45),
        ("/webmail", 40),
        ("wp-login", 40),
        ("wp-admin", 38),
        ("/admin", 35),
        ("/login", 32),
        ("/signin", 30),
        ("/auth", 28),
        ("graphql", 28),
        ("swagger", 28),
        ("/api/", 24),
        ("xmlrpc", 22),
        ("/.env", 50),
        ("phpinfo", 40),
        ("/backup", 30),
        ("/debug", 28),
        ("actuator", 30),
        ("manager/html", 40),
    )

    def _shell_obtained_for_debrief(self, state: AgentState) -> bool:
        sessions = list(getattr(state, "new_sessions", None) or [])
        verified = list(getattr(state, "verified_sessions", None) or [])
        if sessions or verified:
            return True
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        signals = {str(s).lower() for s in (kb.get("risk_signals") or [])}
        return bool(signals.intersection({"interactive_shell", "shell_obtained"}))

    def _interesting_endpoints_for_debrief(
        self,
        endpoints: List[Any],
        *,
        limit: int = 8,
    ) -> List[str]:
        scored: List[Tuple[int, str]] = []
        seen = set()
        for raw in endpoints or []:
            path = str(raw or "").strip()
            if not path:
                continue
            key = path.lower()
            if key in seen:
                continue
            seen.add(key)
            # Drop relative/theme/doc junk harvested from HTML (often 404 at site root).
            if key.startswith("/./") or "/./" in key or key.startswith("./"):
                continue
            if any(
                marker in key
                for marker in (
                    "/themes/pmahomme/",
                    "/themes/original/",
                    "/doc/html/",
                )
            ):
                continue
            if any(key.endswith(ext) for ext in (".css", ".js", ".map", ".woff", ".woff2", ".png", ".jpg", ".gif", ".svg", ".ico")):
                continue
            score = 0
            for marker, weight in self._DEBRIEF_ENDPOINT_MARKERS:
                if marker in key:
                    score = max(score, weight)
            for marker in AUTH_PATH_MARKERS:
                if marker in key:
                    score = max(score, 26)
            if score > 0:
                scored.append((score, path))
        scored.sort(key=lambda row: (-row[0], row[1]))
        return [path for _score, path in scored[:limit]]

    def _debrief_findings_rows(self, state: AgentState) -> List[Dict[str, Any]]:
        """Return findings worth showing in the end-of-run debrief.

        Never promote negative scan results that only inherited CRITICAL/HIGH
        severity from module metadata — that produced false "Notable findings".
        """
        findings = [
            row for row in (state.contextual_findings or [])
            if isinstance(row, dict)
            and not row.get("gate_blocked")
            and (
                bool(row.get("vulnerable"))
                or str(row.get("decision_class") or "").lower() in {"exploit", "followup"}
            )
        ]
        if findings:
            return self._deduplicate_findings(findings)
        rows: List[Dict[str, Any]] = []
        for row in (state.results or []):
            if not isinstance(row, dict):
                continue
            if not row.get("vulnerable"):
                continue
            if row.get("gate_blocked"):
                continue
            rows.append(row)
        return self._deduplicate_findings(rows)

    def _print_session_discoveries_debrief(self, state: AgentState) -> None:
        """End-of-run highlight of useful discoveries, even when no shell was obtained."""
        if getattr(state, "target_reachable", None) is False:
            print_warning(
                f"Session discoveries: target unreachable "
                f"({getattr(state, 'reachability_reason', None) or 'no reason'})"
            )
            return

        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        shell = self._shell_obtained_for_debrief(state)
        tech_hints = self._display_tech_hints(kb, limit=8)
        stack_confidence = self._stack_confidence_rows(kb)
        login_paths = [str(x) for x in (kb.get("login_paths") or []) if str(x).strip()]
        endpoints = list(kb.get("discovered_endpoints") or [])
        interesting_endpoints = self._interesting_endpoints_for_debrief(endpoints)
        risk_signals = [
            str(x)
            for x in (kb.get("risk_signals") or [])
            if str(x).strip() and str(x).strip().lower() not in self._DEBRIEF_NOISE_SIGNALS
        ]
        request_intel = kb.get("request_intel") if isinstance(kb.get("request_intel"), dict) else {}
        interesting_requests = []
        seen_traffic_paths = set()
        for row in (request_intel.get("interesting_requests") or []):
            if not isinstance(row, dict):
                continue
            path = str(row.get("path") or row.get("endpoint") or "")
            status = int(row.get("status_code") or 0)
            collapsed = "/" + "/".join(p for p in path.split("/") if p)
            if collapsed in {"/", ""} or path.strip() in {"/", "//"}:
                continue
            if status in {404, 410}:
                continue
            if status in {301, 302, 303, 307, 308} and int(row.get("interesting_score") or 0) < 8:
                # Empty/normalization redirects without strong auth signal.
                reasons = " ".join(str(r) for r in (row.get("reasons") or [])).lower()
                if "authentication" not in reasons and "auth boundary" not in reasons:
                    continue
            if path.lower().startswith("/./") or "/./" in path.lower():
                continue
            if any(
                marker in path.lower()
                for marker in ("/themes/pmahomme/", "/doc/html/", "cover-upload")
            ):
                continue
            interesting_requests.append(row)
            seen_traffic_paths.add(collapsed.lower())
            if len(interesting_requests) >= 5:
                break

        # Surface confirmed panels from detectors even if active HTTP intel missed them.
        finding_blob = " ".join(
            f"{row.get('path', '')} {row.get('module', '')} {row.get('message', '')}".lower()
            for row in (getattr(state, "contextual_findings", None) or [])
            if isinstance(row, dict)
        )
        confirmed_roundcube = "roundcube" in finding_blob
        confirmed_pma = "phpmyadmin" in finding_blob
        for path in login_paths:
            low = path.lower()
            collapsed = "/" + "/".join(p for p in low.split("/") if p)
            if collapsed in seen_traffic_paths or collapsed in {"/", ""}:
                continue
            label = ""
            if confirmed_roundcube and any(
                tok in low for tok in ("/roundcube", "/webmail", "/mail", "/rc")
            ):
                label = "Roundcube webmail"
            elif confirmed_pma and any(
                tok in low for tok in ("/phpmyadmin", "/pma", "/mysql")
            ):
                label = "phpMyAdmin panel"
            if not label:
                continue
            interesting_requests.insert(
                0,
                {
                    "method": "GET",
                    "path": path,
                    "interesting_score": 12,
                    "reasons": ["authentication surface", f"confirmed {label}"],
                    "status_code": 200,
                },
            )
            seen_traffic_paths.add(collapsed)
            if len(interesting_requests) >= 6:
                break
        interesting_requests = interesting_requests[:5]
        findings = self._debrief_findings_rows(state)
        important = [
            row for row in findings
            if bool(row.get("vulnerable"))
            and not row.get("gate_blocked")
            and (
                str(row.get("importance") or row.get("severity") or "").lower()
                in {"critical", "high", "medium"}
                or str(row.get("decision_class") or "").lower() in {"exploit", "followup"}
            )
        ]
        potential = [
            row for row in (getattr(state, "potential_findings", None) or [])
            if isinstance(row, dict)
        ][:5]
        auth_bits = []
        if any(tok in {s.lower() for s in risk_signals} for tok in (
            "credentials_obtained",
            "auth_obtained",
            "session_cookie",
            "login_success",
        )):
            auth_bits.append("authenticated context available")
        if kb.get("captured_cookies") or kb.get("cookie_header"):
            auth_bits.append("cookie context captured")
        if kb.get("credentials") or kb.get("discovered_credentials"):
            auth_bits.append("credential material recorded")

        print_status("Session discoveries")
        if shell:
            session_count = len(list(getattr(state, "new_sessions", None) or []) or list(getattr(state, "verified_sessions", None) or []))
            print_success(f"Shell/session obtained ({session_count or 1})")
        else:
            print_info("No shell obtained - useful discoveries from this run:")

        if tech_hints:
            print_info(f"Stack: {', '.join(tech_hints)}")
        elif stack_confidence:
            print_info(
                "Stack confidence: "
                + ", ".join(f"{name}={score:.2f}" for name, score in stack_confidence[:5])
            )
        if login_paths:
            print_info(f"Login / panel paths: {', '.join(login_paths[:6])}")
        if interesting_endpoints:
            print_info(f"Interesting endpoints: {', '.join(interesting_endpoints)}")
        if risk_signals:
            print_info(f"Signals: {', '.join(risk_signals[:8])}")
        if auth_bits:
            print_info(f"Auth context: {', '.join(auth_bits)}")

        if important:
            print_status("Notable findings")
            for row in important[:6]:
                severity = str(
                    row.get("importance") or row.get("severity") or "info"
                ).upper()
                badge = str(row.get("decision_class") or ("hit" if row.get("vulnerable") else "info")).upper()
                path = str(row.get("path") or row.get("module") or "").strip()
                message = self._shorten_text(row.get("message", ""), 140)
                print_info(f"[{severity}/{badge}] {path}")
                if message:
                    print_info(f"  -> {message}")
        elif potential:
            print_status("Potential leads")
            for row in potential:
                path = str(row.get("path") or row.get("module") or "").strip()
                message = self._shorten_text(row.get("message", ""), 140)
                print_info(f"- {path}" + (f" | {message}" if message else ""))
        elif not shell and not login_paths and not interesting_endpoints and not tech_hints:
            print_warning("No high-signal surface discoveries beyond baseline recon.")

        if interesting_requests:
            print_status("Interesting HTTP traffic")
            for row in interesting_requests:
                method = str(row.get("method") or "GET").upper()
                url = self._shorten_text(row.get("url") or row.get("path") or "", 100)
                score = int(row.get("interesting_score") or 0)
                reasons = ", ".join(str(r) for r in (row.get("reasons") or [])[:3])
                suffix = f" | {reasons}" if reasons else ""
                print_info(f"- {method} {url} (score={score}){suffix}")

        stop_reason = str(getattr(state, "campaign_stop_reason", "") or "").strip()
        if stop_reason and not shell:
            print_info(f"Stop reason: {self._shorten_text(stop_reason, 160)}")

        if not shell:
            next_steps: List[str] = []
            if login_paths or any("login" in s.lower() or "admin_panel" in s.lower() for s in risk_signals):
                next_steps.append("pursue login/panel auth (credential spray or session replay)")
            if any(tok in " ".join(risk_signals).lower() for tok in ("sql", "sqli")):
                next_steps.append("deepen SQLi confirmation / data extraction")
            if any(tok in " ".join(risk_signals).lower() for tok in ("xss",)):
                next_steps.append("confirm XSS impact in authenticated context")
            if interesting_endpoints and not important:
                next_steps.append("manually review interesting endpoints / panels above")
            if not next_steps and (tech_hints or endpoints):
                next_steps.append("expand surface or re-run with a tighter goal (obtain-auth / shell)")
            if next_steps:
                print_info(f"Suggested next: {'; '.join(next_steps[:3])}")

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
        risk_signals = [
            str(x) for x in kb.get("risk_signals", [])
            if str(x).strip() and str(x).strip().lower() not in {"vulnerability_detected", "scanner_errors"}
        ]
        stack_confidence = self._stack_confidence_rows(kb)
        request_intel = kb.get("request_intel", {}) if isinstance(kb.get("request_intel", {}), dict) else {}

        print_status("Detection summary")
        print_info(
            f"Surface: endpoints={len(endpoints)} params={len(params)} "
            f"tech={len(tech_hints)} login_paths={len(login_paths)}"
        )
        if int(request_intel.get("analyzed_flows", 0) or 0) > 0:
            print_info(
                "HTTP request intel: "
                f"flows={request_intel.get('analyzed_flows', 0)} "
                f"interesting={len(request_intel.get('interesting_requests', []) or [])}"
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

        deduped_findings = self._deduplicate_findings(findings)
        top_source = [f for f in deduped_findings if f.get("importance") in ("critical", "high", "medium")]
        top_rows = top_source[:5] if top_source else deduped_findings[:5]
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
            nba_score = nba.get("decision_score")
            nba_conf = nba.get("confidence")
            score_suffix = ""
            if nba_score is not None or nba_conf is not None:
                score_suffix = (
                    f" | score={float(nba_score or 0.0):.2f}"
                    f" conf={float(nba_conf or 0.0):.2f}"
                )
            print_info(
                f"Next action: {nba.get('type')} {nba.get('path', '')} "
                f"| {self._shorten_text(nba.get('reason', ''), 120)}{score_suffix}"
            )

        actions = [a for a in (plan.get("next_actions") or []) if isinstance(a, dict)]
        run_actions = [
            a for a in actions
            if str(a.get("type", "")).lower() in ("run_followup", "run_exploit")
        ][:4]
        if run_actions:
            print_info("Planned actions:")
            for row in run_actions:
                explanation = row.get("decision_explanation", {})
                reason = (
                    explanation.get("reason")
                    if isinstance(explanation, dict)
                    else ""
                ) or self._action_reason_for_path(
                    str(row.get("path", "") or ""),
                    state,
                    state.contextual_findings or state.vulnerable_results,
                )
                score = row.get("decision_score")
                confidence = row.get("confidence")
                score_suffix = ""
                if score is not None or confidence is not None:
                    score_suffix = f" score={float(score or 0.0):.2f} conf={float(confidence or 0.0):.2f}"
                print_info(f"- {row.get('type')} {row.get('path', '')}")
                print_info(f"  because: {self._shorten_text(reason, 120)}{score_suffix}")
                if isinstance(explanation, dict):
                    evidence = explanation.get("evidence", []) or []
                    if evidence:
                        print_info(f"  evidence: {self._shorten_text('; '.join(evidence[:3]), 140)}")
                    rejected = explanation.get("rejected_alternatives", []) or []
                    if rejected:
                        alt = rejected[0]
                        print_info(
                            f"  not {str(alt.get('path', '?')).split('/')[-1]}: "
                            f"{self._shorten_text(str(alt.get('reason', '')), 100)}"
                        )
                    pivot = str(explanation.get("next_pivot", "") or "")
                    if pivot:
                        print_info(f"  next pivot: {pivot.split('/')[-1]}")
                    risk = explanation.get("risk", {}) if isinstance(explanation.get("risk"), dict) else {}
                    if risk.get("level"):
                        print_info(f"  risk: {risk.get('level')} (cost={risk.get('cost', '?')})")

        rationale = llm_plan.get("rationale")
        if rationale:
            print_info(f"Rationale: {self._shorten_text(rationale, 180)}")

    def _node_report(self, state: AgentState) -> AgentState:
        state.metrics.deterministic_steps += 1
        print_status("Generating report...")
        self._append_timeline_event(
            state,
            "report",
            "Generating Markdown and JSON campaign reports.",
            kind="report",
        )
        sync_metrics_from_budget(state)
        if isinstance(state.knowledge_base, dict):
            try:
                state.knowledge_base["module_memory_summary"] = {
                    "performance": self._module_perf.export_summary(),
                    "context": self._module_ctx.export_summary(),
                    "health": self._module_health.export_summary(),
                    "target_profile": classify_target_profile(state.knowledge_base),
                    "operational_context": classify_operational_context(state.knowledge_base),
                }
            except Exception:
                pass
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
            run_id=state.run_id,
            workspace=state.workspace,
            metrics=state.metrics.__dict__,
            campaign_stop_reason=state.campaign_stop_reason,
            network_budget=sync_metrics_from_budget(state),
            runtime_policy={
                "safety_profile": state.safety_profile,
                "dry_run": state.dry_run,
                "plan_only": state.plan_only,
                "tls_verify": bool(
                    getattr(getattr(state, "runtime_policy", None), "tls_verify", True)
                ),
                "mission_profile": str(
                    getattr(getattr(state, "runtime_policy", None), "mission_profile", "") or ""
                ),
                "approved_risks": sorted(
                    str(value)
                    for value in (
                        getattr(getattr(state, "runtime_policy", None), "approved_risks", set())
                        or set()
                    )
                ),
                "session_policy": state.session_policy,
                "random_seed": state.random_seed,
            },
            decision_source=state.decision_source,
        )
        self._report.update_history_scores(
            state.contextual_findings,
            state.new_sessions,
            (state.knowledge_base or {}).get("session_provenance", {}),
        )
        self._update_host_profile_cache(state)
        self._print_timeline_preview(state)
        self._print_session_discoveries_debrief(state)
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
        print_info(f"- network_units_used: {int(getattr(metrics, 'network_units_used', 0) or 0)}")
        print_info(f"- network_units_skipped: {int(getattr(metrics, 'network_units_skipped', 0) or 0)}")
        print_info(f"- deterministic_ratio: {det_ratio:.1f}%")
        print_info(f"- llm_ratio: {llm_ratio:.1f}%")
