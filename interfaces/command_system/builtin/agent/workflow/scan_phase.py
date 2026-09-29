#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan phase: campaign loop, module selection, and shell-hunter waves."""

from interfaces.command_system.builtin.agent.workflow.imports import *  # noqa: F403


class ScanPhaseMixin:
    """Scan phase: campaign loop, module selection, and shell-hunter waves."""

    def _node_scan(self, state: AgentState) -> AgentState:
        state.metrics.deterministic_steps += 1
        if state.dry_run:
            print_status("Building agent dry-run plan...")
            all_modules = self._catalog.discover_campaign_modules(
                expanded=bool(getattr(state, "expanded_surface", False)),
            )
            modules = self._select_modules_for_target(state, all_modules)
            selected = list(modules[: max(1, int(state.max_modules or 1))])
            state.results = [
                {
                    "module": row.get("name", row.get("path")),
                    "path": row.get("path"),
                    "status": "planned",
                    "vulnerable": False,
                    "message": "dry-run: no module executed",
                    "details": {
                        "risk": assess_module_risk(
                            row,
                            str(row.get("path", "")),
                        ).level,
                    },
                }
                for row in selected
            ]
            state.execution_plan = {
                "next_actions": [
                    {
                        "type": "prioritize",
                        "path": row.get("path"),
                        "priority": index,
                    }
                    for index, row in enumerate(selected, start=1)
                ],
                "max_requests_next_phase": 0,
                "stop_conditions": ["dry_run_complete"],
                "reasoning_confidence": 1.0,
                "skip_exploitation": True,
            }
            state.llm_plan = {
                "selected_paths": [row.get("path") for row in selected if row.get("path")],
                "rationale": "Dry-run plan generated without network traffic.",
                "next_best_action": None,
            }
            state.campaign_stop_reason = "dry_run_complete"
            self._append_timeline_event(
                state,
                "scan",
                f"Dry-run selected {len(selected)} module(s); no traffic sent.",
                kind="plan",
                modules=selected,
            )
            return state
        print_status("Scanning target...")
        request_intel_results = self._ingest_http_request_intelligence(state)
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
            hostname = str((state.target_info or {}).get("hostname", "") or "").strip()
            passive_osint_ok = (
                getattr(state, "expanded_surface", False)
                and self._hostname_is_osint_domain(hostname)
            )
            if getattr(state, "expanded_surface", False) and not passive_osint_ok:
                state.results = list(request_intel_results)
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
                    "rationale": f"Target unreachable (IP or invalid domain): {reason}",
                    "next_best_action": None,
                }
                state.campaign_stop_reason = "target_unreachable"
                print_warning(
                    f"Primary target unreachable ({reason}); stopping campaign "
                    "(OSINT requires a domain, not an IP)."
                )
                return state
            if passive_osint_ok:
                print_warning(
                    f"Primary target unreachable ({reason}); skipping active HTTP scan "
                    "(passive OSINT may continue)."
                )
                state.campaign_stop_reason = "target_unreachable_passive_only"
            elif self._has_proxy_request_intel(state):
                state.results = list(request_intel_results)
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
                    "rationale": (
                        f"Target unreachable by direct probe ({reason}), but matching "
                        "KittyProxy requests were analyzed."
                    ),
                    "next_best_action": None,
                }
                state.campaign_stop_reason = "target_unreachable_with_proxy_request_intel"
                print_warning(
                    f"Target unreachable by direct probe, using captured HTTP request intelligence: {reason}"
                )
                return state
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
        if state.campaign_stop_reason:
            print_warning(f"Campaign paused: {state.campaign_stop_reason}")
            state.results = list(request_intel_results)
            state.vulnerable_results = []
            state.contextual_findings = []
            state.sql_findings = []
            state.potential_findings = []
            state.execution_plan = {
                "next_actions": [],
                "max_requests_next_phase": 0,
                "stop_conditions": ["waf_or_blocking_detected"],
                "reasoning_confidence": 1.0,
                "skip_exploitation": True,
            }
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

        results = list(request_intel_results)
        if getattr(state, "expanded_surface", False):
            intel_results = self._run_expanded_surface_intel_phase(state, all_modules)
            results.extend(intel_results)

        scan_results = self._run_scan_campaign(state, modules, scanner)
        results.extend(scan_results)

        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
            extra_paths = [
                str(p).split("?", 1)[0]
                for p in (kb.get("discovered_endpoints", []) or [])
                if isinstance(p, str) and p.startswith("/")
            ][:16]
            if extra_paths:
                _, probe_rows = self._run_active_web_surface_probe(
                    state,
                    extra_paths=extra_paths,
                    max_requests=min(10, len(extra_paths)),
                )
                results.extend(probe_rows)

        if not results:
            state.error = "No relevant modules selected after intelligent scan campaign."
            return state

        if getattr(state, "expanded_surface", False):
            results = self._run_derived_host_surface_scans(state, scanner, all_modules, results)
        elif is_shell_operator_goal(self._operator_campaign_goal(state)):
            kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
            if kb.get("subdomain_candidates") or kb_subdomain_surface_expandable(kb):
                results = self._run_derived_host_surface_scans(state, scanner, all_modules, results)

        state.results = results
        state.vulnerable_results = deduplicate_scanner_results(
            [r for r in results if self._is_actionable_finding(r)],
            target_info=state.target_info,
        )
        self._ingest_sessions_from_scan_results(state, results)
        self._sync_campaign_goal(state)
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
        if state.target_reachable is False:
            if bool(state.verbose):
                print_info("Scan campaign skipped: target unreachable.")
            return []
        verbose = bool(state.verbose)
        max_modules = int(state.max_modules)
        threads = int(state.threads)
        self._sync_campaign_goal(state)
        if isinstance(state.knowledge_base, dict):
            state.knowledge_base["planner_campaign_goal"] = state.campaign_goal or ""
        # Avoid mixed/interleaved module output in verbose mode: run campaign
        # phases sequentially so logs remain attributable to the right module.
        phase_threads = 1 if verbose or self._discreet_mode(state) else max(2, min(threads, 8))
        forced_protocol = state.protocol

        # For non-web explicit protocol scans, keep bounded one-pass behavior.
        if forced_protocol and forced_protocol not in ("http", "https"):
            selected = modules[:max_modules]
            if is_shell_operator_goal(state.campaign_goal) or bool(getattr(state, "shell_hunter", False)):
                seen = {module_path_lower(m) for m in selected}
                for module in modules:
                    path = module_path_lower(module)
                    if f"auxiliary/scanner/{forced_protocol}/" in path and path not in seen:
                        selected.append(module)
                        seen.add(path)
                selected = selected[:max_modules]
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
            self._ingest_sessions_from_scan_results(state, single_pass_results)
            return self._finalize_scan_campaign(
                state,
                modules,
                scanner,
                single_pass_results,
                {m.get("path") for m in selected if m.get("path")},
                max(2, min(threads, 8)),
                {str(x).lower() for x in (state.knowledge_base or {}).get("tech_hints", [])},
            )

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
            min(6, max_modules),
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
            self._ingest_sessions_from_scan_results(state, cms_probe_results)
            if state.campaign_stop_reason:
                return self._finalize_scan_campaign(
                    state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
                )
            if self._has_shell_milestone(state):
                return self._finalize_scan_campaign(
                    state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
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

        # Obtain-shell + known lab product: do not burn the request budget on
        # recon/CVE spray before auth→RCE (with listener) completes.
        focus_product = product_chain_still_pending(
            state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        )
        if focus_product and (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or bool(getattr(state, "shell_hunter", False))
        ):
            recon_budget = 0
            crawl_budget = 0
            inject_budget = 0
            specialized_budget = 0
            if verbose:
                print_status(
                    f"Product-focus `{focus_product}` + obtain-shell: "
                    "skipping recon/CVE spray until shell chain completes."
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
            self._log_opportunistic_pick(
                phase_name, selected, state, tech_hints, set(executed_paths),
                candidate_pool=phase_modules,
            )
            snapshot_before = self._snapshot_campaign_state(state, all_results)
            if verbose:
                print_status(f"Phase {phase_name}: executing {len(selected)} module(s)")
            crawl_overrides = self._build_inferred_option_overrides(selected, state)
            if phase_name == "crawl":
                phase_results = self._execute_plan_modules_with_options(
                    selected,
                    state,
                    option_overrides=crawl_overrides,
                    verbose=verbose,
                )
            else:
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
                return self._finalize_scan_campaign(
                    state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
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
                    phase_name,
                )
            stop_now, no_novelty_streak, stop_reason = self._evaluate_campaign_stop(
                phase_name,
                phase_results,
                snapshot_before,
                self._snapshot_campaign_state(state, all_results),
                no_novelty_streak,
                state,
            )
            if stop_now:
                state.campaign_stop_reason = stop_reason
                if verbose:
                    print_warning(f"Aggressive stop: {stop_reason}")
                break

        if state.campaign_stop_reason:
            return self._finalize_scan_campaign(
                state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
            )

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
                    self._log_opportunistic_pick(
                        "injection", inject_selected, state, tech_hints, set(executed_paths),
                        candidate_pool=inject_candidates,
                    )
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
                        state,
                    )
                    if stop_now:
                        state.campaign_stop_reason = stop_reason
                        if verbose:
                            print_warning(f"Aggressive stop: {stop_reason}")
                        return self._finalize_scan_campaign(
                            state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
                        )

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
                self._log_opportunistic_pick(
                    "adaptive", specialized_selected, state, tech_hints, set(executed_paths),
                    candidate_pool=specialized_modules,
                )
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
                    state,
                )
                if stop_now:
                    state.campaign_stop_reason = stop_reason
                    if verbose:
                        print_warning(f"Aggressive stop: {stop_reason}")
                    return self._finalize_scan_campaign(
                        state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
                    )
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
                self._log_opportunistic_pick(
                    "follow-up", followup_selected, state, tech_hints, set(executed_paths),
                    candidate_pool=followup_modules,
                )
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
                    phase="follow-up",
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
                    state,
                )
                if stop_now:
                    state.campaign_stop_reason = stop_reason
                    if verbose:
                        print_warning(f"Aggressive stop: {stop_reason}")
                    return self._finalize_scan_campaign(
                        state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
                    )

            post_auth_budget = min(12, max(3, max_modules - len(executed_paths)))
            if self._discreet_mode(state):
                post_auth_budget = min(5, max(2, max_modules - len(executed_paths)))
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
                    state,
                )
                if stop_now:
                    state.campaign_stop_reason = stop_reason
                    if verbose:
                        print_warning(f"Aggressive stop: {stop_reason}")
                    return self._finalize_scan_campaign(
                        state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
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

    def _finalize_scan_campaign(
        self,
        state: AgentState,
        modules,
        scanner,
        all_results: List[Any],
        executed_paths: set,
        phase_threads: int,
        tech_hints: set,
    ) -> List[Any]:
        """
        Central scan exit: classify stop reason, run shell-hunter macro when allowed.

        Soft stops (low novelty, no pivots) are cleared so obtain-shell can continue.
        Hard stops (WAF, policy, budget, unreachable) preserve ``campaign_stop_reason``.
        """
        verbose = bool(state.verbose)
        self._ingest_sessions_from_scan_results(state, all_results)
        pending_reason = state.campaign_stop_reason
        if pending_reason and self._is_soft_campaign_stop_reason(pending_reason):
            if verbose:
                print_info(
                    f"Soft campaign stop deferred to shell-hunter finalization: {pending_reason}"
                )
            state.campaign_stop_reason = None
        elif pending_reason and self._is_hard_campaign_stop_reason(pending_reason):
            text = str(pending_reason).lower()
            if "budget" in text and self._maybe_extend_budget_for_shell_chain(state):
                if verbose:
                    print_info(
                        f"Hard budget stop deferred for product shell chain: {pending_reason}"
                    )
            elif verbose:
                print_info(f"Hard campaign stop (shell-hunter skipped): {pending_reason}")

        if self._should_run_shell_hunter_finalization(state):
            all_results = self._run_shell_hunter_macro_wave(
                state,
                modules,
                scanner,
                all_results,
                executed_paths,
                phase_threads,
                tech_hints,
            )

        state.scan_tech_hints = sorted(tech_hints)
        state.scan_modules_executed = len(executed_paths)
        return all_results

    def _run_shell_hunter_macro_wave(
        self,
        state: AgentState,
        modules: List[Dict[str, Any]],
        scanner: ScannerCommand,
        all_results: List[Any],
        executed_paths: set,
        phase_threads: int,
        tech_hints: set,
    ) -> List[Any]:
        """
        Persistent obtain-shell loop after phased campaign.

        Runs strategic followups/exploits until shell, budget exhaustion, or hard stop (WAF).
        """
        if not (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or bool(getattr(state, "shell_hunter", False))
        ):
            return all_results
        if self._has_shell_milestone(state):
            return all_results

        if self._is_soft_campaign_stop_reason(state.campaign_stop_reason):
            state.campaign_stop_reason = None

        modules_by_path = {
            str(m.get("path", "")).strip(): m
            for m in modules or []
            if m.get("path")
        }
        verbose = bool(state.verbose)
        # Do not starve the DVWA/auth chain because recon already consumed max_modules
        # on unrelated CVE detectors.
        max_rounds = SHELL_HUNTER_MACRO_MAX_ROUNDS

        for round_idx in range(max_rounds):
            if self._has_shell_milestone(state):
                break
            if state.campaign_stop_reason and not self._is_soft_campaign_stop_reason(state.campaign_stop_reason):
                break

            kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
            findings = list(state.vulnerable_results or state.contextual_findings or [])
            action = self._next_best_action_for_shell_goal(state, kb, findings) or {}
            path = str(action.get("path", "") or "").strip()
            action_type = str(action.get("type", "run_followup") or "run_followup").lower()
            wrapper_attempts = {
                str(x).strip().lower()
                for x in (kb.get("product_shell_wrapper_attempts") or [])
                if str(x).strip()
            }
            wrapper_leaves = {a.rsplit("/", 1)[-1] for a in wrapper_attempts}

            def _path_done(candidate: str) -> bool:
                token = str(candidate or "").strip()
                if not token:
                    return True
                if token not in executed_paths:
                    return False
                # Exploit previously run via scanner (no listener) may be in
                # executed_paths without a wrapper attempt — allow one retry.
                if token.startswith(("exploit/", "exploits/")):
                    low = token.lower()
                    leaf = low.rsplit("/", 1)[-1]
                    if low not in wrapper_attempts and leaf not in wrapper_leaves:
                        return False
                return True

            if not path or _path_done(path):
                path = ""
                for candidate in suggest_shell_plan_followups(
                    kb,
                    state,
                    self._catalog.discover_campaign_modules(expanded=True),
                ):
                    if not _path_done(candidate):
                        path = candidate
                        action_type = (
                            "run_exploit"
                            if path.startswith(("exploit/", "exploits/"))
                            else "run_followup"
                        )
                        break
            if not path or _path_done(path):
                break

            if self._module_block_reason_for_profile(state, path):
                executed_paths.add(path)
                continue
            mismatch = self._module_hard_stack_skip_reason(path, kb)
            if mismatch:
                executed_paths.add(path)
                if verbose:
                    print_warning(f"Shell-hunter skip [{path}]: {mismatch}")
                continue

            kb_pre = kb_light_copy(kb)
            if verbose:
                print_status(f"Shell-hunter macro ({round_idx + 1}/{max_rounds}): {path}")

            wrapper_attempts = {
                str(x).strip().lower()
                for x in (kb.get("product_shell_wrapper_attempts") or [])
                if str(x).strip()
            }
            needs_wrapper_retry = (
                path.startswith(("exploit/", "exploits/"))
                and path.lower() not in wrapper_attempts
                and path.rsplit("/", 1)[-1].lower() not in {a.rsplit("/", 1)[-1] for a in wrapper_attempts}
            )

            if (action_type == "run_exploit" or needs_wrapper_retry) and not state.no_exploit:
                self._execute_exploit_results_with_options(
                    [],
                    state.target_info,
                    state=state,
                    explicit_exploit_paths=[path],
                    verbose=verbose,
                )
                executed_paths.add(path)
                if isinstance(kb, dict):
                    observed = set(kb.get("observed_modules", []) or [])
                    observed.add(path)
                    kb["observed_modules"] = sorted(observed)
                if self._has_shell_milestone(state):
                    break
                continue

            module = modules_by_path.get(path) or {
                "path": path,
                "name": path.rsplit("/", 1)[-1],
                "description": "",
            }

            phase_results = self._execute_agent_modules(
                state,
                scanner,
                [module],
                state.target_info,
                phase_threads,
                False,
                "shell-hunter",
            )
            all_results.extend(phase_results)
            executed_paths.add(path)
            phase_hints = self._extract_tech_hints(phase_results)
            tech_hints.update(phase_hints)
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                phase_results,
                [path],
                phase_hints,
                set(),
                phase="shell-hunter",
            )
            self._record_module_performance_phase(state, kb_pre, phase_results, "shell-hunter")
            self._append_timeline_event(
                state,
                "shell-hunter",
                f"Shell-hunter macro step {round_idx + 1}: {path}",
                modules=[module],
                results=phase_results,
            )
            if self._has_shell_milestone(state):
                break

        state.scan_modules_executed = len(executed_paths)
        return all_results

    def _probe_and_filter_live_derived_hosts(
        self,
        state: AgentState,
        hosts: List[str],
    ) -> List[str]:
        """HTTP probe derived candidates; keep live hosts sorted by subdomain priority."""
        if not hosts:
            return []
        from interfaces.command_system.builtin.agent.goal_planner import score_subdomain_host

        live_statuses = set(DERIVED_HOST_LIVE_STATUSES)
        ranked: List[Tuple[int, int, str]] = []

        for host in prioritize_subdomain_hosts(hosts):
            live_hits = 0
            for scheme in ("https", "http"):
                urls = [f"{scheme}://{host}{path}" for path in DERIVED_HOST_PROBE_PATHS]
                rows = self._http_probe_many(state, urls, timeout_s=3, read_bytes=1024)
                live_hits = sum(
                    1 for row in rows
                    if int(row.get("status") or 0) in live_statuses
                )
                if live_hits:
                    break
            if not live_hits:
                continue
            ranked.append((-score_subdomain_host(host), -live_hits, host))

        ranked.sort()
        live_hosts = [host for _, _, host in ranked]
        kb = state.knowledge_base
        if isinstance(kb, dict):
            kb["derived_host_probe"] = {
                "candidates": len(hosts),
                "live": len(live_hosts),
                "hosts": live_hosts[:24],
            }
        return live_hosts

    def _compute_adaptive_budgets(self, state: AgentState) -> Dict[str, int]:
        max_modules = int(state.max_modules)
        kb = state.knowledge_base
        confidence = kb.get("tech_confidence", {}) if isinstance(kb, dict) else {}
        info_score = information_score_kb(kb if isinstance(kb, dict) else {})
        endpoint_count = len((kb or {}).get("discovered_endpoints", []) or []) if isinstance(kb, dict) else 0
        hint_count = len((kb or {}).get("tech_hints", []) or []) if isinstance(kb, dict) else 0
        has_auth = self._has_authenticated_session(kb) or self._credential_milestone_reached(kb)
        auth_focus = self._should_prioritize_auth_surface(kb)
        exploit_pressure = self._has_exploit_pressure(state)
        cms_conf = max(
            float(confidence.get("wordpress", 0.0) or 0.0),
            float(confidence.get("drupal", 0.0) or 0.0),
            float(confidence.get("joomla", 0.0) or 0.0),
        )
        cms_high = cms_conf >= 0.75
        if self._discreet_mode(state):
            if exploit_pressure:
                return {
                    "recon": min(max_modules, max(2, max_modules // 8)),
                    "crawl": 0,
                    "inject": max(2, max_modules // 6),
                    "specialized": max(4, max_modules // 3),
                    "followup": max(5, max_modules // 3),
                }
            if has_auth:
                return {
                    "recon": min(max_modules, max(2, max_modules // 6)),
                    "crawl": 0,
                    "inject": max(1, max_modules // 10),
                    "specialized": max(4, max_modules // 3),
                    "followup": max(4, max_modules // 3),
                }
            if cms_high:
                return {
                    "recon": min(max_modules, 3),
                    "crawl": 0,
                    "inject": 0,
                    "specialized": max(4, max_modules // 3),
                    "followup": max(3, max_modules // 4),
                }
            if auth_focus:
                return {
                    "recon": min(max_modules, 3),
                    "crawl": 0,
                    "inject": 0,
                    "specialized": max(2, max_modules // 5),
                    "followup": max(4, max_modules // 3),
                }
            if info_score <= 4.0 and endpoint_count <= 2 and hint_count <= 2:
                return {
                    "recon": min(max_modules, 4),
                    "crawl": 1,
                    "inject": 1,
                    "specialized": max(2, max_modules // 5),
                    "followup": max(2, max_modules // 6),
                }
            return {
                "recon": min(max_modules, max(3, int(state.recon_modules))),
                "crawl": 0,
                "inject": 1,
                "specialized": max(3, max_modules // 4),
                "followup": max(3, max_modules // 5),
            }
        if exploit_pressure:
            return {
                "recon": min(max_modules, max(3, max_modules // 8)),
                "crawl": 0,
                "inject": max(4, max_modules // 3),
                "specialized": max(8, max_modules // 2),
                "followup": max(10, (max_modules * 3) // 5),
            }
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
        candidates = self._filter_catalog_candidates_for_policy(
            state,
            [m for m in (candidates or []) if isinstance(m, dict)],
            phase=str(getattr(state, "current_phase", "") or "catalog"),
        )
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        if isinstance(state.knowledge_base, dict):
            operator = self._operator_campaign_goal(state)
            if operator:
                state.knowledge_base["operator_campaign_goal"] = operator
            if state.campaign_goal:
                state.knowledge_base["planner_campaign_goal"] = state.campaign_goal
            kb = state.knowledge_base
        # Drop hard stack mismatches before ranking so limit slots go to compatible modules.
        if kb:
            candidates = [
                m for m in candidates
                if not self._module_hard_stack_skip_reason(str(m.get("path", "") or ""), kb)
            ]
        selected = select_opportunistic_batch(
            candidates,
            kb,
            tech_hints,
            executed_paths,
            limit,
            self._module_perf,
            self._module_ctx,
            self._module_health,
            self._learning,
            state,
        )
        return self._pin_shell_priority_modules(
            selected,
            candidates,
            state,
            executed_paths,
            limit,
        )

    def _pin_shell_priority_modules(
        self,
        selected,
        candidates,
        state: AgentState,
        executed_paths: set,
        limit: int,
    ):
        """
        Keep auth→product exploit modules at the front of a phase batch.

        Applies for obtain-shell / shell-hunter and for high-confidence lab apps
        (DVWA) even when the operator goal was left implicit. Missing chain
        modules are injected so recon/CVE pools cannot hide bruteforce.
        """
        operator = self._operator_campaign_goal(state)
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        lab_chain = product_auth_shell_followups(kb, state)
        if not (
            is_shell_operator_goal(operator)
            or is_exploit_operator_goal(operator)
            or bool(getattr(state, "shell_hunter", False))
            or bool(lab_chain)
        ):
            return selected
        priority_paths = []
        for path in lab_chain:
            if path and path not in executed_paths and path not in priority_paths:
                priority_paths.append(path)
        for path in suggest_shell_plan_followups(
            kb,
            state,
            candidates if isinstance(candidates, list) else None,
        ):
            if path and path not in executed_paths and path not in priority_paths:
                priority_paths.append(path)
        # Also pin preferred post-auth exploits when a session already exists.
        if self._has_authenticated_session(kb):
            for path in self._preferred_post_auth_exploit_paths(kb):
                if path and path not in executed_paths and path not in priority_paths:
                    priority_paths.append(path)
        if not priority_paths:
            return selected

        by_path = {
            str(m.get("path", "") or ""): m
            for m in (candidates or [])
            if isinstance(m, dict) and m.get("path")
        }
        pinned = []
        seen = set()
        inject_budget = 4
        for path in priority_paths:
            if self._module_block_reason_for_profile(state, path):
                continue
            mod = by_path.get(path)
            if mod is None:
                if inject_budget <= 0:
                    continue
                inject_budget -= 1
                mod = {"path": path, "name": path.rsplit("/", 1)[-1], "description": ""}
            pinned.append(mod)
            seen.add(path)
            if len(pinned) >= max(1, int(limit or 1)):
                break
        if not pinned:
            return selected
        # Obtain-shell / known lab product: do not dilute the batch with unrelated
        # CMS detectors (wordpress/phpmyadmin) that burn the request budget before
        # auth→shell completes.
        if lab_chain and (
            is_shell_operator_goal(operator)
            or is_exploit_operator_goal(operator)
            or bool(getattr(state, "shell_hunter", False))
        ):
            return pinned[: max(1, int(limit or len(pinned)))]
        rest = [
            m for m in (selected or [])
            if isinstance(m, dict) and str(m.get("path", "") or "") not in seen
        ]
        merged = pinned + rest
        return merged[: max(1, int(limit or len(merged)))]

    def _build_module_decision_report(
        self,
        module: Dict[str, Any],
        state: AgentState,
        tech_hints: set,
        executed_paths: set,
        *,
        phase_label: str = "",
        candidate_pool: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        path = str(module.get("path", "") or "").strip()
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        score = unified_module_score(
            module,
            kb,
            tech_hints,
            executed_paths,
            self._module_perf,
            self._module_ctx,
            self._module_health,
            self._learning,
            state,
        )
        reason = self._action_reason_for_path(
            path,
            state,
            state.contextual_findings or state.vulnerable_results,
        )
        scored: List[tuple] = []
        policy_rejected: List[Dict[str, str]] = []
        for row in candidate_pool or []:
            if not isinstance(row, dict) or not row.get("path"):
                continue
            row_path = str(row.get("path", "") or "").strip()
            block_reason = self._module_block_reason_for_profile(state, row_path, row)
            if block_reason:
                policy_rejected.append({
                    "path": row_path,
                    "reason": f"blocked by policy: {block_reason}",
                })
                continue
            g = unified_module_score(
                row,
                kb,
                tech_hints,
                executed_paths,
                self._module_perf,
                self._module_ctx,
                self._module_health,
                self._learning,
                state,
            )
            if g is None:
                g = -1.0
            scored.append((float(g), row))
        scored.sort(key=lambda item: (item[0], str(item[1].get("path", ""))), reverse=True)

        from interfaces.command_system.builtin.agent.decision_report import infer_rejected_scored_alternatives

        rejected = infer_rejected_scored_alternatives(path, candidate_pool or [], scored)
        rejected = policy_rejected[:4] + [
            row for row in rejected
            if row.get("path") not in {item.get("path") for item in policy_rejected}
        ]
        matching = self._action_matching_findings(path, state.contextual_findings or state.vulnerable_results)
        low = path.lower()
        risk_cost = float(estimate_network_cost(low))
        evidence, tradeoffs = self._module_memory_decision_notes(path, state)
        return build_action_decision_report(
            path,
            "run_module",
            kb,
            campaign_goal=str(getattr(state, "campaign_goal", "") or ""),
            reason=reason,
            matching_finding=matching[0] if matching else None,
            stack_mismatch_fn=self._module_stack_mismatch_reason,
            rejected_alternatives=rejected,
            evidence=evidence,
            tradeoffs=tradeoffs,
            score=float(score or 0.0),
            confidence=0.55 if score and score > 0 else 0.35,
            risk_cost=risk_cost,
        )

    def _module_memory_decision_notes(
        self,
        path: str,
        state: AgentState,
    ) -> Tuple[List[str], List[str]]:
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        evidence: List[str] = []
        tradeoffs: List[str] = []
        if not path:
            return evidence, tradeoffs
        try:
            perf = float(self._module_perf.utility_multiplier(path, kb))
            profile = classify_target_profile(kb)
            evidence.append(f"performance_memory={perf:.2f}@{profile}")
            if perf < 0.9:
                tradeoffs.append(f"historical performance down-weighted ({perf:.2f})")
            elif perf > 1.08:
                evidence.append("historical performance boosted")
        except Exception:
            pass
        try:
            ctxm = float(self._module_ctx.context_multiplier(path, kb))
            context = classify_operational_context(kb)
            evidence.append(f"context_memory={ctxm:.2f}@{context}")
            if ctxm < 0.9:
                tradeoffs.append(f"context memory down-weighted ({ctxm:.2f})")
            elif ctxm > 1.08:
                evidence.append("context memory boosted")
        except Exception:
            pass
        try:
            health = float(self._module_health.health_multiplier(path, kb))
            evidence.append(f"health_memory={health:.2f}")
            if health < 0.85:
                tradeoffs.append(f"recent failures down-weighted ({health:.2f})")
        except Exception:
            pass
        return evidence[:6], tradeoffs[:4]

    def _log_opportunistic_pick(
        self,
        phase_label: str,
        selected: list,
        state: AgentState,
        tech_hints: set,
        executed_paths_before: set,
        *,
        candidate_pool: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        if not selected:
            return
        if state.verbose:
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
                    self._module_health,
                    self._learning,
                    state,
                )
                parts.append(f"{tail}={u:.2f}")
            kb_s = information_score_kb(state.knowledge_base)
            print_info(
                f"[{phase_label}] opportunistic utility order | KB info≈{kb_s:.2f} | " + ", ".join(parts)
            )
        for module in selected[:8]:
            if not isinstance(module, dict):
                continue
            report = self._build_module_decision_report(
                module,
                state,
                tech_hints,
                executed_paths_before,
                phase_label=phase_label,
                candidate_pool=candidate_pool,
            )
            path = str(module.get("path", "") or "")
            self._append_timeline_event(
                state,
                phase_label,
                str(report.get("chosen", path))[:240],
                kind="module_decision",
                modules=[module],
                extra={"decision_explanation": report, "path": path},
            )
            if state.verbose:
                rejected = report.get("rejected_alternatives", []) or []
                if rejected:
                    alt = rejected[0]
                    print_info(
                        f"  not {alt.get('path', '?').split('/')[-1]}: "
                        f"{self._shorten_text(str(alt.get('reason', '')), 90)}"
                    )
            try:
                rejected = report.get("rejected_alternatives", []) or []
                if rejected:
                    self._learning.record_preferences(
                        state,
                        chosen_path=path,
                        rejected_alternatives=rejected,
                        outcome=phase_label,
                    )
            except Exception:
                pass
            if state.verbose:
                pivot = str(report.get("next_pivot", "") or "")
                if pivot:
                    print_info(f"  next pivot: {pivot.split('/')[-1]}")

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
            "sqli_engine", "sql_injection", "sqli", "django_sqli", "xss", "lfi", "rfi", "ssrf",
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

    def _pick_specialized_modules(self, modules, specializations, knowledge_base=None):
        """
        Pick modules matching adaptive specialization buckets.
        """
        if not specializations:
            return []

        kb = knowledge_base if isinstance(knowledge_base, dict) else {}

        specialization_tokens = {
            "wordpress": ("wordpress", "wp_", "wp-", "wpvivid", "wp_plugin"),
            "drupal": ("drupal",),
            "joomla": ("joomla",),
            "dvwa": ("dvwa",),
            "mutillidae": ("mutillidae",),
            "bwapp": ("bwapp",),
            "webgoat": ("webgoat",),
            "phpmyadmin": ("phpmyadmin", "/pma/", "pma_"),
            "grafana": ("grafana",),
            "jenkins": ("jenkins",),
            "tomcat": ("tomcat", "manager/html"),
            "roundcube": ("roundcube", "webmail"),
            "python_web": ("django", "flask", "fastapi", "python_injection"),
            "node_web": ("nodejs", "nextjs", "react", "angular", "vue"),
            "nextjs": ("nextjs", "next_js", "next-", "_next", "js_endpoint", "webhook", "api_leak"),
            # Avoid bare "api" — it matches thousands of unrelated module paths.
            "api": ("api_fuzzer", "swagger", "graphql", "api_bola", "api_leak"),
            # Avoid bare "admin"/"login" — they match printer/router LFI junk.
            "admin_surface": ("grafana", "jenkins", "tomcat", "phpmyadmin", "roundcube", "admin_panel"),
        }

        tokens = set()
        for key in specializations:
            for token in specialization_tokens.get(key, ()):
                tokens.add(token)

        # Dominant lab/product: always keep its modules even if token set is noisy.
        dominant = dominant_product_stack(kb, threshold=0.6) or ""
        if dominant:
            for token in specialization_tokens.get(dominant, (dominant,)):
                tokens.add(token)

        picked = []
        picked_paths = set()
        strong_wordpress = self._has_tech_evidence(kb, "wordpress", threshold=0.8)
        cms_lock = self._get_cms_lock_specializations(kb, specializations)
        for module in modules:
            path = str(module.get("path", "") or "")
            blob = module_blob_lower(module)
            # Skip unrelated CMS modules only when we are not CMS-locked.
            # Exception: never skip modules for the dominant non-CMS product.
            if not cms_lock and any(token in blob for token in CMS_HINT_TOKENS):
                if not (dominant and dominant in blob):
                    continue
            if "wordpress_madara" in blob and not strong_wordpress:
                continue
            if any(token in blob for token in tokens):
                picked.append(module)
                picked_paths.add(path)
                continue
            if kb_client_js_surface_ready(kb) and path in CLIENT_JS_INTEL_MODULES:
                picked.append(module)
                picked_paths.add(path)
                continue
            if "nextjs" in specializations and path in CLIENT_JS_INTEL_MODULES:
                picked.append(module)
                picked_paths.add(path)

        # Force product + auth chain modules into the specialized pool for shell chase.
        force_paths = []
        if dominant == "dvwa" or "dvwa" in specializations:
            force_paths.extend([
                "auxiliary/scanner/http/login/admin_login_bruteforce",
                "exploits/ctf/dvwa_rce",
                "exploits/ctf/dvwa_file_upload",
            ])
        elif dominant in ("mutillidae", "bwapp", "webgoat") or dominant in specializations:
            force_paths.append("auxiliary/scanner/http/login/admin_login_bruteforce")
        if not self._has_authenticated_session(kb):
            login_signals = {
                str(s).lower() for s in kb.get("risk_signals", []) or []
            }.intersection({
                "login_surface_detected",
                "login_redirect_detected",
                "login_form_detected",
            })
            if login_signals or any(
                isinstance(p, str) and p.startswith("/") for p in kb.get("login_paths", []) or []
            ):
                force_paths.insert(0, "auxiliary/scanner/http/login/admin_login_bruteforce")

        if force_paths:
            by_path = {
                str(m.get("path", "") or ""): m
                for m in modules
                if isinstance(m, dict) and m.get("path")
            }
            forced = []
            for path in force_paths:
                if path in picked_paths:
                    continue
                mod = by_path.get(path)
                if mod is not None:
                    forced.append(mod)
                    picked_paths.add(path)
            if forced:
                picked = forced + picked
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
            if s in ("graphql_surface_detected", "api_surface_detected", "js_sourcemap_recovered"):
                detection_tokens.add("api")
                detection_tokens.add("javascript")
        for h in tech_hints_lower:
            if not auth_session and h in ("auth_portal", "login"):
                detection_tokens.add("login_surface")
            if h in ("nextjs", "react", "nodejs", "api", "graphql", "swagger"):
                detection_tokens.add(h)

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
                "nextjs", "next.js", "/_next/", "__next_data__", "javascript",
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
                "scanner/http/phpmyadmin_setup_detect",
            ),
            "roundcube": (
                "scanner/http/roundcube_webmail_portal_detect",
                "scanner/http/roundcube_installer_detect",
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
            "nextjs": CLIENT_JS_INTEL_MODULES,
            "next.js": CLIENT_JS_INTEL_MODULES,
            "/_next/": CLIENT_JS_INTEL_MODULES,
            "__next_data__": CLIENT_JS_INTEL_MODULES,
            "javascript": CLIENT_JS_INTEL_MODULES,
            "react": CLIENT_JS_INTEL_MODULES,
            "nodejs": CLIENT_JS_INTEL_MODULES + (
                "auxiliary/scanner/http/nodejs_injection",
            ),
            "api": (
                "scanner/http/swagger_detect",
                "scanner/http/graphql_detect",
                "auxiliary/scanner/http/api_fuzzer",
            ),
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

        for path in suggest_chain_module_paths(kb):
            wanted.add(path)

        # Obtain-shell / known lab apps: keep auth→exploit chain in follow-up wanted set.
        try:
            dvwa_score = float((kb.get("tech_confidence") or {}).get("dvwa", 0.0) or 0.0)
        except Exception:
            dvwa_score = 0.0
        if dvwa_score >= 0.45:
            if not auth_session:
                wanted.add("auxiliary/scanner/http/login/admin_login_bruteforce")
            wanted.add("exploits/ctf/dvwa_rce")
            wanted.add("exploits/ctf/dvwa_file_upload")
            # SQLi pseudo-shell only when not chasing OS shell.
            goal = str(kb.get("operator_campaign_goal") or kb.get("planner_campaign_goal") or "").lower()
            if "shell" not in goal and not kb.get("shell_hunter_mode"):
                wanted.add("auxiliary/scanner/http/dvwa_sqli_shell")
        for path in suggest_shell_plan_followups(kb):
            wanted.add(path)

        if auth_session:
            auth_skip_tokens = ("login_page_detector", "admin_login_bruteforce")
            wanted = {
                p for p in wanted
                if not any(t in p.lower() for t in auth_skip_tokens)
            }
            for path in self._preferred_post_auth_exploit_paths(kb):
                wanted.add(path)

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
        if state.target_reachable is False:
            return primary_results
        seed = str((state.target_info or {}).get("hostname", "") or "").strip()
        if not seed:
            return primary_results
        hosts = self._harvest_derived_hosts(seed, primary_results)
        kb = state.knowledge_base
        if isinstance(kb, dict):
            kb_candidates = list(kb.get("subdomain_candidates") or [])
            seen = {h.lower() for h in hosts}
            seed_l = seed.lower().strip(".")
            for candidate in kb_candidates:
                hl = str(candidate).lower().strip(".")
                if not hl or hl == seed_l or hl in seen:
                    continue
                if not self._hostname_in_seed_family(seed, hl):
                    continue
                seen.add(hl)
                hosts.append(hl)
            kb["derived_target_candidates"] = list(hosts)
            kb.setdefault("derived_host_scans", [])
        if not hosts:
            return primary_results
        probe_candidates = len(hosts)
        hosts = self._probe_and_filter_live_derived_hosts(state, hosts)
        if isinstance(kb, dict):
            kb["derived_target_candidates"] = list(hosts)
        if not hosts:
            self._append_timeline_event(
                state,
                "scan",
                "Derived host scans skipped: no live HTTP hosts after probe.",
                extra={"candidates": probe_candidates, "live": 0},
            )
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

    def _run_expanded_surface_intel_phase(
        self,
        state: AgentState,
        all_modules: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """``--all``: context-chained OSINT pipeline with linked intel graph."""
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        hostname = str((state.target_info or {}).get("hostname", "") or "").strip()
        if not hostname:
            return []
        if state.target_reachable is False and not self._hostname_is_osint_domain(hostname):
            return []
        root = organization_root_domain(hostname)
        persona_seed = str(kb.get("persona_name") or "").strip()
        if isinstance(state.knowledge_base, dict):
            state.knowledge_base["expanded_surface"] = True
            state.knowledge_base["target_hostname"] = hostname

        max_steps = min(
            EXPANDED_SURFACE_INTEL_MAX_MODULES,
            max(3, int(state.recon_modules or 12) // 2),
        )
        passive_only = self._is_europol_passive_mission(state)
        if passive_only and isinstance(state.knowledge_base, dict):
            state.knowledge_base.setdefault("retention_days", 90)
            state.knowledge_base.setdefault("osint_pseudonymize_exports", True)
            state.knowledge_base.setdefault("osint_require_legal_basis", True)
        if passive_only:
            max_steps = min(max(max_steps, 11), EXPANDED_SURFACE_INTEL_MAX_MODULES)
        if bool(state.verbose):
            print_info(
                f"Agent OSINT pipeline on {root} "
                f"(phased, max {max_steps} steps, persona={persona_seed or 'none'}"
                f"{', passive-LE' if passive_only else ''})"
            )
        self._append_timeline_event(
            state,
            "scan",
            f"Agent OSINT pipeline on {root}",
            kind="plan",
        )

        def _execute_batch(modules, option_overrides):
            return self._execute_plan_modules_with_options(
                modules,
                state,
                option_overrides=option_overrides,
                verbose=bool(state.verbose),
            )

        legal_basis = str(kb.get("legal_basis") or kb.get("mandate_ref") or "")
        evidence_collector = OsintEvidenceCollector(
            str(state.run_id or "agent-osint"),
            legal_basis=legal_basis,
            actor="agent",
        )
        opsec_journal = OsintOpsecJournal(
            workspace=str(state.workspace or "default"),
            case_id=root,
            legal_basis=legal_basis,
            passive_only=passive_only,
        )
        opsec_journal.record(action="pipeline_start", target=root, module="agent/osint-pipeline")

        results, synthesis = run_agent_intel_pipeline(
            execute_modules=_execute_batch,
            catalog_modules=all_modules,
            root_domain=root,
            persona_seed=persona_seed,
            max_steps=max_steps,
            passive_only=passive_only,
            evidence_collector=evidence_collector,
            opsec_journal=opsec_journal,
        )

        harvested_id = harvest_identities_from_results(results, root_domain=root)
        harvested_sub = harvest_subdomains_from_results(results, root_domain=root)
        password_candidates: List[str] = []
        if not passive_only:
            password_candidates = harvest_password_candidates_from_results(
                results,
                identities=harvested_id,
                root_domain=root,
            )
        merge_intel_into_knowledge_base(
            state.knowledge_base if isinstance(state.knowledge_base, dict) else {},
            identities=harvested_id,
            subdomains=harvested_sub,
            username_candidates=build_username_candidates(harvested_id) if not passive_only else [],
            password_candidates=password_candidates,
        )
        if isinstance(state.knowledge_base, dict):
            merge_osint_synthesis_into_knowledge_base(state.knowledge_base, synthesis)
            for line in synthesis.get("summary_lines", [])[:8]:
                print_info(f"  OSINT link: {line}")
            self._persist_osint_evidence_artifacts(
                state,
                module_results=results,
                synthesis=synthesis,
                collector=evidence_collector,
                opsec_journal=opsec_journal,
            )
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                results,
                [str(r.get("path", "")) for r in results if isinstance(r, dict)],
                list(state.knowledge_base.get("tech_hints") or []),
                list(state.scan_specializations or []),
                phase="expanded-osint",
            )
        return results

    def _port_to_protocol(self, port):
        mapping = {
            80: "http", 443: "http", 8080: "http", 8443: "http",
            21: "ftp", 22: "ssh", 23: "telnet", 389: "ldap", 636: "ldap",
            445: "smb", 139: "smb", 3306: "mysql", 5432: "postgresql",
            102: "ics", 502: "ics", 44818: "ics", 20000: "ics",
            2404: "ics", 47808: "ics", 4840: "ics", 111: "ics", 8000: "ics",
        }
        return mapping.get(int(port))

    def _pick_recon_modules(self, modules, state: Optional[AgentState] = None):
        recon = []
        cms_detect_tokens = ("wordpress_detect", "drupal_detect", "joomla_detect")
        panel_detect_tokens = (
            "phpmyadmin_detect",
            "phpmyadmin_setup_detect",
            "roundcube_webmail_portal_detect",
            "roundcube_installer_detect",
        )
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
            is_panel_detect = any(token in path for token in panel_detect_tokens)
            is_auth_recon = any(token in path for token in ("login_page_detector", "simple_login_scanner"))
            is_discovery_aux = any(token in blob for token in ("robots", "swagger", "graphql"))
            is_heavy_scanner = (
                path.startswith("auxiliary/scanner/")
                and any(token in path for token in ("wordpress_scanner", "drupal_scanner", "joomla_scanner"))
            )
            if (
                is_light_detect or is_discovery_aux or is_auth_recon or is_surface_recon or is_panel_detect
            ) and not is_heavy_scanner:
                recon.append(module)
        # Favor quick CMS detectors + colocated panel detectors first.
        recon.sort(
            key=lambda m: (
                0 if any(t in module_path_lower(m) for t in cms_detect_tokens) else 1,
                0 if any(t in module_path_lower(m) for t in panel_detect_tokens) else 1,
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
        wanted = (
            "wordpress_detect",
            "drupal_detect",
            "joomla_detect",
            "phpmyadmin_detect",
            "phpmyadmin_setup_detect",
            "roundcube_webmail_portal_detect",
            "roundcube_installer_detect",
        )
        for module in modules:
            path = module_path_lower(module)
            if any(token in path for token in wanted):
                picked.append(module)
        # Prefer CMS fingerprint first, then colocated panels.
        cms_first = ("wordpress_detect", "drupal_detect", "joomla_detect")
        picked.sort(
            key=lambda m: (
                0 if any(t in module_path_lower(m) for t in cms_first) else 1,
                str(m.get("path", "")),
            )
        )
        return picked

    def _rank_targeted_modules(self, modules, tech_hints, max_modules, specializations=None, knowledge_base=None):
        """
        Deterministic targeted ranking using technology hints + generic web safety checks.
        """
        generic_web_keywords = (
            "sql", "xss", "lfi", "rfi", "ssrf", "cors", "csrf", "headers", "directory_listing",
            "debug", "injection", "wordpress_scanner", "drupal_scanner", "joomla_scanner",
        )
        core_capability_keywords = (
            "crawler", "crawl", "spider", "fuzzer", "fuzz", "sqli", "sqli_engine", "sql_injection",
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
        fuzz_penalty_tokens = ("xss", "sqli_engine", "sql_injection", "sqli", "lfi", "ssrf", "fuzzer")
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
                HTTP_SQLI_SCANNER_MODULE,
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
