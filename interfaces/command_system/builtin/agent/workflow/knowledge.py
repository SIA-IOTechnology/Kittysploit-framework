#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Knowledge base, tech confidence, findings, auth context, and host harvest."""

from interfaces.command_system.builtin.agent.workflow.imports import *  # noqa: F403


class KnowledgeMixin:
    """Knowledge base, tech confidence, findings, auth context, and host harvest."""

    def _endpoint_matches_app_prefix(self, endpoints: Any, prefixes: Tuple[str, ...]) -> bool:
        """True when any discovered endpoint is under one of the app path prefixes."""
        for raw in endpoints or []:
            path = str(raw or "").strip().lower().split("?", 1)[0]
            if not path.startswith("/"):
                path = "/" + path
            for prefix in prefixes:
                token = str(prefix or "").strip().lower()
                if not token:
                    continue
                if not token.startswith("/"):
                    token = "/" + token
                base = token.rstrip("/") or "/"
                if path == base or path == base + "/" or path.startswith(base + "/"):
                    return True
        return False

    def _floor_tech_confidence(self, knowledge_base: Dict[str, Any], tech_key: str, floor: float) -> None:
        if not isinstance(knowledge_base, dict) or not tech_key:
            return
        confidence = dict(knowledge_base.get("tech_confidence", {}) or {})
        key = str(tech_key).lower()
        current = float(confidence.get(key, 0.0) or 0.0)
        confidence[key] = round(max(current, float(floor)), 3)
        knowledge_base["tech_confidence"] = confidence

    def _bodies_look_like_spa_catchall(self, baseline: str, candidate: str) -> bool:
        """True when a path probe likely hit the same SPA/index shell as ``/``."""
        base = (baseline or "").strip()
        other = (candidate or "").strip()
        if not base or not other:
            return False
        if base == other:
            return True
        # Compare bounded prefixes/suffixes to tolerate tiny CSRF/nonce diffs.
        head_n = 600
        if len(base) >= head_n and len(other) >= head_n and base[:head_n] == other[:head_n]:
            if abs(len(base) - len(other)) <= max(80, int(0.08 * max(len(base), 1))):
                return True
        return False

    def _promote_corroborated_web_apps(self, knowledge_base: Dict[str, Any]) -> None:
        """
        Promote known training/web apps when path evidence corroborates weak string hints.

        Homepage links like ``<a href="/dvwa/">DVWA</a>`` already produce endpoints +
        tech_hints at +0.18 each merge (~0.36). Without a path floor, DVWA never reaches
        the exploit/planner gates (0.45–0.7) while Drupal/WordPress get CMS floors.

        phpMyAdmin / Roundcube require content markers — path-only 200s on SPA sites
        (nginx + gunicorn + Flask) previously invented fake login surfaces.
        """
        if not isinstance(knowledge_base, dict):
            return
        endpoints = list(knowledge_base.get("discovered_endpoints", []) or [])
        hints = {str(h).lower().strip() for h in (knowledge_base.get("tech_hints", []) or []) if str(h).strip()}
        login_paths = {str(p) for p in (knowledge_base.get("login_paths", []) or []) if str(p).startswith("/")}
        endpoint_set = {str(e) for e in endpoints if str(e).strip()}
        fingerprint_blobs = " ".join(
            str(row.get("body") or "")
            for row in (knowledge_base.get("fingerprint_bodies") or [])
            if isinstance(row, dict)
        ).lower()
        blob = " ".join(
            [
                fingerprint_blobs,
                " ".join(str(x) for x in (knowledge_base.get("fingerprint_trace") or [])),
            ]
        ).lower()

        if self._endpoint_matches_app_prefix(endpoints, ("/dvwa",)) or "dvwa" in hints:
            if self._endpoint_matches_app_prefix(endpoints, ("/dvwa",)):
                hints.add("dvwa")
                self._floor_tech_confidence(knowledge_base, "dvwa", 0.78)
                login_paths.add("/dvwa/login.php")
                endpoint_set.update({"/dvwa/", "/dvwa/login.php"})
                risk = set(knowledge_base.get("risk_signals", []) or [])
                risk.add("login_surface_detected")
                knowledge_base["risk_signals"] = sorted(risk)
            elif "dvwa" in hints:
                self._floor_tech_confidence(knowledge_base, "dvwa", 0.45)
                # Hint without a corroborated /dvwa prefix → assume root install.
                if "/login.php" not in login_paths and not any(
                    str(p).lower().startswith("/dvwa/") for p in login_paths
                ):
                    login_paths.add("/login.php")
                    risk = set(knowledge_base.get("risk_signals", []) or [])
                    risk.add("login_surface_detected")
                    knowledge_base["risk_signals"] = sorted(risk)

        pma_content = any(
            tok in blob
            for tok in ("phpmyadmin", "pmahomme", "pma_", "db_structure.php")
        )
        if (
            self._endpoint_matches_app_prefix(
                endpoints,
                ("/phpmyadmin", "/phpMyAdmin", "/pma"),
            )
            and pma_content
        ):
            hints.add("phpmyadmin")
            self._floor_tech_confidence(knowledge_base, "phpmyadmin", 0.75)
            risk = set(knowledge_base.get("risk_signals", []) or [])
            risk.add("admin_panel_detected")
            knowledge_base["risk_signals"] = sorted(risk)
        elif "phpmyadmin" in hints and not pma_content:
            # Drop speculative hint with no body corroboration.
            hints.discard("phpmyadmin")
            confidence = dict(knowledge_base.get("tech_confidence", {}) or {})
            confidence.pop("phpmyadmin", None)
            knowledge_base["tech_confidence"] = confidence

        rc_content = any(
            tok in blob
            for tok in ("roundcube", "rcube_", "roundcube webmail")
        )
        if (
            self._endpoint_matches_app_prefix(
                endpoints,
                ("/roundcube", "/webmail", "/rc"),
            )
            and rc_content
        ):
            hints.add("roundcube")
            self._floor_tech_confidence(knowledge_base, "roundcube", 0.75)
            risk = set(knowledge_base.get("risk_signals", []) or [])
            risk.add("login_surface_detected")
            knowledge_base["risk_signals"] = sorted(risk)
        elif "roundcube" in hints and not rc_content:
            hints.discard("roundcube")
            confidence = dict(knowledge_base.get("tech_confidence", {}) or {})
            confidence.pop("roundcube", None)
            knowledge_base["tech_confidence"] = confidence

        if self._endpoint_matches_app_prefix(endpoints, ("/mutillidae",)):
            hints.add("mutillidae")
            self._floor_tech_confidence(knowledge_base, "mutillidae", 0.7)
            endpoint_set.add("/mutillidae/")

        knowledge_base["tech_hints"] = sorted(hints)
        knowledge_base["login_paths"] = sorted(login_paths)[:40]
        knowledge_base["discovered_endpoints"] = sorted(endpoint_set)[:300]

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
        try:
            self._learning.record_phase_results(
                state,
                kb_before_light,
                kb_after,
                phase_results,
                phase_name,
                get_agent_metadata=self._catalog.get_agent_metadata,
            )
        except Exception:
            pass
        self._module_health.record_phase_outcomes(
            kb_before_light,
            kb_after,
            phase_results,
            hostname=str(state.target_info.get("hostname", "") or ""),
            is_actionable=self._is_actionable_finding,
            get_agent_metadata=self._catalog.get_agent_metadata,
            stack_mismatch_fn=self._module_stack_mismatch_reason,
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
        profile_path = self._memory_path("host_profiles.json")
        return load_json_dict(profile_path)

    def _update_host_profile_cache(self, state: AgentState) -> None:
        target_info = state.target_info or {}
        host = str(target_info.get("hostname", "")).lower().strip()
        if not host:
            return

        profile_path = self._memory_path("host_profiles.json")
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
        except Exception as exc:
            self._record_agent_error(
                state,
                "host_profile_persistence",
                exc,
                phase="report",
            )

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

        def _score(name: str) -> float:
            try:
                return float(conf.get(name, 0.0) or 0.0)
            except Exception:
                return 0.0

        # Product-specific post-auth chains (highest-confidence product first).
        chain_table = (
            ("dvwa", ("exploits/ctf/dvwa_rce", "exploits/ctf/dvwa_file_upload")),
            ("wordpress", ("exploits/http/wordpress_plugin_upload", "exploits/http/wordpress_rce")),
            ("drupal", ("exploits/http/drupal_rce", "exploits/multi/http/drupal_cve_2014_3704_sqli")),
            ("joomla", ("exploits/http/joomla_jce_cve_2026_48907_rce",)),
            ("phpmyadmin", ("exploits/multi/http/phpmyadmin_cve_2018_12613_rce",)),
        )
        dominant = dominant_product_stack(kb, threshold=0.55) or ""
        ordered = sorted(chain_table, key=lambda row: (0 if row[0] == dominant else 1, -_score(row[0])))
        for product, paths in ordered:
            if _score(product) < 0.7 and product != dominant:
                continue
            if product != dominant and _score(product) < 0.85:
                continue
            for path in paths:
                if path in allowed and path not in preferred:
                    preferred.append(path)
        return preferred

    def _post_auth_candidate_sort_key(self, path: str, knowledge_base: Dict[str, Any]) -> Tuple[int, int, str]:
        low = str(path or "").lower()
        preferred = self._preferred_post_auth_exploit_paths(knowledge_base)
        if path in preferred:
            return (0, preferred.index(path), low)
        dominant = (dominant_product_stack(knowledge_base, threshold=0.55) or "").lower()
        if dominant and dominant in low:
            return (1, 0, low)
        if low.startswith(("exploits/", "exploit/")):
            return (2, 0, low)
        return (3, 0, low)

    def _stack_confidence_rows(self, knowledge_base: Dict[str, Any], threshold: float = 0.35) -> List[Tuple[str, float]]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        conf = kb.get("tech_confidence", {}) or {}
        known = (
            "dvwa", "mutillidae", "wordpress", "drupal", "joomla", "phpmyadmin", "grafana", "jenkins",
            "elasticsearch", "kibana", "tomcat", "nginx", "apache", "fastapi",
            "django", "flask", "nextjs", "nodejs", "react", "angular", "vue", "api",
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

    def _has_nextjs_evidence(self, knowledge_base: Dict[str, Any], threshold: float = 0.55) -> bool:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        if self._has_tech_evidence(kb, "nextjs", threshold=threshold):
            return True
        endpoints = " ".join(str(x).lower() for x in kb.get("discovered_endpoints", []) or [])
        trace = " ".join(
            " ".join(str(row.get(key, "")) for key in ("url", "path", "final_url", "body"))
            for row in (kb.get("fingerprint_trace", []) or [])
            if isinstance(row, dict)
        ).lower()
        request_intel = kb.get("request_intel", {}) if isinstance(kb.get("request_intel", {}), dict) else {}
        request_hints = {str(x).lower() for x in request_intel.get("tech_hints", []) or []}
        if "nextjs" in request_hints:
            return True
        return any(token in endpoints or token in trace for token in NEXTJS_HINT_TOKENS)

    def _module_stack_mismatch_reason(self, path: str, knowledge_base: Dict[str, Any]) -> str:
        from interfaces.command_system.builtin.agent.module_stack_gate import resolve_module_stack_mismatch

        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        agent = self._catalog.get_agent_metadata(path)
        return resolve_module_stack_mismatch(
            path,
            kb,
            agent,
            has_tech_evidence=lambda tech, threshold=0.65: self._has_tech_evidence(kb, tech, threshold),
            has_nextjs_evidence=lambda: self._has_nextjs_evidence(kb),
        )

    def _module_hard_stack_skip_reason(self, path: str, knowledge_base: Dict[str, Any]) -> str:
        """Hard pre-launch skip only (incompatible stack / unproven exploit), not cold detectors."""
        from interfaces.command_system.builtin.agent.module_stack_gate import hard_stack_skip_reason

        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        agent = self._catalog.get_agent_metadata(path)
        return hard_stack_skip_reason(
            path,
            kb,
            agent,
            has_tech_evidence=lambda tech, threshold=0.65: self._has_tech_evidence(kb, tech, threshold),
            has_nextjs_evidence=lambda: self._has_nextjs_evidence(kb),
        )

    def _filter_stack_compatible_paths(self, paths: List[str], knowledge_base: Dict[str, Any]) -> List[str]:
        compatible = []
        for path in paths or []:
            if self._module_stack_mismatch_reason(path, knowledge_base):
                continue
            compatible.append(path)
        return compatible

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
        risk = {str(x).lower() for x in kb.get("risk_signals", [])}
        endpoints = [str(x).lower() for x in kb.get("discovered_endpoints", []) or []]
        multi_app_listing = (
            "directory_listing_detected" in risk
            and sum(
                1
                for ep in endpoints
                if ep.endswith(".php") or ep.endswith("/") and ep.count("/") <= 2
            )
            >= 2
        )

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
        if "drupal" in hints:
            if multi_app_listing:
                if drupal_conf >= 0.5 or any(
                    token in endpoints_blob for token in ("sites/default", "x-drupal", "/core/", "drupal.js")
                ):
                    probable.add("drupal")
            elif drupal_conf >= 0.25:
                probable.add("drupal")
        if "joomla" in hints:
            if multi_app_listing:
                if joomla_conf >= 0.5 or "/administrator" in endpoints_blob:
                    probable.add("joomla")
            elif joomla_conf >= 0.25:
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
        if isinstance(result, dict):
            state = str(result.get("evidence_state") or "").lower()
            if state in {"confirmed", "exploitable"}:
                return True
            records = result.get("evidence_records")
            if isinstance(records, list):
                for row in records[:6]:
                    if not isinstance(row, dict):
                        continue
                    try:
                        if float(row.get("confidence", 0.0) or 0.0) >= 0.78:
                            return True
                    except Exception:
                        continue
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

    def _merge_auth_context(
        self,
        knowledge_base,
        candidate: Optional[Dict[str, Any]],
        *,
        state: Optional[AgentState] = None,
    ) -> None:
        self._auth_ops.merge_auth_context(knowledge_base, candidate, state=state)

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
        if "login_decoy_detected" in signals and not signals.intersection({
            "login_form_detected",
            "authenticated_session",
            "credentials_obtained",
        }):
            return False
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
        if "login_decoy_detected" in signals and not signals.intersection({"login_form_detected", "credentials_obtained"}):
            return False
        login_signals = signals.intersection({
            "login_redirect_detected",
            "login_form_detected",
            "login_surface_detected",
        })
        login_paths = [p for p in kb.get("login_paths", []) if isinstance(p, str) and p.startswith("/")]
        endpoint_count = len(kb.get("discovered_endpoints", []))
        return bool(login_paths) and (bool(login_signals) or endpoint_count <= 2)

    def _get_cms_lock_specializations(self, knowledge_base, specializations=None):
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        # Dominant non-CMS product (lab/admin/framework) must never be starved by CMS lock.
        if should_suppress_cms_lock(kb, threshold=0.7):
            return set()
        # Lock only to the dominant CMS at high confidence — never specialization noise alone.
        return cms_lock_targets(kb, threshold=0.7)

    def _get_primary_cms_focus(self, knowledge_base):
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        # Lab/admin/framework targets must not enter CMS-only prune mode.
        if should_suppress_cms_lock(kb, threshold=0.7):
            return None
        confidence = kb.get("tech_confidence", {}) or {}

        cms_scores = {
            "wordpress": float(confidence.get("wordpress", 0.0) or 0.0),
            "drupal": float(confidence.get("drupal", 0.0) or 0.0),
            "joomla": float(confidence.get("joomla", 0.0) or 0.0),
        }
        # Do not boost from polluted tech_hints — confidence evidence only.
        winner = max(cms_scores, key=cms_scores.get)
        best = cms_scores[winner]
        second = max([v for k, v in cms_scores.items() if k != winner] or [0.0])
        # Dominant single-CMS mode: enough evidence and clear lead.
        if best >= 0.6 and (best - second) >= 0.2:
            return winner
        return None

    def _snapshot_campaign_state(self, state: AgentState, all_results):
        kb = state.knowledge_base
        return {
            "endpoints": len(kb.get("discovered_endpoints", [])),
            "params": len(kb.get("discovered_params", [])),
            "hints": len(kb.get("tech_hints", [])),
            "vulns": len([r for r in all_results if r.get("vulnerable")]),
        }

    def _update_knowledge_base_from_results(
        self,
        knowledge_base,
        results,
        module_paths,
        tech_hints,
        specializations,
        *,
        phase: str = "",
    ):
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
        cms_base_paths = dict(knowledge_base.get("cms_base_paths", {}) or {})

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
            elif hint_lower in ("dvwa", "phpmyadmin"):
                tech_confidence[hint_lower] = round(
                    max(float(tech_confidence.get(hint_lower, 0.0) or 0.0), 0.45),
                    3,
                )
            elif hint_lower == "nextjs":
                tech_confidence["nextjs"] = round(
                    max(float(tech_confidence.get("nextjs", 0.0) or 0.0), 0.68),
                    3,
                )
                tech_confidence["nodejs"] = round(
                    max(float(tech_confidence.get("nodejs", 0.0) or 0.0), 0.5),
                    3,
                )
                tech_confidence["react"] = round(
                    max(float(tech_confidence.get("react", 0.0) or 0.0), 0.45),
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
                if any(token in evidence_blob for token in NEXTJS_HINT_TOKENS):
                    kb_hints.add("nextjs")
                    kb_hints.add("nodejs")
                    kb_hints.add("react")
                    tech_confidence["nextjs"] = round(max(float(tech_confidence.get("nextjs", 0.0) or 0.0), 0.78), 3)
                    tech_confidence["nodejs"] = round(max(float(tech_confidence.get("nodejs", 0.0) or 0.0), 0.55), 3)
                    tech_confidence["react"] = round(max(float(tech_confidence.get("react", 0.0) or 0.0), 0.5), 3)
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

            if isinstance(details, dict):
                cms_blob = " ".join((mod_path_low, msg_lower, evidence_blob))
                if "drupal" in cms_blob:
                    base_hint = str(details.get("base_path") or details.get("path") or "").strip()
                    if base_hint.startswith("/"):
                        base_norm = "/" + base_hint.strip("/")
                        if base_norm == "//":
                            base_norm = "/"
                        cms_base_paths["drupal"] = base_norm
                        discovered_endpoints.add(base_norm)
                        discovered_endpoints.add(
                            (base_norm.rstrip("/") if base_norm != "/" else "") + "/user/login"
                        )
                        discovered_endpoints.add(
                            (base_norm.rstrip("/") if base_norm != "/" else "") + "/user/register"
                        )
                        discovered_endpoints.add(
                            (base_norm.rstrip("/") if base_norm != "/" else "") + "/sites/default"
                        )

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
                findings = details.get("findings")
                sqli_rows = details.get("sqli_findings")
                if isinstance(sqli_rows, list) and sqli_rows:
                    risk_signals.add("sqli_confirmed")
                    risk_signals.add("sql_signal")
                    kb_sqli = list(knowledge_base.get("sqli_findings", []) or [])
                    for row in sqli_rows:
                        if isinstance(row, dict):
                            kb_sqli.append(row)
                    knowledge_base["sqli_findings"] = kb_sqli[-24:]
                    allowed_paths = set(
                        (knowledge_base.get("module_capability_catalog", {}) or {}).get("all_paths", []) or []
                    )
                    if HTTP_SQLI_POST_MODULE in allowed_paths:
                        post_auth_catalog_paths.add(HTTP_SQLI_POST_MODULE)
                if isinstance(findings, dict):
                    for endpoint in findings.get("endpoints", []) or []:
                        for candidate in self._extract_endpoint_candidates(str(endpoint)):
                            discovered_endpoints.add(candidate)
                            if "/api" in candidate.lower() or "graphql" in candidate.lower():
                                kb_hints.add("api")
                                risk_signals.add("api_surface_detected")
                    for src in findings.get("source_files", []) or []:
                        if src:
                            kb_hints.add("javascript")
                            risk_signals.add("js_sourcemap_recovered")
                    if findings.get("maps"):
                        risk_signals.add("js_sourcemap_recovered")
                    if findings.get("graphql_endpoint"):
                        risk_signals.add("graphql_surface_detected")
                        knowledge_base["graphql_endpoint"] = str(findings.get("graphql_endpoint"))[:256]
                    if findings.get("key_hints"):
                        risk_signals.add("leaked_secrets_detected")
                        risk_signals.add("possible_secret_literals_in_js")
                        knowledge_base["extracted_secrets"] = list(knowledge_base.get("extracted_secrets", []) or []) + [
                            {
                                "type": "client_js_secret_hint",
                                "name": str(row.get("name", ""))[:80],
                                "source": str(row.get("source", ""))[:240],
                            }
                            for row in findings.get("key_hints", [])[:20]
                            if isinstance(row, dict)
                        ]
                elif isinstance(findings, list) and "secret" in mod_path_low:
                    if findings:
                        risk_signals.add("leaked_secrets_detected")
                        risk_signals.add("possible_secret_literals_in_js")
                    knowledge_base["extracted_secrets"] = list(knowledge_base.get("extracted_secrets", []) or []) + [
                        {
                            "type": str(row.get("type", "secret_hint"))[:80],
                            "source": str(result.get("path", ""))[:200],
                        }
                        for row in findings[:20]
                        if isinstance(row, dict)
                    ]
                endpoint_rows = details.get("endpoints")
                if isinstance(endpoint_rows, list):
                    for row in endpoint_rows:
                        endpoint = row.get("endpoint") if isinstance(row, dict) else row
                        for candidate in self._extract_endpoint_candidates(str(endpoint)):
                            discovered_endpoints.add(candidate)
                            if "/api" in candidate.lower() or "graphql" in candidate.lower():
                                kb_hints.add("api")
                                risk_signals.add("api_surface_detected")
                if bool(details.get("dom_xss_suspected")) or int(details.get("dom_xss_score", 0) or 0) >= 6:
                    risk_signals.add("dom_xss_signal")
                    risk_signals.add("xss_signal")
                    kb_hints.add("dom_xss")
                if bool(details.get("login_error_decoy")):
                    risk_signals.add("login_decoy_detected")
                paths_value = details.get("paths")
                if isinstance(paths_value, str):
                    for raw_path in paths_value.split(","):
                        candidate = raw_path.strip()
                        if candidate.startswith("/"):
                            login_paths.add(candidate.split("?", 1)[0])
                login_path_hint = details.get("login_path")
                if (
                    isinstance(login_path_hint, str)
                    and login_path_hint.startswith("/")
                    and not bool(details.get("login_error_decoy"))
                ):
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
            ) and not (isinstance(details, dict) and bool(details.get("login_error_decoy"))):
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

            session_id = str(
                result.get("session_id")
                or (details.get("session_id") if isinstance(details, dict) else "")
                or ""
            ).strip()
            ssh_shell_win = bool(
                session_id
                and (
                    "ssh_login" in mod_path_low
                    or "ssh login succeeded" in msg_lower
                    or ("ssh" in mod_path_low and "login succeeded" in msg_lower)
                )
            )
            if ssh_shell_win or (
                session_id
                and any(token in mod_path_low for token in ("/ssh/", "ssh_login", "shell"))
                and result.get("vulnerable")
            ):
                risk_signals.update({
                    "shell_obtained",
                    "interactive_shell",
                    "authenticated_session",
                    "credentials_obtained",
                })
                knowledge_base.setdefault("verified_session_ids", [])
                ids = knowledge_base["verified_session_ids"]
                if isinstance(ids, list) and session_id not in ids:
                    ids.append(session_id)

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
        if cms_base_paths:
            knowledge_base["cms_base_paths"] = cms_base_paths
        self._promote_corroborated_web_apps(knowledge_base)

        meta_map: Dict[str, Any] = {}
        for result in results or []:
            if not isinstance(result, dict):
                continue
            path = str(result.get("path", "") or "").strip()
            if path and path not in meta_map:
                meta_map[path] = self._catalog.get_agent_metadata(path) or {}
        sync_chain_context_to_kb(knowledge_base, results or [])
        poison_kb_from_results(
            knowledge_base,
            results or [],
            phase=phase,
            module_agent_meta=meta_map,
        )
        if knowledge_base.get("expanded_surface"):
            root = organization_root_domain(
                str(knowledge_base.get("target_hostname") or "")
            )
            if not root:
                root = ""
            identities = harvest_identities_from_results(results or [], root_domain=root)
            subdomains = harvest_subdomains_from_results(results or [], root_domain=root)
            if identities or subdomains:
                merge_intel_into_knowledge_base(
                    knowledge_base,
                    identities=identities,
                    subdomains=subdomains,
                    username_candidates=build_username_candidates(identities),
                    password_candidates=harvest_password_candidates_from_results(
                        results or [],
                        identities=identities,
                        root_domain=root,
                    ),
                )
        knowledge_base["attack_chain_summary"] = export_chain_summary(knowledge_base)
        merge_ot_context_from_results(knowledge_base, results, module_paths)
        sync_attack_graph_from_kb(
            knowledge_base,
            hostname=str(knowledge_base.get("target_hostname") or ""),
            module_paths=list(module_paths or []),
            results=[r for r in (results or []) if isinstance(r, dict)],
        )
        sync_branches_from_results(
            knowledge_base,
            [r for r in (results or []) if isinstance(r, dict)],
        )

    def _select_best_login_path(self, knowledge_base):
        return self._auth_ops.select_best_login_path(knowledge_base)

    def _build_inferred_option_overrides(self, modules, state: AgentState):
        overrides = self._auth_ops.build_inferred_option_overrides(modules, state)
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        cms_base_paths = kb.get("cms_base_paths", {}) if isinstance(kb.get("cms_base_paths", {}), dict) else {}
        drupal_base = str(cms_base_paths.get("drupal") or "").strip()
        if not drupal_base:
            path_hints = list(kb.get("discovered_endpoints", []) or [])
            path_hints.extend(kb.get("login_paths", []) or [])
            for endpoint in path_hints:
                endpoint_text = str(endpoint or "").strip()
                if "/drupal/" in endpoint_text.lower() or endpoint_text.lower() == "/drupal":
                    drupal_base = "/drupal"
                    break
        chain_overrides = build_chain_context_option_overrides(modules, kb)
        for path, opts in chain_overrides.items():
            if not isinstance(opts, dict) or not opts:
                continue
            merged = dict(overrides.get(path) or {})
            merged.update(opts)
            overrides[path] = merged
        if drupal_base:
            drupal_base = "/" + drupal_base.strip("/")
            if drupal_base == "//":
                drupal_base = "/"
            for module in modules or []:
                module_path = str(module.get("path", "")).strip()
                if not module_path or "drupal" not in module_path.lower():
                    continue
                merged = dict(overrides.get(module_path) or {})
                merged.setdefault("path", drupal_base)
                merged.setdefault("base_path", drupal_base)
                if module_path.lower().endswith("drupal_rce") and drupal_base != "/":
                    merged.setdefault("exploit_path", drupal_base.rstrip("/") + "/user/register")
                overrides[module_path] = merged
        overrides = merge_crawler_overrides(overrides, kb, state)
        return overrides

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

    def _detect_specializations(self, tech_hints, results, knowledge_base=None):
        """
        Determine adaptive specialization buckets from hints + scan outcomes.
        """
        hint_corpus = set([str(h).lower() for h in tech_hints])
        evidence_corpus = set()
        for result in results:
            if not self._result_indicates_positive_detection(result):
                continue
            if not self._result_has_explicit_evidence(result):
                continue
            blob = self._result_evidence_blob(result)
            for token in CMS_SPECIALIZATION_BLOB_TOKENS:
                if token in blob:
                    evidence_corpus.add(token)

        confidence = {}
        if isinstance(knowledge_base, dict):
            confidence = knowledge_base.get("tech_confidence", {}) or {}

        def _conf(name: str) -> float:
            try:
                return float(confidence.get(name, 0.0) or 0.0)
            except Exception:
                return 0.0

        specializations = set()
        # CMS specializations require confident evidence — not polluted tech_hints alone.
        if "wordpress" in evidence_corpus or "wp" in evidence_corpus:
            specializations.add("wordpress")
        if "drupal" in evidence_corpus:
            specializations.add("drupal")
        if "joomla" in evidence_corpus:
            specializations.add("joomla")
        if _conf("wordpress") >= 0.75:
            specializations.add("wordpress")
        if _conf("drupal") >= 0.75:
            specializations.add("drupal")
        if _conf("joomla") >= 0.75:
            specializations.add("joomla")

        # Lab / admin products: hints or confidence are enough (names are distinctive).
        product_specs = (
            ("dvwa", 0.6),
            ("mutillidae", 0.6),
            ("bwapp", 0.6),
            ("webgoat", 0.6),
            ("phpmyadmin", 0.6),
            ("grafana", 0.6),
            ("jenkins", 0.6),
            ("tomcat", 0.6),
            ("roundcube", 0.6),
        )
        for name, floor in product_specs:
            if name in hint_corpus or name in evidence_corpus or _conf(name) >= floor:
                specializations.add(name)

        corpus = hint_corpus | evidence_corpus
        if any(t in corpus for t in ("django", "flask", "fastapi", "python")):
            specializations.add("python_web")
        if any(t in corpus for t in ("nodejs", "nextjs", "react", "angular", "vue")):
            specializations.add("node_web")
        if "nextjs" in corpus or _conf("nextjs") >= 0.6:
            specializations.add("nextjs")
            specializations.add("node_web")
        if any(t in corpus for t in ("api", "swagger", "graphql")):
            specializations.add("api")
        if _conf("api") >= 0.6:
            specializations.add("api")
        if any(t in corpus for t in ("grafana", "jenkins", "tomcat", "phpmyadmin", "roundcube")):
            specializations.add("admin_surface")
        # Dominant product suppresses weaker CMS specializations (mixed lab homepages).
        dominant = dominant_product_stack(
            knowledge_base if isinstance(knowledge_base, dict) else {},
            threshold=0.7,
        )
        if dominant in ("dvwa", "mutillidae", "bwapp", "webgoat", "phpmyadmin", "grafana", "jenkins"):
            specializations.difference_update({"wordpress", "drupal", "joomla"})
            specializations.add(dominant)
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
            signal_blob = " ".join([
                message,
                str(details).lower(),
                str(result.get("module", "")).lower(),
            ])
            if exploit_path:
                return True
            if any(marker in signal_blob for marker in (
                "cve-",
                "cve_",
                "rce",
                "command execution",
                "authenticated as",
                "valid credentials",
                "auth bypass",
                "vulnerable",
            )):
                return True
            return False

        return bool(message and severity)

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

    def _is_europol_passive_mission(self, state: AgentState) -> bool:
        mission = str(
            getattr(getattr(state, "runtime_policy", None), "mission_profile", "") or ""
        ).strip().lower().replace("_", "-")
        return mission == "europol-passive"

    def _persist_osint_evidence_artifacts(
        self,
        state: AgentState,
        *,
        module_results: List[Dict[str, Any]],
        synthesis: Dict[str, Any],
        collector: Optional[OsintEvidenceCollector] = None,
        opsec_journal: Optional[OsintOpsecJournal] = None,
    ) -> None:
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        hostname = str((state.target_info or {}).get("hostname", "") or "").strip()
        root = organization_root_domain(hostname)
        legal_basis = str(kb.get("legal_basis") or kb.get("mandate_ref") or "")
        output_dir = None
        run_id = str(state.run_id or "").strip()
        if run_id:
            try:
                from interfaces.command_system.builtin.agent.run_store import AgentPathService

                output_dir = AgentPathService().run_dir(run_id) / "osint"
            except Exception:
                output_dir = None
        if output_dir is None:
            from pathlib import Path

            output_dir = Path("artifacts/osint") / (root or "unknown")

        try:
            from core.osint.gdpr import OsintRetentionPolicy

            passive = self._is_europol_passive_mission(state)
            data_controller = str(kb.get("data_controller") or "")
            retention_policy = OsintRetentionPolicy.from_osint_config()
            try:
                pii_days = int(
                    kb.get("retention_days")
                    or kb.get("osint_retention_days")
                    or retention_policy.pii_days
                )
            except (TypeError, ValueError):
                pii_days = retention_policy.pii_days
            if pii_days != retention_policy.pii_days or data_controller or passive:
                retention_policy = OsintRetentionPolicy(
                    pii_days=max(1, pii_days),
                    ioc_days=retention_policy.ioc_days,
                    audit_days=retention_policy.audit_days,
                    legal_basis_required=passive or retention_policy.legal_basis_required,
                    pseudonymize_exports=bool(
                        kb.get("osint_pseudonymize_exports", retention_policy.pseudonymize_exports)
                    ),
                    data_controller=data_controller or retention_policy.data_controller,
                    processing_purpose=retention_policy.processing_purpose,
                    lawful_basis_article=retention_policy.lawful_basis_article,
                )
            paths = write_osint_evidence_bundle(
                module_results=module_results,
                synthesis=synthesis,
                output_dir=output_dir,
                run_id=run_id,
                legal_basis=legal_basis,
                target=root,
                tlp=str(kb.get("tlp") or "AMBER"),
                actor="agent",
                workspace=str(state.workspace or "default"),
                passive_only=passive,
                opsec_journal=opsec_journal,
                retention_policy=retention_policy,
                data_controller=str(kb.get("data_controller") or ""),
                recipient_org=str(kb.get("recipient_org") or ""),
            )
            if isinstance(state.knowledge_base, dict):
                state.knowledge_base["osint_evidence_paths"] = paths
                if collector is not None:
                    state.knowledge_base["osint_evidence_verified"] = collector.verify()
                if opsec_journal is not None:
                    state.knowledge_base["osint_opsec_summary"] = opsec_journal.summarize()
            if bool(state.verbose):
                print_info(f"OSINT evidence bundle: {paths.get('manifest', output_dir)}")
        except Exception as exc:
            if bool(state.verbose):
                print_warning(f"OSINT evidence export skipped: {exc}")

    def _extract_tech_hints(self, recon_results):
        hints = set()
        hint_words = [
            "dvwa", "wordpress", "drupal", "joomla", "grafana", "jenkins", "elasticsearch",
            "kibana", "tomcat", "nginx", "apache", "phpmyadmin", "docker", "cloud",
            "api", "swagger", "fastapi", "django", "flask", "nodejs", "nextjs",
            "react", "angular", "php", "python", "java",
            "modbus", "s7comm", "siemens", "bacnet", "iec104", "enip", "dnp3",
            "opcua", "scada", "plc", "ics", "ot",
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

    def _record_exploit_confirmed_finding(
        self,
        state: Optional[AgentState],
        exploit_path: str,
        *,
        session_ids: Optional[List[str]] = None,
    ) -> None:
        """Preserve the vulnerability finding when an exploit path directly yields a shell."""
        if not isinstance(state, AgentState):
            return
        path = str(exploit_path or "").strip()
        low = path.lower()
        if not path:
            return

        finding: Optional[Dict[str, Any]] = None
        if "drupal_cve_2014_3704_sqli" in low:
            finding = {
                "module": "Drupal 7.x SQLi RCE (CVE-2014-3704)",
                "path": path,
                "status": "vulnerable",
                "vulnerable": True,
                "severity": "critical",
                "confidence": "high",
                "message": "Critical SQL injection confirmed: Drupal SA-CORE-2014-005 / CVE-2014-3704",
                "exploit_module": path,
                "evidence_state": "exploitable",
                "proof": "Exploit produced a shell session",
                "details": {
                    "cve": "CVE-2014-3704",
                    "class": "sql_injection",
                    "sqli_confirmed": True,
                    "session_ids": list(session_ids or []),
                },
            }

        if not finding:
            return

        existing_keys = {
            (str(row.get("path") or ""), str(row.get("message") or ""))
            for row in (state.results or [])
            if isinstance(row, dict)
        }
        key = (str(finding.get("path") or ""), str(finding.get("message") or ""))
        if key not in existing_keys:
            state.results.append(finding)

        state.vulnerable_results = self._deduplicate_findings(
            [
                row for row in (state.vulnerable_results or []) + [finding]
                if isinstance(row, dict) and self._is_actionable_finding(row)
            ]
        )
        state.contextual_findings = self._deduplicate_findings(
            self._build_contextual_findings(state.vulnerable_results, state.knowledge_base)
        )

        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        signals = list(kb.get("risk_signals", []) or [])
        signal_set = {str(s).lower() for s in signals}
        for signal in (
            "sql_signal",
            "sqli_confirmed",
            "vulnerability_detected",
            "shell_obtained",
            "interactive_shell",
        ):
            if signal not in signal_set:
                signals.append(signal)
                signal_set.add(signal)
        kb["risk_signals"] = signals
        state.knowledge_base = kb
        state.sql_findings = self._deduplicate_findings(list(state.sql_findings or []) + [finding])
        print_success("High-priority detection: critical SQL injection confirmed (Drupal CVE-2014-3704)")

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
            item = attach_result_evidence(item)
            item = apply_evidence_gate(item)
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
            evidence_state = str(item.get("evidence_state", "") or "").lower()
            if evidence_state == "exploitable":
                confidence += 0.18
            elif evidence_state == "confirmed":
                confidence += 0.12
            elif evidence_state == "signal":
                confidence -= 0.12
            proof_quality = item.get("proof_quality") if isinstance(item.get("proof_quality"), dict) else {}
            try:
                if float(proof_quality.get("best_confidence", 0.0) or 0.0) >= 0.75:
                    confidence += 0.06
            except Exception:
                pass
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
            evidence_count += min(int(proof_quality.get("records", 0) or 0), 4) * 0.18
            evidence_count += min(int(proof_quality.get("independent_sources", 0) or 0), 3) * 0.18
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
            annotated["validation_status"] = self._finding_validation_status(annotated)
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

    def _weaponizable_finding_tokens(self) -> Tuple[str, ...]:
        return (
            "lfi",
            "rfi",
            "sqli",
            "sql_injection",
            "ssrf",
            "xxe",
            "rce",
            "command_injection",
            "file_read",
            "path_traversal",
            "ssti",
            "deserialization",
            "smuggling",
            "auth_bypass",
            "file_upload",
        )

    def _finding_path_has_weaponizable_token(self, finding: Dict[str, Any]) -> bool:
        path = str(finding.get("path", "") or "").lower().replace("-", "_")
        module = str(finding.get("module", "") or "").lower().replace("-", "_")
        message = str(finding.get("message", "") or "").lower()
        tokens = set(self._weaponizable_finding_tokens())
        for raw in (path, module):
            basename = raw.rsplit("/", 1)[-1]
            if basename in tokens:
                return True
            parts = {p for seg in basename.split("_") for p in seg.split(".") if p}
            if parts.intersection(tokens):
                return True
        # Message-level SQL/LFI confirmation (module path may be generic).
        if ("sql" in message and "injection" in message) or " local file inclusion" in f" {message}":
            return True
        if any(f" {tok} " in f" {message} " for tok in ("lfi", "rfi", "ssrf", "xxe", "ssti")):
            return True
        return False

    def _is_weaponizable_vuln_finding(self, finding: Dict[str, Any]) -> bool:
        """
        Confirmed/medium injection-class scanners that should drive follow-up
        even without a linked exploit_module (classic soft targets: LFI/SQLi).
        """
        if not isinstance(finding, dict):
            return False
        if not self._finding_path_has_weaponizable_token(finding):
            return False
        severity = str(finding.get("severity", "") or "").lower()
        if finding.get("vulnerable"):
            return True
        if severity in ("critical", "high", "medium"):
            return True
        message = str(finding.get("message", "") or "").lower()
        # High-priority SQL detection may land before vulnerable=True is set.
        if "sql" in message and "injection" in message:
            return True
        return False

    def _finding_decision_class(self, finding: Dict[str, Any]) -> str:
        if not isinstance(finding, dict):
            return "info"
        path = str(finding.get("path", "")).lower()
        message = str(finding.get("message", "")).lower()
        severity = str(finding.get("severity", "")).lower()
        details = finding.get("details", {}) or {}
        exploit_path = self._catalog.normalize_exploit_module_path(finding.get("exploit_module"))
        validation_status = str(
            finding.get("validation_status")
            or self._finding_validation_status(finding)
        ).lower()

        if exploit_path and validation_status == "exploitable":
            return "exploit"
        if exploit_path:
            return "followup"
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
        if self._is_weaponizable_vuln_finding(finding):
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

    def _finding_validation_status(self, finding: Dict[str, Any]) -> str:
        """Classify signal strength before allowing exploitation."""
        if not isinstance(finding, dict):
            return "signal"
        exploit_path = self._catalog.normalize_exploit_module_path(
            finding.get("exploit_module")
        )
        details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
        evidence_state = str(finding.get("evidence_state", "") or "").lower()
        if evidence_state in {"exploitable", "fixed", "regressed"}:
            return evidence_state
        if evidence_state == "confirmed" and exploit_path:
            return "exploitable"
        if evidence_state == "confirmed":
            return "confirmed"
        strong_runtime = bool(
            details.get("authenticated_as")
            or details.get("command_output")
            or details.get("file_read")
            or details.get("reflection_confirmed")
            or details.get("proof")
            or finding.get("session_id")
        )
        explicit = strong_runtime or self._result_has_explicit_evidence(finding)
        if explicit and exploit_path:
            return "exploitable"
        if explicit:
            return "confirmed"
        if finding.get("vulnerable") and (
            str(finding.get("severity", "")).lower() in {"critical", "high", "medium"}
            or float(finding.get("context_score", 0.0) or 0.0) >= 2.0
        ):
            return "probable"
        return "signal"

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

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate repeated findings by vulnerability, host, service and evidence."""
        return deduplicate_scanner_results(findings)

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
        request_intel = kb.get("request_intel", {}) if isinstance(kb.get("request_intel", {}), dict) else {}
        summary = {
            "goal": state.campaign_goal,
            "stop_reason": state.campaign_stop_reason,
            "tech": kb.get("tech_hints", [])[:12],
            "risk": kb.get("risk_signals", [])[:12],
            "login_paths": kb.get("login_paths", [])[:6],
            "endpoints": len(kb.get("discovered_endpoints", []) or []),
            "params": len(kb.get("discovered_params", []) or []),
            "request_intel": {
                "flows": request_intel.get("analyzed_flows", 0),
                "interesting": len(request_intel.get("interesting_requests", []) or []),
                "top_requests": [
                    f"{row.get('method')} {row.get('path')}"
                    for row in (request_intel.get("interesting_requests", []) or [])[:5]
                    if isinstance(row, dict)
                ],
            } if request_intel else {},
            "top_findings": top_findings,
            "recent_events": recent_events,
        }
        state.compressed_context_summary = self._shorten_text(json.dumps(summary, ensure_ascii=False), 3000)
        return state.compressed_context_summary
