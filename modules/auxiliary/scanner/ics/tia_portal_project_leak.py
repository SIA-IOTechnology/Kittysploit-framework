#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.ics.siemens_defaults import TIA_PROJECT_EXTENSIONS, TIA_PROJECT_PATHS


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "TIA Portal project leak",
        "description": (
            "Probes web-exposed Siemens TIA Portal project archives (.ap17/.ap18/.zap*) "
            "that may disclose PLC/HMI source projects."
        ),
        "author": "KittySploit Team",
        "platform": Platform.OTHER,
        "tags": ["ics", "siemens", "tia", "project", "disclosure", "web"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 15,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(80, "HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", False)
    wordlist = OptFile("", "Extra project paths (one per line)", False)
    min_size = OptInteger(1024, "Minimum response size to treat as a project file", False)
    download = OptBool(False, "Download discovered project files locally", False)
    output_dir = OptString("tia_projects", "Directory for downloaded project files", False)

    def _paths(self) -> list[str]:
        paths = list(TIA_PROJECT_PATHS)
        wordlist = str(self.wordlist or "").strip()
        if wordlist and os.path.isfile(wordlist):
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    value = line.strip()
                    if value and value not in paths:
                        paths.append(value if value.startswith("/") else f"/{value}")
        return paths

    @staticmethod
    def _looks_like_tia_project(content: bytes, path: str) -> bool:
        lower = path.lower()
        if any(lower.endswith(ext) for ext in TIA_PROJECT_EXTENSIONS):
            return content.startswith(b"PK\x03\x04") or content.startswith(b"PK\x05\x06")
        return content.startswith(b"PK\x03\x04")

    def check(self):
        if not str(self.target or "").strip():
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        return {"vulnerable": True, "reason": "ready to probe TIA project paths", "confidence": "low"}

    def run(self):
        if not str(self.target or "").strip():
            print_error("Target is required")
            return False

        found = 0
        min_size = max(1, int(self.min_size or 1024))
        print_status(f"Probing {len(self._paths())} TIA project path(s)...")

        for project_path in self._paths():
            try:
                response = self.http_request("GET", project_path, allow_redirects=True, stream=True)
            except Exception:
                continue
            if response.status_code != 200:
                continue

            content = response.content if hasattr(response, "content") else b""
            if len(content) < min_size:
                continue
            if not self._looks_like_tia_project(content, project_path):
                continue

            found += 1
            url = f"{self.target}:{self.port}{project_path}"
            print_success(f"Exposed TIA project candidate: {url} ({len(content)} bytes)")
            if bool(self.download):
                os.makedirs(str(self.output_dir or "tia_projects"), exist_ok=True)
                filename = os.path.basename(project_path.strip("/")) or "project.ap17"
                dest = os.path.join(str(self.output_dir or "tia_projects"), filename)
                with open(dest, "wb") as handle:
                    handle.write(content)
                print_info(f"  Saved to {dest}")

        if not found:
            print_info("No exposed TIA Portal project files detected")
            return False
        print_success(f"Found {found} exposed project candidate(s)")
        return True
