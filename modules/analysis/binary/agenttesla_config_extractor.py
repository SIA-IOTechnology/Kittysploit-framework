#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extract C2 configuration from AgentTesla .NET malware samples via static IL
analysis and controlled invocation of embedded string-decryption routines.
"""

import os

from kittysploit import *

from core.utils.paths import data_resource_fs_path, require_framework_root
from lib.analysis.malware.agenttesla_extractor import AgentTeslaExtractor
from lib.analysis.malware.dotnet_requirements import check_prerequisites, platform_label
from lib.analysis.malware.dotnet_runtime import format_pythonnet_error, import_clr


class Module(Analysis):
    __info__ = {
        "name": "AgentTesla Config Extractor",
        "description": (
            "Analyze AgentTesla .NET payloads: locate string-decryption methods, "
            "invoke them with IL-derived keys under a watchdog timeout, and extract "
            "likely C2 indicators (HTTP, SMTP, FTP). Requires pythonnet and dnlib.dll."
        ),
        "author": ["Dr4ke-Sm0G", "KittySploit Team"],
        "references": [
            "https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla",
        ],
        "tags": ["malware", "agenttesla", "dotnet", "dfir", "ioc", "analysis"],
        "dependencies": ["pythonnet"],
    }

    file_path = OptString("", "Path to the AgentTesla .NET payload", required=True)
    timeout = OptInteger(2, "Maximum seconds per decryption call (anti-analysis watchdog)",required=False, advanced=True)
    verbose = OptBool(False, "Verbose analysis output", required=False, advanced=True)

    @staticmethod
    def _bundled_dnlib_path() -> str:
        bundled = data_resource_fs_path("dll", "dnlib.dll")
        if bundled:
            return str(bundled)
        return str(require_framework_root() / "data" / "dll" / "dnlib.dll")

    def check(self) -> bool:
        path = os.path.abspath(str(self.file_path or "").strip())
        if not path:
            print_error("file_path is required")
            return False
        if not os.path.isfile(path):
            print_error(f"Payload not found: {path}")
            return False

        dnlib = self._bundled_dnlib_path()
        for issue in check_prerequisites(dnlib):
            print_error(issue)
            return False

        if self.verbose:
            print_info(f"Platform: {platform_label()}")
            print_info(f"dnlib: {dnlib}")

        try:
            clr = import_clr()
            clr.AddReference("System")
        except ImportError as exc:
            print_error(format_pythonnet_error(exc))
            return False
        except Exception as exc:
            print_error(format_pythonnet_error(exc))
            return False

        return True

    def run(self):
        if not self.check():
            return False

        payload = os.path.abspath(str(self.file_path).strip())
        dnlib = self._bundled_dnlib_path()

        try:
            watchdog = max(1, int(self.timeout))
        except (TypeError, ValueError):
            watchdog = 2

        print_status(f"Analyzing AgentTesla payload: {payload}")

        try:
            extractor = AgentTeslaExtractor(
                file_path=payload,
                dnlib_path=dnlib,
                timeout=watchdog,
                verbose=bool(self.verbose),
                log=print_info,
                log_warning=print_warning,
                log_error=print_error,
            )
            results = extractor.run()
        except (FileNotFoundError, ImportError, RuntimeError, ValueError) as exc:
            print_error(str(exc))
            return False
        except Exception as exc:
            print_error(f"AgentTesla analysis failed: {exc}")
            if self.verbose:
                import traceback
                print_error(traceback.format_exc())
            return False

        metadata = results.get("metadata") or {}
        iocs = results.get("extracted_config") or []
        all_strings = results.get("all_strings") or []

        print_empty()
        print_info("=" * 40)
        print_info(" AgentTesla Intelligence Report ")
        print_info("=" * 40)
        print_info(f"File:      {metadata.get('filename', os.path.basename(payload))}")
        print_info(f"Module:    {metadata.get('module_name') or 'n/a'}")
        print_info(f".NET:      {metadata.get('dotnet_runtime_version') or 'n/a'}")
        print_info(f"Mode:      {metadata.get('analysis_mode') or 'n/a'}")
        print_info(f"Timestamp: {metadata.get('timestamp', 'n/a')}")

        for warning in metadata.get("warnings") or []:
            for line in str(warning).splitlines():
                if line.strip():
                    print_warning(line)

        print_empty()
        print_info("C2 / IoC indicators:")
        if iocs:
            for ioc in iocs:
                print_success(f"  [!] {ioc}")
        else:
            print_warning("  [-] No critical IoCs found.")

        print_empty()
        print_info(f"All strings ({len(all_strings)}):")
        if all_strings:
            for value in all_strings:
                print_info(f"  - {value}")
        else:
            print_warning("  [-] No strings decrypted.")

        return results

    def get_graph_nodes(self, data):
        if not isinstance(data, dict):
            return [], []

        root = "agenttesla_extractor"
        nodes = [
            {
                "id": root,
                "label": "AgentTesla Extractor",
                "group": "event",
                "icon": "search",
            }
        ]
        edges = []

        for ioc in data.get("extracted_config") or []:
            node_id = f"ioc_{hash(ioc) & 0xFFFFFFFF}"
            nodes.append(
                {
                    "id": node_id,
                    "label": ioc[:80],
                    "group": "c2",
                    "icon": "ioc",
                }
            )
            edges.append({"from": root, "to": node_id, "label": "c2"})

        return nodes, edges
