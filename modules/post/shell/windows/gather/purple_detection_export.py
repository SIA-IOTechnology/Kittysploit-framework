#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate detection packs for post-ex modules (purple team)."""

from kittysploit import *
import os

from core.detection import DetectionPackGenerator
from core.detection.post_telemetry import POST_TELEMETRY


class Module(Post):
    __info__ = {
        "name": "Purple Team Detection Export",
        "description": (
            "Generate Sigma/EDR detection packs for post-exploitation modules "
            "(Windows & Linux) using the post telemetry registry."
        ),
        "author": "KittySploit Team",
        "platform": [Platform.WINDOWS, Platform.LINUX],
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.3,
            "noise": 0.1,
            "value": 0.8,
            "requires": {"capabilities_any": [], "capabilities_all": []},
            "chain": {"consumes_capabilities": [], "produces_capabilities": []},
        },
    }

    output_dir = OptString("output/purple_detection", "Base output directory for packs", False)
    formats = OptString("sigma,docs,tests", "Comma-separated pack formats", False)
    force = OptBool(True, "Overwrite existing pack directories", False)
    module_filter = OptString(
        "",
        "Generate only this module path (empty = all registry modules)",
        False,
    )

    def run(self):
        if not self.framework:
            print_error("Framework not available.")
            return False

        out_base = str(self.output_dir or "output/purple_detection").strip()
        os.makedirs(out_base, exist_ok=True)

        selected_formats = [
            x.strip() for x in str(self.formats or "sigma,docs,tests").split(",") if x.strip()
        ]
        filt = str(self.module_filter or "").strip().replace("\\", "/")
        paths = sorted(POST_TELEMETRY.keys())
        if filt:
            paths = [p for p in paths if p == filt or filt in p]

        if not paths:
            print_warning("No modules matched module_filter.")
            return False

        generated = 0
        for module_path in paths:
            print_status(f"Generating detection pack for {module_path}...")
            module = self.framework.load_module(module_path, load_only=True)
            if not module:
                print_warning(f"Could not load {module_path}")
                continue
            gen = DetectionPackGenerator(module, module_path=module_path)
            try:
                pack = gen.generate(
                    output_dir=out_base,
                    force=bool(self.force),
                    formats=selected_formats,
                )
                print_success(f"Pack written: {pack.output_dir} ({len(pack.files)} files)")
                generated += 1
            except FileExistsError as exc:
                print_warning(str(exc))
            except Exception as exc:
                print_error(f"{module_path}: {exc}")

        print_info(f"Generated {generated}/{len(paths)} detection packs under ./{out_base}")
        return generated > 0
