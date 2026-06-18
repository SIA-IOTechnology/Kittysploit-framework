#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detection pack command implementation."""

import argparse
from pathlib import Path

from core.detection import DetectionPackGenerator
from core.output_handler import print_error, print_info, print_success
from interfaces.command_system.base_command import BaseCommand


class DetectionPackCommand(BaseCommand):
    """Generate blue-team detection engineering assets from a module."""

    VALID_FORMATS = ("sigma", "yara", "suricata", "zeek", "docs", "tests")

    @property
    def name(self) -> str:
        return "detection_pack"

    @property
    def description(self) -> str:
        return "Generate Sigma/YARA/Suricata/Zeek detections from an offensive module"

    @property
    def usage(self) -> str:
        return "detection_pack [module_path] [--output <dir>] [--formats <list>] [--force] [--preview]"

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

If module_path is omitted, the currently selected module is used.

Options:
    --output, -o <dir>      Base output directory (default: artifacts/detection_packs)
    --formats <list>        Comma-separated formats: {", ".join(self.VALID_FORMATS)}
    --force                 Overwrite an existing pack directory
    --preview               Show extracted metadata without writing files

Examples:
    detection_pack
    detection_pack exploits/linux/http/php_cgi_cve_2024_4577_rce
    detection_pack --formats sigma,suricata,docs,tests --force
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="detection_pack",
            description="Generate detection engineering assets from a KittySploit module",
            add_help=True,
        )
        parser.add_argument("module_path", nargs="?", help="Module path to load; defaults to current module")
        parser.add_argument("--output", "-o", default=str(DetectionPackGenerator.DEFAULT_OUTPUT_DIR), help="Base output directory")
        parser.add_argument("--formats", default=",".join(self.VALID_FORMATS), help="Comma-separated output formats")
        parser.add_argument("--force", action="store_true", help="Overwrite existing pack directory")
        parser.add_argument("--preview", action="store_true", help="Preview extracted metadata without writing files")
        return parser

    def execute(self, args, **kwargs) -> bool:
        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return True

        module = None
        module_path = parsed.module_path
        if module_path:
            module = self.framework.module_loader.load_module(module_path, load_only=True, framework=self.framework)
            if not module:
                print_error(f"Could not load module: {module_path}")
                return False
        else:
            module = getattr(self.framework, "current_module", None)
            if not module:
                print_error("No module selected. Use 'use <module>' or pass a module path.")
                return False
            module_path = self._current_module_path(module)

        formats = self._parse_formats(parsed.formats)
        if not formats:
            return False

        generator = DetectionPackGenerator(module, module_path=module_path)
        if parsed.preview:
            print_info(generator.preview())
            return True

        try:
            result = generator.generate(output_dir=parsed.output, force=parsed.force, formats=formats)
        except FileExistsError as exc:
            print_error(str(exc))
            return False
        except Exception as exc:
            print_error(f"Failed to generate detection pack: {exc}")
            return False

        print_success(f"Detection pack generated: {result.output_dir}")
        print_info("Files:")
        for path in result.files:
            print_info(f"  - {Path(path)}")
        print_info(f"Run tests with: python -m unittest discover -s {result.output_dir / 'tests'}")
        return True

    def get_subcommands(self):
        return ["--preview", "--force", "--output", "--formats"]

    def _parse_formats(self, raw: str):
        formats = [item.strip().lower() for item in str(raw or "").split(",") if item.strip()]
        invalid = [item for item in formats if item not in self.VALID_FORMATS]
        if invalid:
            print_error(f"Unknown detection pack format(s): {', '.join(invalid)}")
            print_info(f"Valid formats: {', '.join(self.VALID_FORMATS)}")
            return None
        return formats

    def _current_module_path(self, module) -> str:
        module_name = getattr(module.__class__, "__module__", "")
        if module_name.startswith("modules."):
            return module_name[len("modules."):].replace(".", "/")
        return module_name.replace(".", "/") or getattr(module, "name", "current_module")
