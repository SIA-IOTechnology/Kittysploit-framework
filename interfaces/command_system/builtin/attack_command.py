#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ATT&CK mapping command — catalog, coverage, and exports."""

from __future__ import annotations

import argparse
import json

from core.attack_mapping import (
    build_attack_catalog,
    export_heatmap_json,
    export_heatmap_markdown,
    export_navigator_layer,
    export_stix_bundle,
    export_taxii_collection_manifest,
)
from core.attack_mapping.exporters import write_json_export, write_text_export
from core.output_handler import print_empty, print_error, print_info, print_success, print_table, print_warning
from interfaces.command_system.base_command import BaseCommand


class AttackCommand(BaseCommand):
    """Native MITRE ATT&CK mapping for KittySploit modules."""

    @property
    def name(self) -> str:
        return "attack"

    @property
    def description(self) -> str:
        return "Browse ATT&CK mappings and export Navigator, STIX/TAXII, and coverage heatmaps"

    @property
    def usage(self) -> str:
        return "attack [catalog|show|export] [args...]"

    def get_subcommands(self):
        return ["catalog", "show", "export"]

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Modules can declare native ATT&CK metadata in ``__info__``:

    "attack": {{
        "tactics": ["TA0007", "Discovery"],
        "techniques": ["T1046"],
        "prerequisites": ["TCP connectivity to target"],
        "detections": ["IDS port sweep alert", "Sigma: network_connection_port_scan"],
        "artifacts": ["Firewall flow logs", "Zeek conn.log"],
    }}

Subcommands:
    catalog [--json] [--declared-only]     Summarize technique/tactic coverage
    show <module_path>                     Show mapping for one module
    export [--format navigator|stix|taxii|heatmap] [--output <path>]

Examples:
    attack catalog
    attack show auxiliary/scanner/portscan/tcp
    attack export --format navigator --output /tmp/kittysploit-navigator.json
    attack export --format stix --output /tmp/kittysploit-attack.stix.json
    attack export --format heatmap --output /tmp/attack-heatmap.md
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="attack",
            description="MITRE ATT&CK mapping for KittySploit modules",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        subparsers = parser.add_subparsers(dest="action")

        catalog = subparsers.add_parser("catalog", help="Summarize ATT&CK coverage")
        catalog.add_argument("--json", action="store_true", help="JSON output")
        catalog.add_argument("--declared-only", action="store_true", help="Only declared mappings")

        show = subparsers.add_parser("show", help="Show mapping for one module")
        show.add_argument("module_path", help="Module path")

        export = subparsers.add_parser("export", help="Export ATT&CK artifacts")
        export.add_argument(
            "--format",
            choices=["navigator", "stix", "taxii", "heatmap", "all"],
            default="navigator",
            help="Export format",
        )
        export.add_argument("--output", "-o", help="Output file or directory")
        export.add_argument(
            "--heatmap-format",
            choices=["json", "markdown"],
            default="markdown",
            help="Heatmap serialization when --format heatmap",
        )
        return parser

    def execute(self, args, **kwargs) -> bool:
        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return True

        if not parsed.action:
            self._print_usage_hint()
            return True

        catalog = self._build_catalog()
        if catalog is None:
            return False

        if parsed.action == "catalog":
            return self._handle_catalog(catalog, parsed)
        if parsed.action == "show":
            return self._handle_show(catalog, parsed.module_path)
        if parsed.action == "export":
            return self._handle_export(catalog, parsed)
        return False

    def _build_catalog(self):
        loader = getattr(self.framework, "module_loader", None)
        if loader is None:
            print_error("Module loader is not available")
            return None
        return build_attack_catalog(loader.discover_modules())

    def _handle_catalog(self, catalog, parsed) -> bool:
        mappings = catalog.mappings
        if parsed.declared_only:
            mappings = [item for item in mappings if item.declared]

        if parsed.json:
            payload = catalog.to_dict()
            if parsed.declared_only:
                payload["mappings"] = [item.to_dict() for item in mappings]
            print_info(json.dumps(payload, indent=2, sort_keys=True))
            return True

        print_info("ATT&CK Module Catalog")
        print_info("=" * 50)
        print_info(f"Modules indexed: {len(catalog.mappings)}")
        print_info(f"Declared mappings: {catalog.declared_count}")
        print_info(f"Inferred-only mappings: {catalog.inferred_only_count}")
        print_info(f"Techniques covered: {len(catalog.technique_index)}")
        print_info(f"Tactics covered: {len(catalog.tactic_index)}")
        print_info(f"Defensive metadata entries: {len(catalog.defensive_techniques)}")

        print_empty()
        print_info("Top techniques:")
        rows = []
        for technique, modules in list(catalog.technique_index.items())[:15]:
            rows.append(
                [
                    technique,
                    str(len(modules)),
                    str(len(catalog.offensive_techniques.get(technique, []))),
                    str(len(catalog.defensive_techniques.get(technique, []))),
                ]
            )
        if rows:
            print_table(["Technique", "Modules", "Offensive", "Defensive"], rows)
        else:
            print_warning("No ATT&CK techniques indexed yet")
        return True

    def _handle_show(self, catalog, module_path: str) -> bool:
        mapping = next((item for item in catalog.mappings if item.module_path == module_path), None)
        if mapping is None:
            print_error(f"Module not found in catalog: {module_path}")
            return False

        print_info(f"Module: {mapping.module_path}")
        print_info(f"Name: {mapping.module_name}")
        print_info(f"Type: {mapping.module_type}")
        print_info(f"Declared mapping: {'yes' if mapping.declared else 'no'}")
        print_info(f"Tactics: {', '.join(mapping.tactics) or 'n/a'}")
        print_info(f"Techniques: {', '.join(mapping.techniques) or 'n/a'}")
        if mapping.inferred_techniques:
            print_info(f"Inferred techniques: {', '.join(mapping.inferred_techniques)}")
        if mapping.prerequisites:
            print_info("Prerequisites:")
            for item in mapping.prerequisites:
                print_info(f"  - {item}")
        if mapping.detections:
            print_info("Expected detections:")
            for item in mapping.detections:
                print_info(f"  - {item}")
        if mapping.artifacts:
            print_info("Artifacts:")
            for item in mapping.artifacts:
                print_info(f"  - {item}")
        return True

    def _handle_export(self, catalog, parsed) -> bool:
        output = parsed.output
        formats = ["navigator", "stix", "taxii", "heatmap"] if parsed.format == "all" else [parsed.format]

        for fmt in formats:
            if fmt == "navigator":
                payload = export_navigator_layer(catalog)
                path = output or "artifacts/attack/attack_navigator_layer.json"
                write_json_export(payload, path)
                print_success(f"Navigator layer exported to {path}")
            elif fmt == "stix":
                payload = export_stix_bundle(catalog)
                path = output or "artifacts/attack/kittysploit_attack.stix.json"
                write_json_export(payload, path)
                print_success(f"STIX bundle exported to {path}")
            elif fmt == "taxii":
                payload = export_taxii_collection_manifest(catalog)
                path = output or "artifacts/attack/taxii_collection_manifest.json"
                write_json_export(payload, path)
                print_success(f"TAXII collection manifest exported to {path}")
            elif fmt == "heatmap":
                if parsed.heatmap_format == "json":
                    payload = export_heatmap_json(catalog)
                    path = output or "artifacts/attack/attack_heatmap.json"
                    write_json_export(payload, path)
                else:
                    content = export_heatmap_markdown(catalog)
                    path = output or "artifacts/attack/attack_heatmap.md"
                    write_text_export(content, path)
                print_success(f"Heatmap exported to {path}")
        return True

    def _print_usage_hint(self) -> None:
        print_info("Usage: attack catalog | attack show <module> | attack export --format navigator")
