#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""API import command implementation."""

import argparse

from core.api_module_generator import ApiModuleGenerator
from core.output_handler import print_error, print_info, print_success
from interfaces.command_system.base_command import BaseCommand


class ApiImportCommand(BaseCommand):
    """Generate KittySploit modules from OpenAPI, GraphQL introspection or traffic."""

    @property
    def name(self) -> str:
        return "api_import"

    @property
    def description(self) -> str:
        return "Generate scanners/fuzzers/tests from OpenAPI, GraphQL introspection or KittyProxy traffic"

    @property
    def usage(self) -> str:
        return "api_import <schema_or_traffic_file> [--type auto|openapi|graphql|traffic] [--name <name>] [--kind scanner,fuzzer]"

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Inputs:
    OpenAPI/Swagger JSON or YAML
    GraphQL introspection JSON
    HAR, KittyProxy-like JSON, or list of HTTP request entries

Options:
    --type          Input type (default: auto)
    --name          Friendly API/module pack name
    --kind          scanner, fuzzer, or scanner,fuzzer (default)
    --module-dir    Output directory for generated modules (default: modules/generated/api)
    --artifact-dir  Output directory for manifest/fixtures/tests (default: artifacts/api_module_packs)
    --preview       Show normalized inventory without writing files
    --force         Overwrite generated files

Examples:
    api_import openapi.json
    api_import graphql-introspection.json --type graphql --name internal_graphql
    api_import kittyproxy_traffic.har --type traffic --kind scanner --force
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="api_import", description=self.description)
        parser.add_argument("source", help="OpenAPI/GraphQL/traffic source file")
        parser.add_argument("--type", choices=["auto", "openapi", "graphql", "traffic"], default="auto", help="Input type")
        parser.add_argument("--name", help="Generated API pack name")
        parser.add_argument("--kind", default="scanner,fuzzer", help="scanner, fuzzer, or scanner,fuzzer")
        parser.add_argument("--module-dir", default=str(ApiModuleGenerator.DEFAULT_MODULE_DIR), help="Generated module directory")
        parser.add_argument("--artifact-dir", default=str(ApiModuleGenerator.DEFAULT_ARTIFACT_DIR), help="Generated artifact directory")
        parser.add_argument("--preview", action="store_true", help="Preview normalized endpoints without writing files")
        parser.add_argument("--force", action="store_true", help="Overwrite generated module files")
        return parser

    def execute(self, args, **kwargs) -> bool:
        try:
            parsed = self.parser.parse_args(args)
            generator = ApiModuleGenerator(parsed.source, source_type=parsed.type, name=parsed.name)
            if parsed.preview:
                print_info(generator.preview())
                return True
            kinds = [item.strip() for item in parsed.kind.split(",") if item.strip()]
            result = generator.generate(
                module_dir=parsed.module_dir,
                artifact_dir=parsed.artifact_dir,
                kinds=kinds,
                force=parsed.force,
            )
        except SystemExit:
            return True
        except Exception as exc:
            print_error(f"API import failed: {exc}")
            return False

        print_success(f"Generated {len(result.module_files)} module file(s)")
        for path in result.module_files:
            print_info(f"  - {path}")
        print_success(f"Generated API module pack: {result.manifest['artifact_path']}")
        for path in result.artifact_files:
            print_info(f"  - {path}")
        print_info(f"Run tests with: python -m unittest discover -s {result.manifest['artifact_path']}/tests")
        return True

    def get_subcommands(self):
        return ["--type", "--name", "--kind", "--module-dir", "--artifact-dir", "--preview", "--force"]
