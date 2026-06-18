#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""New command implementation — scaffold modules and other assets."""

import argparse

from core.module_generator import MODULE_KINDS, ModuleSkeletonGenerator
from core.output_handler import print_error, print_info, print_success
from interfaces.command_system.base_command import BaseCommand


class NewCommand(BaseCommand):
    """Scaffold new KittySploit modules with template, metadata and tests."""

    @property
    def name(self) -> str:
        return "new"

    @property
    def description(self) -> str:
        return "Scaffold new framework assets (module skeletons with metadata and tests)"

    @property
    def usage(self) -> str:
        return (
            "new module <slug> [--type scanner|auxiliary|exploit|post|payload|listener] "
            "[--path <modules/subpath>] [--name <title>] [--author <name>] "
            "[--description <text>] [--tag <tag>] [--cve CVE-YYYY-NNNN] "
            "[--http-mixin|--no-http-mixin] [--preview] [--force]"
        )

    @property
    def help_text(self) -> str:
        kinds = ", ".join(sorted(MODULE_KINDS))
        return f"""
{self.description}

Usage: {self.usage}

Subcommands:
    module <slug>    Generate a module skeleton under modules/

Module types (--type):
    {kinds}

Options:
    --path           Directory under modules/ (default depends on --type)
    --name           Human-readable module title
    --author         Author name, or comma-separated list
    --description    Module description
    --tag            Extra tag (repeatable)
    --cve            CVE identifier for vulnerability modules
    --http-mixin     Include Http_client mixin (default for HTTP scanner/exploit)
    --no-http-mixin  Omit Http_client mixin
    --modules-dir    Override modules root (default: modules)
    --tests-dir      Override tests root (default: tests/modules)
    --preview        Show planned output without writing files
    --force          Overwrite existing files

Generated files:
    modules/<path>/<slug>.py
    modules/<path>/<slug>.metadata.json
    tests/modules/<path>/test_<slug>.py

Examples:
    new module acme_login_scanner --type scanner --path scanner/http --tag acme
    new module acme_rce --type exploit --cve CVE-2026-12345 --author "Jane Doe"
    new module tcp_probe --type auxiliary --path auxiliary/scanner/portscan --no-http-mixin
    new module bash_rev --type payload --path payloads/singles/cmd/unix
    new module bind_tcp --type listener --preview
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="new module", description=self.description)
        parser.add_argument("slug", help="Module file slug (e.g. acme_cve_2026_1234)")
        parser.add_argument(
            "--type",
            choices=sorted(MODULE_KINDS),
            default="scanner",
            help="Module kind (default: scanner)",
        )
        parser.add_argument("--path", help="Subpath under modules/ (default depends on --type)")
        parser.add_argument("--name", help="Display name for __info__")
        parser.add_argument("--author", help="Author name or comma-separated authors")
        parser.add_argument("--description", help="Module description")
        parser.add_argument("--tag", action="append", default=[], help="Extra tag (repeatable)")
        parser.add_argument("--cve", help="CVE identifier")
        parser.add_argument("--http-mixin", dest="http_mixin", action="store_true", default=None, help="Include Http_client mixin")
        parser.add_argument("--no-http-mixin", dest="http_mixin", action="store_false", help="Omit Http_client mixin")
        parser.add_argument("--modules-dir", default=str(ModuleSkeletonGenerator.DEFAULT_MODULES_DIR), help="Modules root directory")
        parser.add_argument("--tests-dir", default=str(ModuleSkeletonGenerator.DEFAULT_TESTS_DIR), help="Generated tests root")
        parser.add_argument("--preview", action="store_true", help="Preview without writing files")
        parser.add_argument("--force", action="store_true", help="Overwrite existing files")
        return parser

    def execute(self, args, **kwargs) -> bool:
        if not args:
            print_info(self.help_text)
            return True

        if args[0].lower() in {"-h", "--help", "help"}:
            print_info(self.help_text)
            return True

        subcommand = args[0].lower()
        if subcommand != "module":
            print_error(f"Unknown subcommand: {subcommand}")
            print_info("Usage: new module <slug> [options]")
            return False

        return self._run_module(args[1:])

    def _run_module(self, args) -> bool:
        try:
            parsed = self.parser.parse_args(args)
            generator = ModuleSkeletonGenerator(
                slug=parsed.slug,
                module_type=parsed.type,
                subpath=parsed.path,
                name=parsed.name,
                description=parsed.description,
                author=parsed.author,
                tags=parsed.tag,
                cve=parsed.cve,
                http_mixin=parsed.http_mixin,
            )
            if parsed.preview:
                print_info(generator.preview())
                return True
            result = generator.generate(
                modules_dir=parsed.modules_dir,
                tests_dir=parsed.tests_dir,
                force=parsed.force,
            )
        except SystemExit:
            return True
        except Exception as exc:
            print_error(f"Module scaffold failed: {exc}")
            return False

        print_success(f"Created module skeleton: {result.module_path}")
        print_info(f"  - {result.metadata_path}")
        print_info(f"  - {result.test_path}")
        print_info(f"Module path: {result.module_relative_path}")
        print_info(f"Run tests: python -m unittest {result.test_path}")
        print_info(f"Load with: use {result.module_relative_path}")
        return True

    def get_subcommands(self):
        return ["module", "--type", "--path", "--name", "--author", "--description", "--tag", "--cve", "--preview", "--force"]
