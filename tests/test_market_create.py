#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for ``market create`` and marketplace project scaffolding."""

import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import toml

from core.registry.manifest import ManifestParser
from core.registry.scaffold import MarketplaceScaffoldGenerator
from interfaces.command_system.builtin.market_command import MarketCommand


class MarketplaceScaffoldGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="kitty_market_create_")
        self.output_parent = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generates_publishable_scanner_project(self):
        result = MarketplaceScaffoldGenerator(
            "My New Tool",
            author="Test Author",
            description="A generated marketplace scanner",
        ).generate(self.output_parent)

        self.assertEqual(result.module_id, "my-new-tool")
        self.assertTrue(result.manifest_path.is_file())
        self.assertTrue(result.module_path.is_file())
        self.assertTrue(result.readme_path.is_file())
        self.assertTrue(result.test_path.is_file())

        manifest_data = toml.load(result.manifest_path)
        self.assertEqual(manifest_data["id"], "my-new-tool")
        self.assertEqual(manifest_data["version"], "0.1.0")
        self.assertEqual(manifest_data["entry_point"], "src/module.py")
        self.assertEqual(
            manifest_data["install_path"],
            "modules/scanner/http/my_new_tool.py",
        )
        self.assertTrue(manifest_data["permissions"]["network_access"])

        manifest = ManifestParser.parse(str(result.manifest_path))
        self.assertIsNotNone(manifest)
        valid, errors = ManifestParser.validate(manifest)
        self.assertTrue(valid, msg="; ".join(errors))

        source = result.module_path.read_text(encoding="utf-8")
        self.assertIn("class Module(Scanner, Http_client)", source)
        compile(source, str(result.module_path), "exec")

    def test_honors_exploit_options(self):
        result = MarketplaceScaffoldGenerator(
            "acme-rce",
            module_type="exploit",
            name="ACME RCE",
            version="1.2.3",
            network_access=False,
            database_access=True,
            price=9.99,
            currency="usd",
            license_name="Proprietary",
            kittysploit_max="2.0.0",
        ).generate(self.output_parent)

        manifest = toml.load(result.manifest_path)
        self.assertEqual(manifest["version"], "1.2.3")
        self.assertEqual(
            manifest["install_path"],
            "modules/exploits/multi/http/acme_rce.py",
        )
        self.assertFalse(manifest["permissions"]["network_access"])
        self.assertTrue(manifest["permissions"]["database_access"])
        self.assertEqual(manifest["metadata"]["price"], 9.99)
        self.assertEqual(manifest["metadata"]["currency"], "USD")
        self.assertEqual(manifest["compatibility"]["kittysploit_max"], "2.0.0")

    def test_generates_ui_project_without_install_path(self):
        result = MarketplaceScaffoldGenerator(
            "status-ui",
            module_type="UI",
            author="UI Author",
            description="A generated marketplace UI",
        ).generate(self.output_parent)

        self.assertEqual(result.module_type, "ui")
        self.assertEqual(result.entry_point, "src/main.py")
        self.assertIsNone(result.install_path)
        self.assertTrue(result.module_path.is_file())

        manifest_data = toml.load(result.manifest_path)
        self.assertEqual(manifest_data["extension_type"], "UI")
        self.assertEqual(manifest_data["entry_point"], "src/main.py")
        self.assertNotIn("install_path", manifest_data)
        self.assertTrue(manifest_data["permissions"]["network_access"])

        manifest = ManifestParser.parse(str(result.manifest_path))
        self.assertIsNotNone(manifest)
        valid, errors = ManifestParser.validate(manifest)
        self.assertTrue(valid, msg="; ".join(errors))

        source = result.module_path.read_text(encoding="utf-8")
        self.assertIn("def main", source)
        compile(source, str(result.module_path), "exec")

    def test_refuses_to_overwrite_existing_project(self):
        generator = MarketplaceScaffoldGenerator("duplicate-tool")
        generator.generate(self.output_parent)

        with self.assertRaises(FileExistsError):
            generator.generate(self.output_parent)

    def test_rejects_invalid_settings_without_writing(self):
        with self.assertRaises(ValueError):
            MarketplaceScaffoldGenerator("bad-version", version="latest")
        with self.assertRaises(ValueError):
            MarketplaceScaffoldGenerator("bad-price", price=-1)

        self.assertEqual(list(self.output_parent.iterdir()), [])


class MarketCreateCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="kitty_market_command_")
        self.output_parent = Path(self.temp_dir.name)
        self.command = MarketCommand(None, None, None)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_create_is_exposed_as_subcommand(self):
        self.assertIn("create", self.command.get_subcommands())
        self.assertIn("publish", self.command.get_subcommands())
        self.assertIn("mine", self.command.get_subcommands())
        self.assertIn("versions", self.command.get_subcommands())
        self.assertIn("remove", self.command.get_subcommands())
        self.assertNotIn("yank", self.command.get_subcommands())
        self.assertIn("status", self.command.get_subcommands())
        self.assertIn("logout", self.command.get_subcommands())
        parsed = self.command.parser.parse_args(
            [
                "create",
                "cli-tool",
                "--type",
                "browser_exploits",
                "--output",
                str(self.output_parent),
            ]
        )
        self.assertEqual(parsed.action, "create")
        self.assertEqual(parsed.module_id, "cli-tool")
        self.assertEqual(parsed.type, "browser_exploit")

        parsed = self.command.parser.parse_args(
            ["publish", str(self.output_parent), "--dry-run"]
        )
        self.assertEqual(parsed.action, "publish")
        self.assertTrue(parsed.dry_run)

        parsed = self.command.parser.parse_args(["status"])
        self.assertEqual(parsed.action, "status")

        parsed = self.command.parser.parse_args(["logout"])
        self.assertEqual(parsed.action, "logout")

        parsed = self.command.parser.parse_args(["mine"])
        self.assertEqual(parsed.action, "mine")

        parsed = self.command.parser.parse_args(["versions", "cli-tool"])
        self.assertEqual(parsed.action, "versions")
        self.assertEqual(parsed.module_id, "cli-tool")

        parsed = self.command.parser.parse_args(
            ["remove", "cli-tool", "--version", "1.2.3", "--yes"]
        )
        self.assertEqual(parsed.action, "remove")
        self.assertEqual(parsed.module_id, "cli-tool")
        self.assertEqual(parsed.version, "1.2.3")
        self.assertTrue(parsed.yes)

        parsed = self.command.parser.parse_args(["yank", "cli-tool", "--yes"])
        self.assertEqual(parsed.action, "yank")
        self.assertEqual(parsed.module_id, "cli-tool")
        self.assertTrue(parsed.yes)

    def test_status_without_credentials_does_not_prompt(self):
        self.command.token = None
        self.command.api_key = None

        self.assertTrue(self.command.execute(["status"]))

    def test_market_without_arguments_shows_help(self):
        with patch.object(self.command, "show_help") as show_help, patch.object(
            self.command,
            "_browse_modules",
        ) as browse_modules, patch.object(
            self.command,
            "_prompt_account_setup",
        ) as prompt_account:
            self.assertTrue(self.command.execute([]))

        show_help.assert_called_once()
        browse_modules.assert_not_called()
        prompt_account.assert_not_called()

    def test_status_checks_remote_authenticated_user(self):
        self.command.token = "test-token"

        class FakeResponse:
            status_code = 200
            content = b'{"principal": {"subject": "shogan"}}'
            text = '{"principal": {"subject": "shogan"}}'

            def json(self):
                return {
                    "principal": {
                        "subject": "shogan",
                        "email": "shogan@example.test",
                        "username": "Shogan",
                        "roles": ["admin"],
                        "permissions": ["*"],
                    }
                }

        with patch(
            "interfaces.command_system.builtin.market_command.requests.get",
            return_value=FakeResponse(),
        ) as get, patch(
            "interfaces.command_system.builtin.market_command.print_info"
        ) as print_info:
            self.assertTrue(self.command.execute(["status"]))

        get.assert_called_once()
        _, kwargs = get.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-token")
        printed = "\n".join(str(call.args[0]) for call in print_info.call_args_list)
        self.assertIn("Email: shogan@example.test", printed)
        self.assertIn("Username: Shogan", printed)
        self.assertNotIn("User: shogan", printed)

    def test_status_uses_saved_email_when_remote_omits_it(self):
        self.command.token = "test-token"
        self.command.account_email = "local@example.test"
        self.command.account_username = "LocalUser"

        data = {"principal": {"subject": "local-subject"}}
        identity = self.command._marketplace_status_identity(data)

        self.assertEqual(identity["email"], "local@example.test")
        self.assertEqual(identity["username"], "LocalUser")
        self.assertEqual(identity["subject"], "local-subject")

    def test_logout_removes_saved_credentials_but_keeps_server(self):
        with tempfile.TemporaryDirectory(prefix="kitty_market_logout_") as home:
            config_dir = Path(home) / ".kittysploit"
            config_dir.mkdir()
            config_file = config_dir / "registry_config.json"
            config_file.write_text(
                json.dumps(
                    {
                        "base_url": "https://market.example.test",
                        "token": "secret-token",
                        "api_key": "legacy-key",
                        "email": "shogan@example.test",
                        "username": "Shogan",
                        "expires_at": "2026-08-01T00:00:00Z",
                    }
                )
            )

            with patch.dict(os.environ, {"HOME": home}):
                command = MarketCommand(None, None, None)
                self.assertEqual(command.registry_url, "https://market.example.test")
                self.assertTrue(command.execute(["logout"]))

            saved = json.loads(config_file.read_text())
            self.assertEqual(saved, {"base_url": "https://market.example.test"})
            self.assertIsNone(command.token)
            self.assertIsNone(command.api_key)
            self.assertIsNone(command.account_email)
            self.assertIsNone(command.account_username)

    def test_status_handles_expired_token_as_status_result(self):
        self.command.token = "expired-token"

        class FakeResponse:
            status_code = 401
            content = b'{"error": "Unauthorized"}'
            text = '{"error": "Unauthorized"}'

        with patch(
            "interfaces.command_system.builtin.market_command.requests.get",
            return_value=FakeResponse(),
        ):
            self.assertTrue(self.command.execute(["status"]))

    def test_create_defaults_to_apps_directory(self):
        parsed = self.command.parser.parse_args(["create", "default-output-tool"])
        self.assertEqual(parsed.output, "apps")

        previous_cwd = Path.cwd()
        try:
            os.chdir(self.output_parent)
            success = self.command.execute(["create", "default-output-tool"])
        finally:
            os.chdir(previous_cwd)

        self.assertTrue(success)
        self.assertTrue(
            (self.output_parent / "apps" / "default-output-tool").is_dir()
        )
        self.assertTrue(
            (
                self.output_parent
                / "apps"
                / "default-output-tool"
                / "extension.toml"
            ).is_file()
        )

    def test_execute_creates_project_without_authentication(self):
        success = self.command.execute(
            [
                "create",
                "cli-tool",
                "--type",
                "post",
                "--author",
                "CLI Test",
                "--output",
                str(self.output_parent),
            ]
        )

        self.assertTrue(success)
        project = self.output_parent / "cli-tool"
        self.assertTrue((project / "extension.toml").is_file())
        self.assertTrue((project / "src" / "module.py").is_file())

    def test_create_auxiliary_has_no_required_target_option_by_default(self):
        success = self.command.execute(
            [
                "create",
                "hash-md5",
                "--type",
                "auxiliary",
                "--output",
                str(self.output_parent),
            ]
        )

        self.assertTrue(success)
        source = (
            self.output_parent / "hash-md5" / "src" / "module.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("rhosts = OptString", source)
        self.assertNotIn("rhost = OptString", source)

    def test_create_without_id_opens_interactive_wizard(self):
        answers = iter(
            [
                "interactive-tool",
                "8",
                "Wizard Tester",
                "Created through the wizard",
                "",
                "n",
            ]
        )
        with patch("builtins.input", side_effect=lambda _prompt: next(answers)):
            success = self.command.execute(
                ["create", "--output", str(self.output_parent)]
            )

        self.assertTrue(success)
        project = self.output_parent / "interactive-tool"
        manifest = toml.load(project / "extension.toml")
        self.assertEqual(manifest["name"], "Interactive Tool")
        self.assertEqual(
            manifest["install_path"],
            "modules/exploits/multi/http/interactive_tool.py",
        )
        self.assertTrue(manifest["permissions"]["network_access"])
        self.assertFalse(manifest["permissions"]["database_access"])

    def test_create_wizard_ctrl_c_cancels_without_failing_command(self):
        answers = iter(["interrupted-tool", KeyboardInterrupt()])

        def fake_input(_prompt):
            answer = next(answers)
            if isinstance(answer, BaseException):
                raise answer
            return answer

        with patch("builtins.input", side_effect=fake_input):
            success = self.command.execute(
                ["create", "--output", str(self.output_parent)]
            )

        self.assertTrue(success)
        self.assertFalse((self.output_parent / "interrupted-tool").exists())

    def test_create_supports_backdoor_category(self):
        success = self.command.execute(
            [
                "create",
                "linux-persist",
                "--type",
                "backdoor",
                "--output",
                str(self.output_parent),
            ]
        )

        self.assertTrue(success)
        project = self.output_parent / "linux-persist"
        manifest = toml.load(project / "extension.toml")
        self.assertEqual(
            manifest["install_path"],
            "modules/backdoors/linux/linux_persist.py",
        )
        source = (project / "src" / "module.py").read_text(encoding="utf-8")
        self.assertIn("class Module(Backdoor)", source)

    def test_publish_dry_run_validates_project_without_authentication(self):
        project = MarketplaceScaffoldGenerator(
            "publishable-tool",
            module_type="auxiliary",
        ).generate(self.output_parent).project_dir

        success = self.command.execute(["publish", str(project), "--dry-run"])

        self.assertTrue(success)
        self.assertFalse((project / "dist").exists())

    def test_publish_keep_bundle_writes_dist_bundle(self):
        project = MarketplaceScaffoldGenerator(
            "bundled-tool",
            module_type="auxiliary",
        ).generate(self.output_parent).project_dir
        self.command.token = "test-token"

        success = self.command.execute(
            ["publish", str(project), "--dry-run", "--keep-bundle"]
        )

        self.assertTrue(success)
        bundles = list((project / "dist").glob("*.kext"))
        self.assertEqual(len(bundles), 1)

    def test_publish_uploads_valid_bundle(self):
        project = MarketplaceScaffoldGenerator(
            "uploadable-tool",
            module_type="auxiliary",
        ).generate(self.output_parent).project_dir
        self.command.token = "test-token"

        class FakeResponse:
            status_code = 200
            content = b'{"success": true}'
            text = '{"success": true}'

            def raise_for_status(self):
                return None

            def json(self):
                return {"success": True, "url": "https://example.test/tool"}

        with patch(
            "interfaces.command_system.builtin.market_command.requests.post",
            return_value=FakeResponse(),
        ) as post:
            success = self.command.execute(["publish", str(project)])

        self.assertTrue(success)
        self.assertEqual(post.call_count, 1)
        _, kwargs = post.call_args
        self.assertIn("files", kwargs)
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-token")

    def test_publish_reports_missing_server_endpoint(self):
        project = MarketplaceScaffoldGenerator(
            "missing-endpoint-tool",
            module_type="auxiliary",
        ).generate(self.output_parent).project_dir
        self.command.token = "test-token"

        class FakeResponse:
            status_code = 404
            content = b'{"error": "not found"}'
            text = '{"error": "not found"}'

            def raise_for_status(self):
                return None

        with patch(
            "interfaces.command_system.builtin.market_command.requests.post",
            return_value=FakeResponse(),
        ) as post:
            success = self.command.execute(["publish", str(project)])

        self.assertTrue(success)
        self.assertEqual(post.call_count, 2)

    def test_mine_lists_authenticated_publications(self):
        self.command.token = "test-token"

        class FakeResponse:
            status_code = 200
            content = b'{"modules": []}'
            text = '{"modules": []}'

            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "modules": [
                        {
                            "id": 1,
                            "extension_id": "hash-md5",
                            "name": "Hash Md5",
                            "version": "0.1.0",
                            "status": "published",
                        }
                    ]
                }

        with patch(
            "interfaces.command_system.builtin.market_command.requests.request",
            return_value=FakeResponse(),
        ) as request, patch(
            "interfaces.command_system.builtin.market_command.print_info"
        ) as print_info:
            self.assertTrue(self.command.execute(["mine"]))

        request.assert_called_once()
        args, kwargs = request.call_args
        self.assertEqual(args[0], "GET")
        self.assertTrue(args[1].endswith("/api/cli/market/my/modules"))
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-token")
        printed = "\n".join(str(call.args[0]) for call in print_info.call_args_list)
        self.assertIn("Hash Md5 v0.1.0 [published]", printed)
        self.assertIn("ID: hash-md5", printed)
        self.assertIn("Remove: market remove hash-md5", printed)

    def test_versions_lists_authenticated_module_versions(self):
        self.command.token = "test-token"

        class FakeResponse:
            status_code = 200
            content = b'{"versions": []}'
            text = '{"versions": []}'

            def raise_for_status(self):
                return None

            def json(self):
                return {"versions": [{"version": "0.1.0", "is_latest": True}]}

        with patch(
            "interfaces.command_system.builtin.market_command.requests.request",
            return_value=FakeResponse(),
        ) as request:
            self.assertTrue(self.command.execute(["versions", "hash-md5"]))

        args, _kwargs = request.call_args
        self.assertEqual(args[0], "GET")
        self.assertTrue(args[1].endswith("/api/cli/market/my/modules/hash-md5/versions"))

    def test_remove_deletes_authenticated_publication_with_confirmation_skip(self):
        self.command.token = "test-token"

        class FakeResponse:
            status_code = 200
            content = b'{"success": true}'
            text = '{"success": true}'

            def raise_for_status(self):
                return None

            def json(self):
                return {"success": True}

        with patch(
            "interfaces.command_system.builtin.market_command.requests.request",
            return_value=FakeResponse(),
        ) as request:
            self.assertTrue(
                self.command.execute(
                    ["remove", "hash-md5", "--version", "0.1.0", "--yes"]
                )
            )

        args, kwargs = request.call_args
        self.assertEqual(args[0], "DELETE")
        self.assertTrue(
            args[1].endswith(
                "/api/cli/market/my/modules/hash-md5/versions/0.1.0"
            )
        )
        self.assertEqual(kwargs["json"], {})


if __name__ == "__main__":
    unittest.main()
