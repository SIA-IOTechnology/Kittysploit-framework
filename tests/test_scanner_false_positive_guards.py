#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for scanner false-positive guards."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from core.framework.base_module import normalize_module_result
from core.framework.scanner import Scanner
from core.scanner.result_dedup import (
    enrich_scanner_result,
    scanner_return_is_vulnerable,
)
from lib.scanner.http.serverless_probe import probe_function_endpoint


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = dict(headers or {})

    def __bool__(self):
        # Match requests.Response: HTTP errors are falsey.
        return self.status_code < 400

    def json(self):
        return json.loads(self.text)


def bare_module(module_class, response):
    instance = object.__new__(module_class)
    instance.http_request = lambda **_kwargs: response
    instance.set_info = lambda **kwargs: setattr(instance, "vulnerability_info", kwargs)
    return instance


class ScannerResultGuardTests(unittest.TestCase):
    def test_explicit_false_verdict_overrides_command_success(self):
        raw = {"success": True, "vulnerable": False, "reason": "patched"}
        self.assertFalse(scanner_return_is_vulnerable(raw))
        self.assertFalse(scanner_return_is_vulnerable(normalize_module_result(raw)))
        self.assertFalse(scanner_return_is_vulnerable({"vulnerable": "false"}))

    def test_scanner_console_demotes_info_only_match(self):
        class InfoScanner(Scanner):
            __info__ = {"name": "Technology fingerprint", "severity": "info"}

            def run(self):
                self.set_info(severity="info", reason="Technology detected")
                return True

        self.assertFalse(InfoScanner()._exploit())

    def test_info_detection_is_not_counted_as_vulnerability(self):
        result = enrich_scanner_result(
            {
                "path": "scanner/http/apache_axis_detect",
                "severity": "info",
                "message": "Apache Axis detected",
                "vulnerable": True,
            }
        )
        self.assertFalse(result["vulnerable"])
        self.assertTrue(result["detected"])
        self.assertEqual(result["status"], "detected")

    def test_actionable_non_info_finding_is_preserved(self):
        result = enrich_scanner_result(
            {
                "path": "scanner/http/example_file_read",
                "severity": "high",
                "message": "Arbitrary file read confirmed",
                "vulnerable": True,
            }
        )
        self.assertTrue(result["vulnerable"])

    def test_low_confidence_cve_is_suppressed(self):
        result = enrich_scanner_result(
            {
                "path": "scanner/http/example_cve_detect",
                "cve": "CVE-2026-99999",
                "severity": "high",
                "message": "Product detected; version unknown",
                "vulnerable": True,
                "details": {"confidence": "low"},
            }
        )
        self.assertFalse(result["vulnerable"])
        self.assertIn("speculative", result["suppressed_reason"])

    def test_high_confidence_cve_is_preserved(self):
        result = enrich_scanner_result(
            {
                "path": "scanner/http/example_cve_detect",
                "cve": "CVE-2026-99999",
                "severity": "high",
                "message": "Exploit behavior confirmed",
                "vulnerable": True,
                "details": {"confidence": "high"},
            }
        )
        self.assertTrue(result["vulnerable"])


class HttpEvidenceGuardTests(unittest.TestCase):
    def test_generic_json_is_not_a_serverless_finding(self):
        response = FakeResponse(200, "{}", {"Content-Type": "application/json"})
        self.assertIsNone(probe_function_endpoint(lambda **_kwargs: response, "/api"))

    def test_vendor_header_is_serverless_evidence(self):
        response = FakeResponse(200, "ok", {"x-amzn-requestid": "request-1"})
        hit = probe_function_endpoint(lambda **_kwargs: response, "/api")
        self.assertIsNotNone(hit)
        self.assertIn("aws_lambda_response", hit["indicators"])

    def test_openapi_document_requires_schema_fields(self):
        body = json.dumps({"openapi": "3.0.0", "paths": {"/hello": {}}})
        response = FakeResponse(200, body, {"Content-Type": "application/json"})
        hit = probe_function_endpoint(
            lambda **_kwargs: response,
            "/.well-known/openapi.json",
        )
        self.assertIsNotNone(hit)
        self.assertIn("openapi_document", hit["indicators"])

    def test_generic_html_does_not_trigger_reflected_xss_modules(self):
        from modules.scanner.http.cve_2023_35158_detect import Module as XwikiRestore
        from modules.scanner.http.cve_2023_46732_detect import Module as XwikiRevision
        from modules.scanner.http.cve_2024_3822_detect import Module as Base64Plugin
        from modules.scanner.http.fronsetiav_xss_detect import Module as Fronsetia

        response = FakeResponse(
            200,
            "<!doctype html><html><title>Welcome</title></html>",
            {"Content-Type": "text/html"},
        )
        for module_class in (XwikiRestore, XwikiRevision, Base64Plugin, Fronsetia):
            with self.subTest(module=module_class.__module__):
                self.assertFalse(bare_module(module_class, response).run())

    def test_generic_html_does_not_trigger_sensitive_file_modules(self):
        from modules.scanner.http.apache_axis_detect import Module as ApacheAxis
        from modules.scanner.http.application_yaml_detect import Module as ApplicationYaml
        from modules.scanner.http.cve_2017_10974_detect import Module as YawsKey
        from modules.scanner.http.generic_db_detect import Module as GenericDatabase
        from modules.scanner.http.laravel_passport_keys_exposed_detect import (
            Module as LaravelKeys,
        )
        from modules.scanner.http.makefile_detect import Module as Makefile
        from modules.scanner.http.rubygems_credentials_detect import Module as RubyGems
        from modules.scanner.http.stem_audio_table_private_keys_detect import (
            Module as StemKey,
        )
        from modules.scanner.http.wordpress_git_config_detect import Module as WordpressGit
        from modules.scanner.http.xss_uri_reflected_detect import Module as GenericXss

        response = FakeResponse(
            200,
            "<!doctype html><html><title>Welcome</title><body>Access Denied</body></html>",
            {"Content-Type": "text/html"},
        )
        classes = (
            ApacheAxis,
            ApplicationYaml,
            YawsKey,
            GenericDatabase,
            LaravelKeys,
            Makefile,
            RubyGems,
            StemKey,
            WordpressGit,
            GenericXss,
        )
        for module_class in classes:
            with self.subTest(module=module_class.__module__):
                self.assertFalse(bare_module(module_class, response).run())

    def test_iis_shortname_requires_iis_and_repeatable_differential(self):
        from modules.scanner.http.iis_shortname_detect import Module

        instance = bare_module(Module, None)

        def generic_router(**kwargs):
            path = kwargs["path"]
            status = 200 if path.startswith("/*") else 404
            return FakeResponse(status, "", {"Server": "nginx"})

        instance.http_request = generic_router
        self.assertFalse(instance.run())

        def vulnerable_iis(**kwargs):
            path = kwargs["path"]
            status = 404 if path.startswith("/*") else 400
            return FakeResponse(status, "", {"Server": "Microsoft-IIS/10.0"})

        instance.http_request = vulnerable_iis
        self.assertTrue(instance.run())


class PatchedVersionGuardTests(unittest.TestCase):
    def test_patched_nextjs_is_negative(self):
        import modules.scanner.http.nextjs_cve_2026_44578_websocket_upgrade_ssrf_detect as mod

        instance = bare_module(mod.Module, FakeResponse(200, "nextjs"))
        instance.active_probe = False
        with patch.object(mod, "probe_nextjs_stack", return_value=(True, "")), patch.object(
            mod, "extract_nextjs_version", return_value="16.2.5"
        ):
            self.assertFalse(instance.run())

    def test_patched_langflow_is_negative(self):
        from modules.scanner.http.langflow_cve_2026_5027 import Module

        instance = bare_module(Module, FakeResponse())
        instance._fingerprint = lambda: (True, "1.9.0")
        instance._get_token = lambda: ("token", "test")
        instance.active_probe = False
        self.assertFalse(instance.run())

    def test_patched_wordpress_plugins_are_negative(self):
        from modules.scanner.http.wp_plugin_divi_form_builder_cve_2026_5118 import (
            Module as Divi,
        )
        from modules.scanner.http.wp_plugin_kirki_cve_2026_8206 import Module as Kirki

        divi = bare_module(Divi, None)
        divi.wp_plugin_version = lambda *_args: "5.1.3"
        divi.wp_version_to_tuple = lambda value: tuple(int(x) for x in value.split("."))
        divi._base = lambda: ""
        divi.probe_paths = ""
        self.assertFalse(divi.run())

        kirki = bare_module(Kirki, None)
        kirki.wp_plugin_version = lambda *_args: "6.0.7"
        kirki._base = lambda: ""
        kirki._route_exposed = lambda: False
        kirki.probe_paths = "/"
        self.assertFalse(kirki.run())

    def test_fixed_superset_is_negative(self):
        from modules.scanner.http.superset_cve_2026_23980 import Module

        instance = bare_module(Module, FakeResponse())
        instance._looks_like_superset = lambda: True
        instance._get_version = lambda: "6.0.0"
        instance.active_probe = False
        instance.anonymous = False
        instance.username = ""
        instance.password = ""
        self.assertFalse(instance.run())

    def test_non_cisco_telnet_banner_is_negative(self):
        import modules.scanner.tcp.cisco_cmp_cve_2017_3881 as mod

        instance = object.__new__(mod.Module)
        instance._host = lambda: "127.0.0.1"
        instance._port = lambda: 23
        instance._timeout = lambda: 1
        instance.is_tcp_open = lambda **_kwargs: True
        instance.set_info = lambda **kwargs: setattr(instance, "vulnerability_info", kwargs)
        probe = {"detected": True, "cisco_likely": False, "banner": "Generic Telnet"}
        with patch.object(mod, "_probe_cisco_telnet", return_value=probe):
            self.assertFalse(instance.run())


if __name__ == "__main__":
    unittest.main()
