#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path

from core.framework.base_module import BaseModule
from core.framework.option.base_option import Option
from interfaces.mcp_kittysploit_bridge import NaturalLanguagePlanner


class FakeWordPressScanner(BaseModule):
    __info__ = {
        "name": "WordPress Detector",
        "description": "Detect WordPress websites and exposed components",
        "author": "Test",
        "tags": ["wordpress", "http", "cms"],
        "references": [],
    }

    TARGET = Option("", "Target URL", required=True)
    SSL = Option(False, "Use HTTPS")

    def run(self):
        return True


class FakeSMBScanner(BaseModule):
    __info__ = {
        "name": "SMBv1 Detector",
        "description": "Detect legacy SMB services",
        "author": "Test",
        "tags": ["smb", "network"],
        "references": [],
    }

    RHOST = Option("", "Target host", required=True)
    RPORT = Option(445, "Target port")

    def run(self):
        return True


class FakeModuleLoader:
    def __init__(self, root: Path):
        self._module_paths = {
            "scanner/http/wordpress_detect": root / "scanner/http/wordpress_detect.py",
            "scanner/smb/smbv1_detect": root / "scanner/smb/smbv1_detect.py",
        }
        self._runtime_map = {
            "scanner/http/wordpress_detect": FakeWordPressScanner,
            "scanner/smb/smbv1_detect": FakeSMBScanner,
        }

    def discover_modules(self):
        return {path: str(file_path) for path, file_path in self._module_paths.items()}

    def load_module(self, module_path, framework=None):
        module_class = self._runtime_map.get(module_path)
        return module_class(framework=framework) if module_class else None


class FakeFramework:
    def __init__(self, root: Path):
        self.module_loader = FakeModuleLoader(root)
        self.session_manager = type("SessionManager", (), {"sessions": {}, "browser_sessions": {}})()
        self.current_module = None
        self.current_workspace = "default"

    def get_current_workspace(self):
        return self.current_workspace


def _write_module(path: Path, info: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(info, encoding="utf-8")


def _build_planner(tmp_path: Path) -> NaturalLanguagePlanner:
    _write_module(
        tmp_path / "scanner/http/wordpress_detect.py",
        """__info__ = {
    "name": "WordPress Detector",
    "description": "Detect WordPress websites and exposed components",
    "author": "Test",
    "tags": ["wordpress", "http", "cms"],
}
""",
    )
    _write_module(
        tmp_path / "scanner/smb/smbv1_detect.py",
        """__info__ = {
    "name": "SMBv1 Detector",
    "description": "Detect legacy SMB services",
    "author": "Test",
    "tags": ["smb", "network"],
}
""",
    )
    return NaturalLanguagePlanner(FakeFramework(tmp_path))


def test_parse_request_extracts_target_keywords_and_profile(tmp_path):
    planner = _build_planner(tmp_path)

    parsed = planner.parse_request("scan wordpress quietly against https://blog.example.com")

    assert parsed.intent == "search_module"
    assert parsed.operation_profile == "discreet"
    assert parsed.target["normalized"] == "https://blog.example.com"
    assert parsed.target["scheme"] == "https"
    assert "wordpress" in parsed.keywords
    assert "web" in parsed.keywords


def test_search_modules_prefers_matching_wordpress_module(tmp_path):
    planner = _build_planner(tmp_path)

    result = planner.search_modules("scan wordpress on https://blog.example.com")

    assert result["count"] >= 1
    assert result["modules"][0]["path"] == "scanner/http/wordpress_detect"


def test_get_module_details_infers_target_option_hints(tmp_path):
    planner = _build_planner(tmp_path)

    details = planner.get_module_details(
        "scanner/http/wordpress_detect",
        request="run a wordpress scan against https://blog.example.com",
    )

    assert "TARGET" in details["required_options"]
    assert details["option_hints"]["TARGET"] == "https://blog.example.com"
    assert details["option_hints"]["SSL"] == "true"


def test_plan_request_suggests_use_and_run_sequence(tmp_path):
    planner = _build_planner(tmp_path)

    plan = planner.plan_request("run a discreet wordpress scan against https://blog.example.com")
    commands = [item["command"] for item in plan["recommended_commands"]]

    assert any(command.startswith("search ") for command in commands)
    assert "use scanner/http/wordpress_detect" in commands
    assert "show options" in commands
    assert "run" in commands


def test_ollama_search_assist_can_bias_module_search(tmp_path):
    class DummyLLM:
        last_error = None

        def query_json(self, endpoint, model, instruction, payload, timeout=20):
            if "search-query assistant" in instruction:
                return {
                    "search_terms": ["wordpress", "cms"],
                    "boost_terms": ["http"],
                    "module_types": ["scanner"],
                    "rewritten_request": "scan wordpress cms over http",
                    "rationale": "WordPress web scan requested.",
                    "reasoning_confidence": 0.95,
                }
            return {
                "rationale": "Use the WordPress detector workflow.",
                "selected_paths": ["scanner/http/wordpress_detect"],
                "command_sequence": [
                    {"command": "use scanner/http/wordpress_detect", "reason": "Select best module"}
                ],
            }

    planner = NaturalLanguagePlanner(
        FakeFramework(tmp_path),
        llm_service=DummyLLM(),
        ollama_enabled=True,
    )
    _write_module(
        tmp_path / "scanner/http/wordpress_detect.py",
        """__info__ = {
    "name": "WordPress Detector",
    "description": "Detect WordPress websites and exposed components",
    "author": "Test",
    "tags": ["wordpress", "http", "cms"],
}
""",
    )
    _write_module(
        tmp_path / "scanner/smb/smbv1_detect.py",
        """__info__ = {
    "name": "SMBv1 Detector",
    "description": "Detect legacy SMB services",
    "author": "Test",
    "tags": ["smb", "network"],
}
""",
    )

    plan = planner.plan_request("scan the target", prefer_ollama=True)

    assert plan["ollama_search_assist"]["rewritten_request"] == "scan wordpress cms over http"
    assert plan["recommended_modules"][0]["path"] == "scanner/http/wordpress_detect"


def test_framework_info_request_does_not_return_modules(tmp_path):
    planner = _build_planner(tmp_path)

    plan = planner.plan_request("Explique moi kittysploit framework", prefer_ollama=False)

    assert plan["parsed_request"]["intent"] == "framework_info"
    assert plan["recommended_modules"] == []
    assert plan["recommended_commands"] == []
    assert "KittySploit" in plan["framework_overview"]["title"]
