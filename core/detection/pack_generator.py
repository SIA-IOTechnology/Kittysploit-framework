#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate blue-team detection packs from offensive KittySploit modules."""

import hashlib
import inspect
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import unquote

from core.detection.post_telemetry import enrich_edr_hypotheses, enrich_expected_logs


@dataclass
class GeneratedPack:
    """Result returned by the detection pack generator."""

    output_dir: Path
    files: List[Path]
    manifest: Dict[str, Any]


class DetectionPackGenerator:
    """Build Sigma, YARA, Suricata, Zeek and validation assets for a module."""

    DEFAULT_OUTPUT_DIR = Path("artifacts") / "detection_packs"

    def __init__(self, module: Any, module_path: Optional[str] = None):
        self.module = module
        self.module_path = module_path or self._module_path_from_instance(module)
        self.info = self._module_info(module)
        self.source = self._module_source(module)
        self.slug = self._slugify(self.module_path or self.info.get("name") or module.__class__.__name__)
        self.rule_name = self._rule_name(self.info.get("name") or self.slug)
        self.indicators = self._extract_indicators()

    def generate(
        self,
        output_dir: str = None,
        force: bool = False,
        formats: Optional[Iterable[str]] = None,
    ) -> GeneratedPack:

        selected_formats = set(formats or ["sigma", "yara", "suricata", "zeek", "docs", "tests"])
        root = Path(output_dir or self.DEFAULT_OUTPUT_DIR) / self.slug
        if root.exists() and any(root.iterdir()) and not force:
            raise FileExistsError(f"Detection pack already exists: {root}. Use --force to overwrite.")

        root.mkdir(parents=True, exist_ok=True)
        generated: List[Path] = []

        manifest = self._manifest()
        generated.append(self._write_json(root / "manifest.json", manifest))

        if "docs" in selected_formats:
            generated.append(self._write_text(root / "README.md", self.render_readme(manifest)))
            generated.append(self._write_text(root / "edr_hypotheses.md", self.render_edr_hypotheses()))
            generated.append(self._write_json(root / "expected_logs.json", self.expected_logs()))

        if "sigma" in selected_formats:
            generated.append(self._write_text(root / "sigma" / f"{self.slug}.yml", self.render_sigma()))

        if "yara" in selected_formats:
            generated.append(self._write_text(root / "yara" / f"{self.slug}.yar", self.render_yara()))

        if "suricata" in selected_formats:
            generated.append(self._write_text(root / "suricata" / f"{self.slug}.rules", self.render_suricata()))

        if "zeek" in selected_formats:
            generated.append(self._write_text(root / "zeek" / f"{self.slug}.zeek", self.render_zeek()))

        if "tests" in selected_formats:
            generated.append(self._write_json(root / "tests" / "fixtures.json", self.test_fixtures()))
            generated.append(self._write_text(root / "tests" / f"test_{self.slug}.py", self.render_tests()))

        return GeneratedPack(output_dir=root, files=generated, manifest=manifest)

    def preview(self) -> str:

        cves = ", ".join(self._as_list(self.info.get("cve"))) or "none"
        tags = ", ".join(self._as_list(self.info.get("tags"))) or "none"
        lines = [
            f"Module: {self.info.get('name') or self.module_path}",
            f"Path: {self.module_path}",
            f"Type: {self.info.get('type', 'module')}",
            f"CVE: {cves}",
            f"Tags: {tags}",
            f"Indicators: {', '.join(self.indicators[:12]) if self.indicators else 'generic module metadata only'}",
            "Outputs: Sigma, YARA, Suricata, Zeek, EDR hypotheses, expected logs, tests",
        ]
        return "\n".join(lines)

    def render_readme(self, manifest: Dict[str, Any]) -> str:
        title = self.info.get("name") or self.slug
        description = self.info.get("description") or "Detection pack generated from KittySploit module metadata."
        references = "\n".join(f"- {ref}" for ref in self._as_list(self.info.get("references"))) or "- None provided"
        indicators = "\n".join(f"- `{indicator}`" for indicator in self.indicators) or "- No strong indicators extracted"
        return f"""# Detection Pack: {title}

Generated from KittySploit module `{self.module_path}`.

## Purpose

{description}

## Contents

- `sigma/`: SIEM correlation rule for expected log fields.
- `yara/`: artifact/string rule for payload or exploit residue hunting.
- `suricata/`: HTTP/network IDS signature.
- `zeek/`: Zeek notice script for HTTP telemetry.
- `edr_hypotheses.md`: host telemetry hypotheses for EDR validation.
- `expected_logs.json`: expected logs and sample events.
- `tests/`: stdlib tests that verify pack consistency and fixture matching.

## Extracted Indicators

{indicators}

## References

{references}

## Manifest

- Pack ID: `{manifest["pack_id"]}`
- Confidence: `{manifest["confidence"]}`
- Created UTC: `{manifest["created_utc"]}`
"""

    def render_edr_hypotheses(self) -> str:
        title = self.info.get("name") or self.slug
        tags = set(tag.lower() for tag in self._as_list(self.info.get("tags")))
        platform = str(self.info.get("platform") or "").lower()
        lines = [
            f"# EDR Hypotheses: {title}",
            "",
            "## Primary Hypotheses",
            "",
            "- The offensive module should create a detectable control-plane event near the target service.",
            "- Network telemetry should contain at least one generated indicator before successful impact.",
            "- Host telemetry should show the vulnerable service spawning or loading an unusual child process, script interpreter, or module.",
        ]
        if "powershell" in tags or "windows" in platform:
            lines.extend([
                "- Windows EDR should capture process creation event 4688 and PowerShell script block event 4104 if script execution occurs.",
                "- Investigate parent-child chains where web, service, or management processes launch `powershell.exe`, `cmd.exe`, `wscript.exe`, or `rundll32.exe`.",
            ])
        if "php" in tags or "web" in tags or "http" in self.module_path:
            lines.extend([
                "- Web server access logs should preserve suspicious query parameters and request body handling anomalies.",
                "- EDR should flag web server processes launching shell interpreters or reading pseudo streams such as `php://input`.",
            ])
        if "linux" in platform or "/linux/" in self.module_path or "unix" in tags:
            lines.extend([
                "- Linux telemetry should include `execve`, auditd, or eBPF events for shell/interpreter launches by service users.",
                "- Review writes to temporary directories and unexpected outbound connections from service accounts.",
            ])
        lines.extend([
            "",
            "## Validation Notes",
            "",
            "- Tune field names to the target SIEM schema before production deployment.",
            "- Treat generated rules as a starting point: test with authorized replay traffic and known-benign service activity.",
            "- Record false positives and promote stable indicators into organization-specific detections.",
        ])
        return "\n".join(enrich_edr_hypotheses(lines, self.module_path)) + "\n"

    def render_sigma(self) -> str:
        title = self.info.get("name") or self.slug
        level = self._severity_to_sigma_level(self.info.get("severity"))
        selection = self._sigma_selection()
        detection_lines = []
        for name, values in selection.items():
            detection_lines.append(f"    {name}:")
            for field, field_values in values.items():
                detection_lines.append(f"        {field}:")
                for value in field_values:
                    detection_lines.append(f"            - {self._yaml_quote(value)}")

        references = "\n".join(f"    - {self._yaml_quote(ref)}" for ref in self._as_list(self.info.get("references")))
        tags = self._sigma_tags()
        tag_lines = "\n".join(f"    - {self._yaml_quote(tag)}" for tag in tags)
        return f"""title: {self._yaml_quote(title)}
id: {uuid.uuid5(uuid.NAMESPACE_URL, "kittysploit:detection:" + self.slug)}
status: experimental
description: {self._yaml_quote(self.info.get("description") or "Generated from KittySploit module metadata.")}
author: KittySploit Detection Pack Generator
date: {date.today().isoformat()}
references:
{references or "    - https://kittysploit.com"}
tags:
{tag_lines or "    - attack.initial-access"}
logsource:
{self._sigma_logsource()}
detection:
{chr(10).join(detection_lines)}
    condition: 1 of selection_*
falsepositives:
    - Authorized security testing
    - Vulnerability scanners replaying proof-of-concept probes
level: {level}
"""

    def render_yara(self) -> str:
        title = self.info.get("name") or self.slug
        strings = self._yara_strings()
        string_lines = []
        for idx, value in enumerate(strings, start=1):
            string_lines.append(f'        $s{idx} = "{self._escape_yara(value)}" ascii wide nocase')
        condition = "2 of them" if len(strings) >= 3 else "any of them"
        return f"""rule KITTYSPLOIT_{self.rule_name}
{{
    meta:
        description = "{self._escape_yara(title)}"
        module_path = "{self._escape_yara(self.module_path)}"
        cve = "{self._escape_yara(','.join(self._as_list(self.info.get('cve'))))}"
        generated_by = "KittySploit Detection Pack Generator"
        generated_utc = "{self._escape_yara(datetime.now(timezone.utc).isoformat())}"
    strings:
{chr(10).join(string_lines)}
    condition:
        {condition}
}}
"""

    def render_suricata(self) -> str:
        title = self.info.get("name") or self.slug
        sid = self._suricata_sid()
        contents = []
        for indicator in self._network_indicators()[:6]:
            contents.append(f'content:"{self._escape_suricata(indicator)}"; nocase;')
        if not contents:
            contents.append(f'content:"{self._escape_suricata(self.slug.replace("_", "-"))}"; nocase;')
        metadata = []
        for cve in self._as_list(self.info.get("cve")):
            metadata.append(f"cve {cve}")
        metadata.append(f"module {self.module_path}")
        return (
            f'alert http any any -> any any (msg:"KITTYSPLOIT detection {self._escape_suricata(title)}"; '
            f'flow:to_server,established; http.uri; {" ".join(contents)} '
            f'classtype:web-application-attack; sid:{sid}; rev:1; metadata:{", ".join(metadata)};)\n'
        )

    def render_zeek(self) -> str:
        title = self.info.get("name") or self.slug
        indicators = self._network_indicators()[:12] or [self.slug.replace("_", "-")]
        escaped = ", ".join(f'"{self._escape_zeek(item)}"' for item in indicators)
        notice_type = f"KittySploit_{self.rule_name}"
        return f"""@load base/protocols/http
@load base/frameworks/notice

module KittySploit;

export {{
    redef enum Notice::Type += {{
        {notice_type},
    }};
}}

const indicators: set[string] = {{{escaped}}} &redef;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {{
    local uri = to_lower(original_URI);
    for (indicator in indicators)
        {{
        if ( indicator != "" && indicator in uri )
            {{
            NOTICE([$note={notice_type},
                    $conn=c,
                    $msg=fmt("KittySploit detection for {self._escape_zeek(title)}: %s", indicator),
                    $identifier=cat(c$id$orig_h, "-", c$id$resp_h, "-", indicator)]);
            break;
            }}
        }}
    }}
"""

    def expected_logs(self) -> Dict[str, Any]:
        sample_uri = "/" + (self._network_indicators()[0] if self._network_indicators() else self.slug)
        base = {
            "schema_version": "1.0",
            "module": self.module_path,
            "expected_sources": [
                "webserver.access",
                "ids.http",
                "edr.process",
                "edr.script",
            ],
            "sample_events": [
                {
                    "source": "webserver.access",
                    "http": {
                        "request": {
                            "method": "POST",
                            "uri": sample_uri,
                            "body_bytes": 128,
                        },
                        "response": {"status_code": 200},
                    },
                    "event": {"action": "authorized-test-probe"},
                    "rule": {"name": self.info.get("name") or self.slug},
                },
                {
                    "source": "edr.process",
                    "process": {
                        "parent": {"name": self._expected_parent_process()},
                        "name": self._expected_child_process(),
                        "command_line": "generated detection hypothesis, tune to environment",
                    },
                    "event": {"action": "process-start"},
                },
            ],
            "indicators": self.indicators,
        }
        return enrich_expected_logs(base, self.module_path)

    def test_fixtures(self) -> Dict[str, Any]:
        return {
            "positive_uri": "/" + "&".join(self._network_indicators()[:3]),
            "negative_uri": "/index.html?healthcheck=true",
            "positive_artifact": " ".join(self._yara_strings()[:3]),
            "indicators": self.indicators,
        }

    def render_tests(self) -> str:
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import pathlib
import unittest


PACK_ROOT = pathlib.Path(__file__).resolve().parents[1]


class DetectionPackTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = json.loads((PACK_ROOT / "tests" / "fixtures.json").read_text(encoding="utf-8"))
        self.manifest = json.loads((PACK_ROOT / "manifest.json").read_text(encoding="utf-8"))

    def test_manifest_has_required_sections(self):
        for key in ("pack_id", "module", "outputs", "indicators"):
            self.assertIn(key, self.manifest)

    def test_network_fixture_matches_generated_rules(self):
        uri = self.fixtures["positive_uri"].lower()
        rule_text = (PACK_ROOT / "suricata" / "{self.slug}.rules").read_text(encoding="utf-8").lower()
        zeek_text = (PACK_ROOT / "zeek" / "{self.slug}.zeek").read_text(encoding="utf-8").lower()
        self.assertTrue(any(indicator.lower() in uri for indicator in self.fixtures["indicators"]))
        self.assertTrue(any(indicator.lower() in rule_text for indicator in self.fixtures["indicators"]))
        self.assertTrue(any(indicator.lower() in zeek_text for indicator in self.fixtures["indicators"]))

    def test_artifact_fixture_matches_yara_strings(self):
        artifact = self.fixtures["positive_artifact"].lower()
        yara_text = (PACK_ROOT / "yara" / "{self.slug}.yar").read_text(encoding="utf-8").lower()
        self.assertTrue(any(indicator.lower() in artifact for indicator in self.fixtures["indicators"]))
        self.assertTrue(any(indicator.lower() in yara_text for indicator in self.fixtures["indicators"]))


if __name__ == "__main__":
    unittest.main()
'''

    def _manifest(self) -> Dict[str, Any]:
        outputs = {
            "sigma": f"sigma/{self.slug}.yml",
            "yara": f"yara/{self.slug}.yar",
            "suricata": f"suricata/{self.slug}.rules",
            "zeek": f"zeek/{self.slug}.zeek",
            "edr_hypotheses": "edr_hypotheses.md",
            "expected_logs": "expected_logs.json",
            "tests": f"tests/test_{self.slug}.py",
        }
        return {
            "schema_version": "1.0",
            "pack_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "kittysploit:detection:" + self.slug)),
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "module": {
                "path": self.module_path,
                "name": self.info.get("name"),
                "type": self.info.get("type"),
                "description": self.info.get("description"),
                "cve": self._as_list(self.info.get("cve")),
                "tags": self._as_list(self.info.get("tags")),
                "references": self._as_list(self.info.get("references")),
            },
            "confidence": self._confidence(),
            "indicators": self.indicators,
            "outputs": outputs,
        }

    def _extract_indicators(self) -> List[str]:
        indicators: List[str] = []

        patterns = [
            r"CVE-\d{4}-\d{4,7}",
            r"[A-Za-z0-9_./:%?=&+\-]{5,}",
            r"/[A-Za-z0-9_./%?=&+\-]{2,}",
        ]
        for pattern in patterns:
            for value in re.findall(pattern, self.source):
                cleaned = value.strip("'\"`(),[]{}")
                if self._looks_like_reference_url(cleaned):
                    continue
                if self._is_useful_indicator(cleaned):
                    indicators.append(cleaned)
                    decoded = unquote(cleaned, errors="ignore")
                    if decoded != cleaned and self._is_useful_indicator(decoded):
                        indicators.append(decoded)
                    indicators.extend(self._split_indicator(cleaned))
                    indicators.extend(self._split_indicator(decoded))

        indicators.extend(self._as_list(self.info.get("cve")))
        indicators.extend(self._interesting_tokens(self.info.get("description", "")))
        indicators.extend(self._interesting_tokens(self.info.get("name", "")))
        indicators.extend(self._as_list(self.info.get("tags")))

        options = getattr(self.module, "get_options", lambda: {})() or {}
        for name, option_data in options.items():
            indicators.append(str(name))
            if option_data:
                indicators.append(str(option_data[0]))
                if len(option_data) > 2:
                    indicators.extend(self._interesting_tokens(str(option_data[2])))

        ranked = self._rank_indicators([item for item in indicators if self._is_useful_indicator(item)])
        return ranked[:24]

    def _interesting_tokens(self, value: str) -> List[str]:
        words = re.findall(r"[A-Za-z0-9][A-Za-z0-9_.:/%+\-]{3,}", str(value))
        boring = {"this", "that", "with", "from", "using", "module", "target", "detects", "execute"}
        return [word for word in words if word.lower() not in boring]

    def _is_useful_indicator(self, value: str) -> bool:
        if not value or len(value) < 3:
            return False
        if any(ord(char) > 127 for char in value):
            return False
        if value.startswith("Mozilla/"):
            return False
        lowered = value.lower()
        boring = {
            "self", "true", "false", "none", "return", "str", "int", "bool", "timeout",
            "required", "advanced", "description", "author", "references", "payload",
        }
        if lowered in boring:
            return False
        if lowered.startswith("http") and "://" not in lowered:
            return False
        if value.isdigit() and len(value) < 4:
            return False
        return True

    def _looks_like_reference_url(self, value: str) -> bool:
        lowered = str(value).lower()
        return lowered.startswith(("http://", "https://", "//")) and "." in lowered

    def _split_indicator(self, value: str) -> List[str]:
        parts = re.split(r"[/?&+\s]+", str(value))
        expanded = []
        for part in parts:
            part = part.strip("'\"`(),[]{}")
            if not part:
                continue
            expanded.append(part)
            if "=" in part:
                expanded.extend(piece for piece in part.split("=") if piece)
        return [part for part in expanded if self._is_useful_indicator(part)]

    def _rank_indicators(self, values: Iterable[str]) -> List[str]:
        deduped = self._dedupe(values)
        return sorted(deduped, key=self._indicator_score, reverse=True)

    def _indicator_score(self, value: str) -> int:
        lowered = str(value).lower()
        score = min(len(value), 80)
        if re.search(r"cve-\d{4}-\d{4,7}", lowered):
            score += 100
        if any(token in value for token in ("=", "%", "://", "?", "&", "/", "\\")):
            score += 50
        if any(token in lowered for token in ("auto_prepend", "allow_url_include", "php://input", "powershell", "cmd.exe")):
            score += 60
        if lowered in {"php", "cgi", "rce", "execute", "argument", "injection", "marker", "target"}:
            score -= 80
        if lowered.startswith(("http://", "https://", "//")) and "." in lowered:
            score -= 160
        return score

    def _sigma_selection(self) -> Dict[str, Dict[str, List[str]]]:
        from core.detection.post_telemetry import get_post_telemetry

        profile = get_post_telemetry(self.module_path)
        if profile and profile.get("sigma_hints"):
            return {
                "selection_post_telemetry": {
                    "CommandLine|contains": list(profile["sigma_hints"][:8]),
                }
            }

        network = self._network_indicators()
        artifact = self._artifact_indicators()
        selections = {}
        if network:
            selections["selection_web"] = {
                "cs-uri-query|contains": network[:8],
                "url.query|contains": network[:8],
            }
        if artifact:
            selections["selection_process"] = {
                "process.command_line|contains": artifact[:8],
            }
        if not selections:
            selections["selection_metadata"] = {"message|contains": [self.slug.replace("_", "-")]}
        return selections

    def _sigma_logsource(self) -> str:
        tags = set(tag.lower() for tag in self._as_list(self.info.get("tags")))
        if "windows" in str(self.info.get("platform", "")).lower() or "powershell" in tags:
            return "    product: windows\n    category: process_creation"
        if "http" in self.module_path or "web" in tags or "php" in tags:
            return "    category: webserver"
        return "    category: application"

    def _sigma_tags(self) -> List[str]:
        tags = ["attack.initial-access"]
        lowered = " ".join(self._as_list(self.info.get("tags"))).lower() + " " + self.module_path.lower()
        if "rce" in lowered or "command" in lowered:
            tags.append("attack.t1203")
            tags.append("attack.t1059")
        if "persistence" in lowered:
            tags.append("attack.persistence")
        if self.info.get("cve"):
            tags.extend(cve.lower() for cve in self._as_list(self.info.get("cve")))
        return self._dedupe(tags)

    def _yara_strings(self) -> List[str]:
        values = self._artifact_indicators()
        values.extend(self._network_indicators())
        values.extend([self.slug.replace("_", "-"), self.info.get("name", "")])
        return self._dedupe([value for value in values if self._is_useful_indicator(value)])[:12] or [self.slug]

    def _network_indicators(self) -> List[str]:
        likely = []
        for indicator in self.indicators:
            lowered = indicator.lower()
            if any(token in lowered for token in ["/", "?", "=", "%", "php://", "cmd", "payload", "auto_prepend", "allow_url"]):
                likely.append(indicator)
        if not likely:
            likely = [item for item in self.indicators if len(item) >= 8 and item.lower() not in {"argument", "injection"}]
        return self._rank_indicators(likely)

    def _artifact_indicators(self) -> List[str]:
        likely = []
        for indicator in self.indicators:
            lowered = indicator.lower()
            if any(token in lowered for token in ["powershell", "cmd", "bash", "python", "php", "shell", "exe", ".dll", "payload"]):
                likely.append(indicator)
        if not likely:
            likely = self.indicators[:8]
        return self._dedupe(likely)

    def _expected_parent_process(self) -> str:
        text = (self.module_path + " " + " ".join(self._as_list(self.info.get("tags")))).lower()
        if "http" in text or "web" in text or "php" in text:
            return "apache2/nginx/php-cgi"
        if "ssh" in text:
            return "sshd"
        return "target-service"

    def _expected_child_process(self) -> str:
        text = " ".join(self.indicators).lower()
        if "powershell" in text:
            return "powershell.exe"
        if "php" in text:
            return "php"
        if "python" in text:
            return "python"
        return "shell/interpreter"

    def _module_info(self, module: Any) -> Dict[str, Any]:
        info = dict(getattr(module.__class__, "__info__", {}) or {})
        for key in ("name", "description", "author", "references", "cve", "tags"):
            if key not in info and hasattr(module, key):
                info[key] = getattr(module, key)
        info["type"] = getattr(module, "type", getattr(module.__class__, "TYPE_MODULE", "module"))
        if "platform" in info:
            info["platform"] = self._stringify(info["platform"])
        return self._jsonable(info)

    def _module_source(self, module: Any) -> str:
        try:
            return inspect.getsource(module.__class__)
        except Exception:
            try:
                module_file = inspect.getfile(module.__class__)
                return Path(module_file).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return ""

    def _module_path_from_instance(self, module: Any) -> str:
        module_name = getattr(module.__class__, "__module__", "")
        if module_name.startswith("modules."):
            return module_name[len("modules."):].replace(".", "/")
        return module_name.replace(".", "/") or module.__class__.__name__

    def _confidence(self) -> str:
        if len(self.indicators) >= 8 and self.info.get("cve"):
            return "high"
        if len(self.indicators) >= 4:
            return "medium"
        return "low"

    def _suricata_sid(self) -> int:
        digest = hashlib.sha1(self.slug.encode("utf-8")).hexdigest()
        return 9000000 + (int(digest[:6], 16) % 900000)

    def _write_text(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _write_json(self, path: Path, data: Dict[str, Any]) -> Path:
        return self._write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")

    def _as_list(self, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return [self._stringify(item) for item in value if item not in (None, "")]
        return [self._stringify(value)] if value != "" else []

    def _jsonable(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {str(key): self._jsonable(value) for key, value in data.items()}
        if isinstance(data, (list, tuple, set)):
            return [self._jsonable(value) for value in data]
        return self._stringify(data) if not isinstance(data, (str, int, float, bool, type(None))) else data

    def _stringify(self, value: Any) -> str:
        if hasattr(value, "value"):
            return str(value.value)
        if hasattr(value, "name"):
            return str(value.name).lower()
        return str(value)

    def _dedupe(self, values: Iterable[str]) -> List[str]:
        seen = set()
        result = []
        for value in values:
            normalized = str(value).strip()
            key = normalized.lower()
            if normalized and key not in seen:
                seen.add(key)
                result.append(normalized)
        return result

    def _slugify(self, value: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
        return slug[:96] or "detection_pack"

    def _rule_name(self, value: str) -> str:
        name = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
        if not name or name[0].isdigit():
            name = "MODULE_" + name
        return name[:80]

    def _yaml_quote(self, value: Any) -> str:
        text = str(value).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{text}"'

    def _escape_yara(self, value: str) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    def _escape_suricata(self, value: str) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;")

    def _escape_zeek(self, value: str) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    def _severity_to_sigma_level(self, severity: Any) -> str:
        value = str(severity or "").lower()
        if value in ("critical", "high", "medium", "low"):
            return value
        if self.info.get("cve"):
            return "high"
        return "medium"
