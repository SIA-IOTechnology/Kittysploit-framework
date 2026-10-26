"""Build Vulners feed bulletins from KittySploit module sources."""

from __future__ import annotations

import ast
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set

from core.utils.module_static_metadata import CVE_RE, parse_static_module_info
from core.utils.paths import require_framework_root

GITHUB_MODULE_HREF_BASE = (
    "https://github.com/SIA-IOTechnology/Kittysploit-framework/blob/main/modules/"
)

_ATTCK_SUBTECH = re.compile(
    r"(https?://attack\.mitre\.org/techniques/T\d+)\.(\d+)(/?)",
    re.I,
)
_URL_RE = re.compile(r"^https?://", re.I)
_CVE_TOKEN = re.compile(r"CVE-\d{4}-\d+", re.I)
def module_path_to_vulners_id(module_path: str) -> str:
    """KS:EXPLOITS-LINUX-HTTP-MODULE_NAME from exploits/linux/http/module.py."""
    path = str(module_path or "").replace("\\", "/").strip().strip("/")
    if path.endswith(".py"):
        path = path[:-3]
    slug = path.upper().replace("/", "-")
    return f"KS:{slug}"


def module_href(module_path: str) -> str:
    rel = str(module_path or "").replace("\\", "/").lstrip("/")
    if not rel.endswith(".py"):
        rel = f"{rel}.py"
    return f"{GITHUB_MODULE_HREF_BASE}{rel}"


def fix_mitre_attack_url(url: str) -> str:
    return _ATTCK_SUBTECH.sub(r"\1/\2\3", url)


def _string_from_ast(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _references_from_info_dict(info: dict) -> List[Any]:
    refs = info.get("references") or []
    if isinstance(refs, str):
        return [refs]
    if isinstance(refs, (list, tuple)):
        return list(refs)
    return []


def _references_from_ast_node(node: ast.AST) -> List[Any]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple)):
        out: List[Any] = []
        for element in node.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                out.append(element.value)
            elif isinstance(element, (ast.List, ast.Tuple)):
                pair = [_string_from_ast(item) for item in element.elts]
                if len(pair) >= 2 and pair[0] is not None and pair[1] is not None:
                    out.append([pair[0], pair[1]])
        return out
    return []


def _find_info_dict_node(tree: ast.Module) -> Optional[ast.Dict]:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__info__":
                    if isinstance(node.value, ast.Dict):
                        return node.value
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "Module":
            continue
        for item in node.body:
            if not isinstance(item, ast.Assign):
                continue
            for target in item.targets:
                if isinstance(target, ast.Name) and target.id == "__info__":
                    if isinstance(item.value, ast.Dict):
                        return item.value
    return None


def _extract_references_from_ast(file_path: str) -> List[Any]:
    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=file_path)
    except OSError:
        return []
    except SyntaxError:
        return []

    info_node = _find_info_dict_node(tree)
    if info_node is None:
        return []
    for key_node, value_node in zip(info_node.keys, info_node.values):
        key = _string_from_ast(key_node) if key_node is not None else None
        if key == "references":
            return _references_from_ast_node(value_node)
    try:
        ev = ast.literal_eval(info_node)
    except (ValueError, SyntaxError):
        return []
    if isinstance(ev, dict):
        return _references_from_info_dict(ev)
    return []


def _parse_stringified_reference(value: str) -> Optional[str]:
    text = value.strip()
    if not text:
        return None
    if _URL_RE.match(text):
        return fix_mitre_attack_url(text)
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = ast.literal_eval(text)
        except (ValueError, SyntaxError):
            parsed = None
        if isinstance(parsed, (list, tuple)):
            return _coerce_reference_entry(parsed)
    return None


def _coerce_reference_entry(entry: Any) -> Optional[str]:
    if isinstance(entry, str):
        return _parse_stringified_reference(entry)
    if isinstance(entry, (list, tuple)) and len(entry) >= 2:
        label = str(entry[0] or "").strip()
        url = str(entry[1] or "").strip()
        if _URL_RE.match(url):
            return fix_mitre_attack_url(url)
        if _URL_RE.match(label):
            return fix_mitre_attack_url(label)
        return None
    return None


def normalize_feed_references(raw_refs: List[Any]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for entry in raw_refs:
        url: Optional[str] = None
        if isinstance(entry, str):
            url = _parse_stringified_reference(entry)
        else:
            url = _coerce_reference_entry(entry)
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(url)
    return out


def cvelist_from_metadata(info: Dict[str, Any], raw_refs: List[Any]) -> List[str]:
    found: Set[str] = set()
    cve_field = info.get("cve") or ""
    if isinstance(cve_field, (list, tuple, set)):
        parts = cve_field
    else:
        parts = re.split(r"[\s,;]+", str(cve_field))
    for part in parts:
        token = str(part).strip().upper()
        if token and CVE_RE.match(token):
            found.add(token)

    for entry in raw_refs:
        blob = entry if isinstance(entry, str) else str(entry)
        for match in _CVE_TOKEN.finditer(blob):
            found.add(match.group(0).upper())
    return sorted(found)


def _git_committer_iso(file_path: Path) -> Optional[str]:
    root = require_framework_root()
    try:
        rel = file_path.resolve().relative_to(root)
    except ValueError:
        rel = file_path.name
    try:
        proc = subprocess.run(
            ["git", "log", "-1", "--format=%cI", "--", str(rel).replace("\\", "/")],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    stamp = (proc.stdout or "").strip()
    return stamp or None


def _git_first_author_iso(file_path: Path) -> Optional[str]:
    root = require_framework_root()
    try:
        rel = file_path.resolve().relative_to(root)
    except ValueError:
        rel = file_path.name
    try:
        proc = subprocess.run(
            ["git", "log", "--reverse", "--format=%aI", "-1", "--", str(rel).replace("\\", "/")],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    stamp = (proc.stdout or "").strip()
    return stamp or None


def _mtime_iso(file_path: Path) -> str:
    try:
        ts = file_path.stat().st_mtime
    except OSError:
        ts = datetime.now(timezone.utc).timestamp()
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_module_bulletin(module_path: str, file_path: str) -> Dict[str, Any]:
    path = Path(file_path)
    info = parse_static_module_info(file_path)
    raw_refs = _extract_references_from_ast(file_path)
    if not raw_refs:
        raw_refs = info.get("references") or []

    references = normalize_feed_references(raw_refs)
    cvelist = cvelist_from_metadata(info, raw_refs)
    title = str(info.get("name") or module_path).strip()
    description = str(info.get("description") or "").strip()
    modified = _git_committer_iso(path) or _mtime_iso(path)
    published = _git_first_author_iso(path) or modified

    try:
        source_data = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        source_data = ""

    bulletin: Dict[str, Any] = {
        "id": module_path_to_vulners_id(module_path),
        "type": "kittysploit",
        "bulletinFamily": "exploit",
        "title": title,
        "description": description,
        "href": module_href(module_path),
        "references": references,
        "cvelist": cvelist,
        "published": published,
        "modified": modified,
        "sourceData": source_data,
    }
    author = str(info.get("author") or "").strip()
    if author:
        bulletin["reporter"] = author
    tags = info.get("tags") or []
    if tags:
        bulletin["tags"] = tags
    return bulletin


def iter_feed_bulletins(module_index: Dict[str, str]) -> Iterator[Dict[str, Any]]:
    for module_path, file_path in sorted(module_index.items()):
        if not file_path or not str(file_path).endswith(".py"):
            continue
        rel = str(module_path).replace("\\", "/")
        yield build_module_bulletin(rel, file_path)
