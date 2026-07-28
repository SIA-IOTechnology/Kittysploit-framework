#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Prefetch HTTP probe paths for bulk scanner runs.

P0: seed common paths (especially ``/``) once into the response cache.
P1: collect unique GET paths across selected modules and prefetch them so
modules share one network round-trip per path.
"""

from __future__ import annotations

import ast
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

_EXTRACT_CACHE: Dict[Tuple[str, int, int], Tuple[str, ...]] = {}
_EXTRACT_LOCK = threading.Lock()


def _file_stamp(path: str) -> Tuple[int, int]:
    try:
        st = os.stat(path)
        return int(st.st_mtime_ns), int(st.st_size)
    except OSError:
        return 0, 0


def _const_str(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _tuple_strs(node: ast.AST) -> List[str]:
    out: List[str] = []
    if isinstance(node, (ast.Tuple, ast.List)):
        for elt in node.elts:
            s = _const_str(elt)
            if s is not None:
                out.append(s)
    return out


def extract_get_paths(file_path: str) -> Tuple[str, ...]:
    """
    Extract literal GET paths from a scanner module source (no import).

    Handles:
      http_request(..., path='/x')
      for path in ('/a', '/b'): http_request(..., path=path)
    """
    if not file_path or not os.path.isfile(file_path):
        return ("/",)

    stamp = _file_stamp(file_path)
    key = (os.path.abspath(file_path), stamp[0], stamp[1])
    with _EXTRACT_LOCK:
        cached = _EXTRACT_CACHE.get(key)
        if cached is not None:
            return cached

    paths: Set[str] = set()
    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=file_path)
    except Exception:
        result = ("/",)
        with _EXTRACT_LOCK:
            _EXTRACT_CACHE[key] = result
        return result

    loop_paths: Dict[str, List[str]] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.For) and isinstance(node.target, ast.Name):
            vals = _tuple_strs(node.iter)
            if vals:
                loop_paths[node.target.id] = vals

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_http = False
        if isinstance(func, ast.Attribute) and func.attr == "http_request":
            is_http = True
        elif isinstance(func, ast.Name) and func.id == "http_request":
            is_http = True
        if not is_http:
            continue

        method = "GET"
        path_node = None
        for kw in node.keywords:
            if kw.arg == "method":
                m = _const_str(kw.value)
                if m:
                    method = m.upper()
            elif kw.arg == "path":
                path_node = kw.value
        if method != "GET":
            continue

        if path_node is None:
            paths.add("/")
            continue

        literal = _const_str(path_node)
        if literal is not None:
            paths.add(literal if literal.startswith("/") else "/" + literal)
            continue

        if isinstance(path_node, ast.Name) and path_node.id in loop_paths:
            for p in loop_paths[path_node.id]:
                paths.add(p if p.startswith("/") else "/" + p)

    if not paths:
        paths.add("/")

    result = tuple(sorted(paths))
    with _EXTRACT_LOCK:
        _EXTRACT_CACHE[key] = result
    return result


def probe_url(hostname: str, port: int, path: str, scheme: Optional[str] = None) -> str:
    """Build the same URL shape ``Http_client.http_request`` uses for cache keys."""
    proto = scheme or ("https" if int(port) == 443 else "http")
    path_str = "/" if path in (None, "") else str(path)
    if not path_str.startswith("/"):
        path_str = "/" + path_str
    return f"{proto}://{hostname}:{port}{path_str}"


def _fetch_url_without_fragment(url: str) -> str:
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    path = parts.path or "/"
    if "#" in path:
        path = path.split("#", 1)[0] or "/"
    # urlsplit already separates fragment; drop it explicitly
    return urlunsplit((parts.scheme, parts.netloc, path or "/", "", ""))


def collect_module_probes(
    modules: Sequence[Dict[str, Any]],
    *,
    hostname: str,
    port_for_module,
    scheme_for_port=None,
) -> List[Tuple[str, str, int, str]]:
    """
    Return unique probes as (method, url, port, path).

    ``port_for_module(module_path) -> int``
    ``scheme_for_port(port) -> str`` optional
    """
    seen: Set[str] = set()
    probes: List[Tuple[str, str, int, str]] = []

    for module in modules:
        module_path = module.get("path") or ""
        file_path = module.get("file_path") or ""
        # HTTP-family only
        if not str(module_path).startswith("scanner/http") and not str(module_path).startswith(
            "scanner/cloud"
        ):
            # still seed `/` for telecom http etc. when file looks http
            if "/http/" not in str(module_path).replace("\\", "/"):
                if not str(module_path).startswith("scanner/telecom"):
                    continue

        port = int(port_for_module(module_path))
        scheme = None
        if callable(scheme_for_port):
            scheme = scheme_for_port(port)
        get_paths = extract_get_paths(file_path) if file_path else ("/",)
        for path in get_paths:
            url = probe_url(hostname, port, path, scheme=scheme)
            if url in seen:
                continue
            seen.add(url)
            probes.append(("GET", url, port, path))

    # Always ensure root is probed for each distinct port used
    ports_used = {p[2] for p in probes} or {443}
    for port in ports_used:
        scheme = scheme_for_port(port) if callable(scheme_for_port) else None
        url = probe_url(hostname, port, "/", scheme=scheme)
        if url not in seen:
            seen.add(url)
            probes.insert(0, ("GET", url, port, "/"))

    # Soft-404 canary: one random missing path per port (custom 404 pages).
    try:
        from lib.scanner.http.soft_404 import (
            make_canary_path,
            origin_key_from_url,
            remember_canary_path,
        )

        for port in ports_used:
            scheme = scheme_for_port(port) if callable(scheme_for_port) else None
            canary = make_canary_path()
            url = probe_url(hostname, port, canary, scheme=scheme)
            if url in seen:
                continue
            seen.add(url)
            probes.append(("GET", url, port, canary))
            remember_canary_path(origin_key_from_url(url), canary)
    except Exception:
        pass

    # Prefer `/` first, then canary, then shorter paths
    def _sort_key(t):
        path = t[3] or "/"
        if path == "/":
            rank = 0
        elif str(path).startswith("/ks-soft404-"):
            rank = 1
        else:
            rank = 2
        return (t[2], rank, len(path), path)

    probes.sort(key=_sort_key)
    return probes


def prefetch_probes(
    probes: Sequence[Tuple[str, str, int, str]],
    *,
    threads: int = 10,
    timeout: float = 10.0,
    verify: bool = False,
    progress_cb=None,
) -> Dict[str, Any]:
    """
    Issue unique GETs and store responses in the scanner HTTP cache.

    Fragment-only variants (``/#/login``) share one network fetch with ``/``
    and are stored under every alias cache key.
    """
    from lib.scanner.cache import get_cache, is_cache_enabled
    from lib.scanner.http_pool import get_scan_session
    import requests

    if not is_cache_enabled() or not probes:
        return {
            "prefetched": 0,
            "skipped": 0,
            "errors": 0,
            "total": len(probes),
            "network_fetches": 0,
        }

    cache = get_cache()
    session = get_scan_session()
    owns_session = False
    if session is None:
        session = requests.Session()
        owns_session = True

    fetch_map: Dict[str, List[Tuple[str, str]]] = {}
    for method, url, _port, _path in probes:
        fetch_url = _fetch_url_without_fragment(url)
        fetch_map.setdefault(fetch_url, []).append((method, url))

    stats = {
        "prefetched": 0,
        "skipped": 0,
        "errors": 0,
        "total": len(probes),
        "network_fetches": len(fetch_map),
    }
    lock = threading.Lock()

    def _one(fetch_url: str, aliases: List[Tuple[str, str]]) -> None:
        if all(cache.has(method, alias_url) for method, alias_url in aliases):
            with lock:
                stats["skipped"] += len(aliases)
            return
        method = aliases[0][0]
        try:
            resp = session.request(
                method,
                fetch_url,
                timeout=timeout,
                verify=verify,
                allow_redirects=True,
            )
            for method_i, alias_url in aliases:
                cache.set(method_i, alias_url, resp)
                # Seed soft-404 baselines from prefetched `/` and canary paths
                try:
                    from urllib.parse import urlparse
                    from lib.scanner.http.soft_404 import (
                        origin_key_from_url,
                        register_baseline_from_response,
                        register_canary_from_response,
                    )

                    path = urlparse(alias_url).path or "/"
                    origin = origin_key_from_url(alias_url)
                    if str(method_i).upper() != "GET":
                        continue
                    if path == "/":
                        register_baseline_from_response(origin, resp)
                    elif path.startswith("/ks-soft404-"):
                        register_canary_from_response(origin, resp, path=path)
                except Exception:
                    pass
            with lock:
                stats["prefetched"] += 1
        except Exception:
            with lock:
                stats["errors"] += 1

    workers = max(1, min(int(threads), len(fetch_map) or 1))
    items = list(fetch_map.items())
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, fu, aliases) for fu, aliases in items]
        done = 0
        for fut in as_completed(futures):
            fut.result()
            done += 1
            if progress_cb and (done == 1 or done == len(items) or done % 5 == 0):
                progress_cb(done, len(items), dict(stats))

    if owns_session:
        try:
            session.close()
        except Exception:
            pass

    return stats


def group_modules_by_primary_path(
    modules: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Stable reorder: modules sharing the same primary GET path are adjacent
    (better cache locality if prefetch is partial / cache disabled).
    """
    decorated = []
    for idx, module in enumerate(modules):
        paths = extract_get_paths(module.get("file_path") or "")
        primary = paths[0] if paths else "/"
        # Prefer modules that only hit `/` early (seed consumers)
        only_root = 0 if paths == ("/",) else 1
        decorated.append((only_root, primary, idx, module))
    decorated.sort(key=lambda t: (t[0], t[1], t[2]))
    return [t[3] for t in decorated]
