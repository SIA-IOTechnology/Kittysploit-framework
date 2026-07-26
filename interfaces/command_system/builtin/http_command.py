#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import html.parser
import json
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import urllib3

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_empty, print_info, print_success, print_error, print_warning, print_table


DEFAULT_MAX_BODY_CHARS = 12000
TEXT_SAMPLE_BYTES = 4096


class _HtmlTextExtractor(html.parser.HTMLParser):
    """Small, dependency-free HTML text previewer for CLI output."""

    def __init__(self):
        super().__init__()
        self.title_parts: List[str] = []
        self.text_parts: List[str] = []
        self._in_title = False
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag in {"script", "style", "noscript"}:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data):
        cleaned = " ".join(str(data or "").split())
        if not cleaned:
            return
        if self._in_title:
            self.title_parts.append(cleaned)
        elif not self._skip_depth:
            self.text_parts.append(cleaned)

    @property
    def title(self) -> str:
        return " ".join(self.title_parts).strip()

    @property
    def text(self) -> str:
        return " ".join(self.text_parts).strip()


class HttpCommand(BaseCommand):
    """Send HTTP requests from the framework CLI."""

    @property
    def name(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Send HTTP requests with clean, readable output"

    @property
    def usage(self) -> str:
        return "http <url> [options]"

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Examples:
    http example.com
    http https://example.com/api -i
    http api.local/users -j '{{"name":"kitty"}}'
    http https://example.com --format json
    http https://example.com --raw --max-body 50000
    http https://example.com -o response.html

Options keep curl-like names where useful, but output is formatted by default:
    JSON responses are pretty-printed, HTML responses show title + text preview,
    binary responses are summarized, and metadata is shown as a compact table.
        """

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog='http',
            description='Send HTTP requests with clean, readable output'
        )
        parser.add_argument('url', help='Target URL (e.g. https://example.com/api)')
        parser.add_argument('-X', '--method', default='GET', help='HTTP method (default: GET)')
        parser.add_argument('-H', '--header', action='append', default=[], help='Custom header (format: "Key: Value")')
        parser.add_argument('-d', '--data', help='Raw request body')
        parser.add_argument('-j', '--json', dest='json_data', help='JSON body string')
        parser.add_argument('--timeout', type=float, default=15.0, help='Request timeout in seconds (default: 15)')
        parser.add_argument('-k', '--insecure', action='store_true', help='Disable TLS certificate verification')
        parser.add_argument('-L', '--location', action='store_true', help='Follow redirects')
        parser.add_argument('-i', '--include', action='store_true', help='Include response headers in output')
        parser.add_argument('-I', '--head', action='store_true', help='Send HEAD request')
        parser.add_argument('-o', '--output', help='Write response body to file')
        parser.add_argument('--proxy', help='Override proxy URL for this request')
        parser.add_argument('-A', '--user-agent', help='Override User-Agent header')
        parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
        parser.add_argument('--format', choices=['auto', 'raw', 'json', 'text'], default='auto', help='Body display format (default: auto)')
        parser.add_argument('--raw', action='store_true', help='Print response body without pretty formatting')
        parser.add_argument('--no-body', action='store_true', help='Show metadata and headers only')
        parser.add_argument('--max-body', type=int, default=DEFAULT_MAX_BODY_CHARS, help=f'Max body chars to print (default: {DEFAULT_MAX_BODY_CHARS})')
        parser.add_argument('--fail', action='store_true', help='Return failure on HTTP status >= 400')
        return parser

    def execute(self, args, **kwargs) -> bool:
        if not args:
            print_info(self.help_text)
            return True

        if args[0].lower() in {"-h", "--help", "help"}:
            print_info(self.help_text)
            return True

        try:
            parsed = self._create_parser().parse_args(args)
        except SystemExit:
            return True

        try:
            return self._run_request(parsed)
        except Exception as e:
            print_error(f"HTTP command failed: {e}")
            return False

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme:
            return url
        return f"http://{url}"

    def _parse_headers(self, values: List[str]) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        for entry in values:
            if ':' not in entry:
                raise ValueError(f"Invalid header format: {entry!r}. Use 'Key: Value'")
            key, value = entry.split(':', 1)
            headers[key.strip()] = value.strip()
        return headers

    def _build_proxies(self, proxy_override: Optional[str]) -> Dict[str, str]:
        if proxy_override:
            return {'http': proxy_override, 'https': proxy_override}

        if hasattr(self.framework, 'is_tor_enabled') and self.framework.is_tor_enabled():
            tor_proxies = self.framework.tor_manager.get_tor_proxy_dict()
            if tor_proxies:
                return tor_proxies

        if hasattr(self.framework, 'is_proxy_enabled') and self.framework.is_proxy_enabled():
            proxy_url = self.framework.get_proxy_url()
            if proxy_url:
                return {'http': proxy_url, 'https': proxy_url}

        return {}

    def _run_request(self, args) -> bool:
        url = self._normalize_url(args.url)
        method = 'HEAD' if args.head else str(args.method).upper()

        if args.data and args.json_data:
            print_error("Use either --data or --json, not both.")
            return False

        headers = self._parse_headers(args.header)
        if args.user_agent:
            headers['User-Agent'] = args.user_agent
        else:
            headers.setdefault('User-Agent', 'KittySploit-HTTP/1.0')

        request_kwargs = {
            'headers': headers,
            'timeout': args.timeout,
            'allow_redirects': bool(args.location),
            'verify': not args.insecure,
            'proxies': self._build_proxies(args.proxy),
        }

        if args.insecure:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if args.json_data:
            try:
                request_kwargs['json'] = json.loads(args.json_data)
                request_kwargs['headers'].setdefault('Content-Type', 'application/json')
            except json.JSONDecodeError as e:
                print_error(f"Invalid JSON for --json: {e}")
                return False
        elif args.data is not None:
            request_kwargs['data'] = args.data

        if args.verbose:
            print_info(f"> {method} {url}")
            for hname, hvalue in headers.items():
                print_info(f"> {hname}: {hvalue}")
            if request_kwargs.get('proxies'):
                print_info(f"> Proxy: {request_kwargs['proxies']}")

        started = time.time()
        response = requests.request(method, url, **request_kwargs)
        elapsed_ms = (time.time() - started) * 1000.0

        self._print_summary(method, url, response, elapsed_ms)

        if args.include:
            self._print_headers(response.headers)

        if args.head or args.no_body:
            return self._status_result(response, args.fail)

        if args.output:
            with open(args.output, 'wb') as f:
                f.write(response.content)
            print_success(f"Response body saved to: {args.output}")
            return self._status_result(response, args.fail)

        self._print_body(response, args)
        return self._status_result(response, args.fail)

    def _status_result(self, response: requests.Response, fail_on_error: bool) -> bool:
        return not (fail_on_error and response.status_code >= 400)

    def _print_summary(self, method: str, requested_url: str, response: requests.Response, elapsed_ms: float) -> None:
        status = f"{response.status_code} {response.reason}".strip()
        if 200 <= response.status_code < 400:
            print_success(f"{status} ({elapsed_ms:.1f} ms)")
        else:
            print_warning(f"{status} ({elapsed_ms:.1f} ms)")

        rows = [
            ["Method", method],
            ["Requested", requested_url],
            ["Final URL", response.url],
            ["Content-Type", response.headers.get("Content-Type", "unknown")],
            ["Size", self._format_size(len(response.content or b""))],
        ]
        redirect_count = len(getattr(response, "history", []) or [])
        if redirect_count:
            rows.append(["Redirects", str(redirect_count)])

        print_table(
            ["Field", "Value"],
            rows,
            max_width=120,
            expand_to_terminal=True,
            protect_full_width_headers=(),
            wrap_extra_headers=("value",),
        )

    def _print_headers(self, headers) -> None:
        print_empty()
        print_info("Response headers")
        rows = [[str(key), str(value)] for key, value in headers.items()]
        if rows:
            print_table(
                ["Header", "Value"],
                rows,
                max_width=120,
                expand_to_terminal=True,
                protect_full_width_headers=(),
                wrap_extra_headers=("value",),
            )
        else:
            print_info("(none)")

    def _print_body(self, response: requests.Response, args) -> None:
        body_format = "raw" if args.raw else args.format
        max_chars = max(0, int(args.max_body or 0))
        rendered, label = self._render_body(response, body_format)

        print_empty()
        print_info(label)
        if not rendered:
            print_info("(empty)")
            return

        output, truncated = self._truncate(rendered, max_chars)
        print_info(output)
        if truncated:
            print_warning(f"Body truncated at {max_chars} chars. Use --max-body 0 for the full body or -o <file> to save it.")

    def _render_body(self, response: requests.Response, body_format: str) -> Tuple[str, str]:
        content = response.content or b""
        content_type = response.headers.get("Content-Type", "").lower()

        if body_format == "raw":
            return self._decode_response_text(response), "Response body (raw)"

        if body_format == "json" or (body_format == "auto" and self._looks_like_json(response, content_type)):
            pretty = self._pretty_json(response)
            if pretty is not None:
                return pretty, "Response body (JSON)"
            if body_format == "json":
                return self._decode_response_text(response), "Response body (invalid JSON, raw text)"

        if body_format in {"auto", "text"} and self._looks_binary(content, content_type):
            return self._binary_summary(content), "Response body (binary)"

        if body_format == "auto" and "html" in content_type:
            title, text = self._extract_html_preview(self._decode_response_text(response))
            lines = []
            if title:
                lines.append(f"Title: {title}")
            if text:
                lines.append(text)
            return "\n\n".join(lines) if lines else self._decode_response_text(response), "Response body (HTML preview)"

        return self._decode_response_text(response), "Response body"

    def _pretty_json(self, response: requests.Response) -> Optional[str]:
        try:
            parsed = response.json()
        except ValueError:
            try:
                parsed = json.loads(self._decode_response_text(response))
            except ValueError:
                return None
        return json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=False)

    def _looks_like_json(self, response: requests.Response, content_type: str) -> bool:
        if "json" in content_type:
            return True
        sample = self._decode_response_text(response).lstrip()
        return sample.startswith("{") or sample.startswith("[")

    def _looks_binary(self, content: bytes, content_type: str) -> bool:
        if not content:
            return False
        if content_type.startswith("text/") or any(marker in content_type for marker in ("json", "xml", "html", "javascript")):
            return False
        sample = content[:TEXT_SAMPLE_BYTES]
        if b"\x00" in sample:
            return True
        try:
            sample.decode("utf-8")
            return False
        except UnicodeDecodeError:
            return True

    def _decode_response_text(self, response: requests.Response) -> str:
        try:
            return response.text if response.text is not None else ""
        except UnicodeDecodeError:
            return response.content.decode("utf-8", errors="replace")

    def _binary_summary(self, content: bytes) -> str:
        preview = base64.b64encode(content[:48]).decode("ascii")
        suffix = "..." if len(content) > 48 else ""
        return f"{self._format_size(len(content))} binary payload\nbase64(first 48 bytes): {preview}{suffix}"

    def _extract_html_preview(self, text: str) -> Tuple[str, str]:
        parser = _HtmlTextExtractor()
        try:
            parser.feed(text)
        except Exception:
            return "", text
        body = re.sub(r"\s+", " ", parser.text).strip()
        return parser.title, body

    def _truncate(self, text: str, max_chars: int) -> Tuple[str, bool]:
        if max_chars == 0 or len(text) <= max_chars:
            return text, False
        return text[:max_chars], True

    def _format_size(self, size: int) -> str:
        units = ["B", "KB", "MB", "GB"]
        value = float(size)
        for unit in units:
            if value < 1024.0 or unit == units[-1]:
                if unit == "B":
                    return f"{int(value)} {unit}"
                return f"{value:.1f} {unit}"
            value /= 1024.0
