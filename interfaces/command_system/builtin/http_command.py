#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
import urllib3

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning


class HttpCommand(BaseCommand):
    """Send HTTP requests from the framework CLI."""

    @property
    def name(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Send HTTP requests with curl-like options"

    @property
    def usage(self) -> str:
        return "http <url> [options]"

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog='http',
            description='Send HTTP requests with curl-like options'
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
        return parser

    def execute(self, args, **kwargs) -> bool:
        if not args:
            args = ['--help']

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

        print_success(f"{response.status_code} {response.reason} ({elapsed_ms:.1f} ms)")
        print_info(f"Final URL: {response.url}")
        print_info(f"Response size: {len(response.content)} bytes")

        if args.include:
            print_info("")
            print_info("=== Response Headers ===")
            for key, value in response.headers.items():
                print_info(f"{key}: {value}")

        if args.head:
            return True

        if args.output:
            with open(args.output, 'wb') as f:
                f.write(response.content)
            print_success(f"Response body saved to: {args.output}")
            return True

        print_info("")
        print_info("=== Response Body ===")
        body = response.text if response.text is not None else ""
        print_info(body)
        return True
