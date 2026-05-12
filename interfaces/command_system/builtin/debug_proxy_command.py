from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
from core.proxy_manager import ProxyManager
import argparse
from datetime import datetime
from typing import List


class DebugProxyCommand(BaseCommand):
    """Legacy proxy command for request interception/debugging."""

    @property
    def name(self) -> str:
        return "debug_proxy"

    @property
    def description(self) -> str:
        return "Intercept and analyze network requests from framework modules"

    @property
    def usage(self) -> str:
        return "debug_proxy [start|stop|status|list|show|replay|export|clear|hexdump] [options]"

    def get_subcommands(self) -> List[str]:
        return ['start', 'stop', 'status', 'list', 'show', 'replay', 'export', 'clear', 'hexdump']

    def _create_parser(self):
        parser = argparse.ArgumentParser(
            prog='debug_proxy',
            description='Intercept and analyze network requests from framework modules'
        )

        subparsers = parser.add_subparsers(dest='action', help='Available actions')

        start_parser = subparsers.add_parser('start', help='Start the proxy server')
        start_parser.add_argument('--host', default='127.0.0.1', help='Host to bind proxy to (default: 127.0.0.1)')
        start_parser.add_argument('--port', type=int, default=8888, help='Port to bind proxy to (default: 8888)')
        start_parser.add_argument('--mode', choices=['http', 'socks'], default='http', help='Proxy mode to start (default: http)')
        start_parser.add_argument('--socks-user', dest='socks_user', help='Username for SOCKS authentication (optional)')
        start_parser.add_argument('--socks-pass', dest='socks_pass', help='Password for SOCKS authentication (optional)')
        start_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

        subparsers.add_parser('stop', help='Stop the proxy server')
        subparsers.add_parser('status', help='Show proxy status')

        list_parser = subparsers.add_parser('list', help='List captured requests')
        list_parser.add_argument('--limit', type=int, default=20, help='Number of requests to show (default: 20)')
        list_parser.add_argument('--protocol', choices=['HTTP', 'HTTPS', 'TCP', 'UDP', 'SOCKS5'], help='Filter by protocol')
        list_parser.add_argument('--method', help='Filter by HTTP method (GET, POST, etc.)')

        show_parser = subparsers.add_parser('show', help='Show details of a specific request')
        show_parser.add_argument('request_id', help='Request ID to show')
        show_parser.add_argument('--raw', action='store_true', help='Show raw request/response data')

        hexdump_parser = subparsers.add_parser('hexdump', help='Show hex dump of request/response data')
        hexdump_parser.add_argument('request_id', help='Request ID to show hex dump for')
        hexdump_parser.add_argument('--request', action='store_true', help='Show hex dump of request data (default: response)')
        hexdump_parser.add_argument('--response', action='store_true', help='Show hex dump of response data (default)')

        replay_parser = subparsers.add_parser('replay', help='Replay a captured request')
        replay_parser.add_argument('request_id', help='Request ID to replay')

        export_parser = subparsers.add_parser('export', help='Export captured requests')
        export_parser.add_argument('filename', help='Output filename')
        export_parser.add_argument('--format', choices=['json', 'har'], default='json', help='Export format (default: json)')

        subparsers.add_parser('clear', help='Clear all captured requests')

        return parser

    def execute(self, args, **kwargs):
        if not args:
            args = ['--help']

        try:
            parsed_args = self._create_parser().parse_args(args)
            return self._handle_action(parsed_args)
        except SystemExit:
            return True
        except Exception as e:
            print_error(f"Error executing debug_proxy command: {e}")
            return False

    def _handle_action(self, args):
        if not args.action:
            print_error("No action specified. Use 'debug_proxy --help' for usage information.")
            return False

        if not hasattr(self.framework, 'proxy_manager'):
            self.framework.proxy_manager = ProxyManager(verbose=True)

        proxy_manager = self.framework.proxy_manager

        if args.action == 'start':
            return self._start_proxy(proxy_manager, args)
        if args.action == 'stop':
            return self._stop_proxy(proxy_manager)
        if args.action == 'status':
            return self._show_status(proxy_manager)
        if args.action == 'list':
            return self._list_requests(proxy_manager, args)
        if args.action == 'show':
            return self._show_request(proxy_manager, args)
        if args.action == 'hexdump':
            return self._hexdump_request(proxy_manager, args)
        if args.action == 'replay':
            return self._replay_request(proxy_manager, args)
        if args.action == 'export':
            return self._export_requests(proxy_manager, args)
        if args.action == 'clear':
            return self._clear_requests(proxy_manager)

        print_error(f"Unknown action: {args.action}")
        return False

    def _start_proxy(self, proxy_manager: ProxyManager, args):
        if proxy_manager.is_running:
            print_warning("Proxy server is already running")
            return True

        if proxy_manager.start(args.host, args.port, mode=args.mode, socks_username=args.socks_user, socks_password=args.socks_pass):
            print_success(f"{args.mode.upper()} proxy server started on {args.host}:{args.port}")
            return True
        print_error("Failed to start proxy server")
        return False

    def _stop_proxy(self, proxy_manager: ProxyManager):
        if not proxy_manager.is_running:
            print_warning("Proxy server is not running")
            return True
        proxy_manager.stop()
        print_success("Proxy server stopped")
        return True

    def _show_status(self, proxy_manager: ProxyManager):
        status = proxy_manager.get_status()

        print_info("=== Debug Proxy Status ===")
        print_info(f"Running: {'Yes' if status['is_running'] else 'No'}")
        print_info(f"Mode: {status.get('mode', 'http').upper()}")
        if status['is_running']:
            print_info(f"Host: {status['host']}")
            print_info(f"Port: {status['port']}")
        print_info(f"Captured requests: {status['captured_requests']}")
        print_info(f"Capture HTTP: {'Yes' if status['capture_http'] else 'No'}")
        print_info(f"Capture HTTPS: {'Yes' if status['capture_https'] else 'No'}")
        print_info(f"Capture TCP: {'Yes' if status['capture_tcp'] else 'No'}")
        print_info(f"Capture UDP: {'Yes' if status['capture_udp'] else 'No'}")
        print_info("=" * 26)
        return True

    def _list_requests(self, proxy_manager: ProxyManager, args):
        requests = proxy_manager.get_requests(limit=args.limit)
        if not requests:
            print_info("No requests captured yet")
            return True

        if args.protocol:
            expected = args.protocol.upper()
            requests = [req for req in requests if req.get('protocol', '').upper() == expected]
        if args.method:
            requests = [req for req in requests if req.get('method', '').upper() == args.method.upper()]
        if not requests:
            print_info("No requests match the specified filters")
            return True

        print_info(f"=== Captured Requests ({len(requests)} shown) ===")
        print_info(f"{'ID':<8} {'Time':<8} {'Protocol':<6} {'Method':<6} {'URL':<40} {'Status':<6} {'Duration':<8}")
        print_info("-" * 90)
        for req in requests:
            timestamp = datetime.fromisoformat(req['timestamp']).strftime("%H:%M:%S")
            method = req.get('method', '')[:6]
            url = req.get('url', '')[:40]
            response_code = req.get('response_code', 0)
            if req['protocol'] == 'HTTPS' and req.get('method') == 'CONNECT':
                if response_code == 200:
                    status = "TUNNEL"
                elif response_code == 504:
                    status = "TIMEOUT"
                elif response_code == 502:
                    status = "ERROR"
                else:
                    status = "CONNECT"
            else:
                status = str(response_code)[:6]
            duration = f"{req.get('duration_ms', 0):.1f}ms"[:8]
            print_info(f"{req['id']:<8} {timestamp:<8} {req['protocol']:<6} {method:<6} {url:<40} {status:<6} {duration:<8}")
        print_info("=" * 90)
        return True

    def _show_request(self, proxy_manager: ProxyManager, args):
        request = proxy_manager.get_request_by_id(args.request_id)
        if not request:
            print_error(f"Request {args.request_id} not found")
            return False

        print_info(f"=== Request Details: {args.request_id} ===")
        print_info(f"Timestamp: {request['timestamp']}")
        print_info(f"Protocol: {request['protocol']}")
        print_info(f"Method: {request.get('method', 'N/A')}")
        print_info(f"URL: {request.get('url', 'N/A')}")
        print_info(f"Host: {request['host']}")
        print_info(f"Port: {request['port']}")
        print_info(f"SSL: {'Yes' if request['ssl_enabled'] else 'No'}")
        print_info(f"Response Code: {request.get('response_code', 'N/A')}")
        print_info(f"Duration: {request.get('duration_ms', 0):.2f}ms")

        if request.get('error'):
            print_error(f"Error: {request['error']}")

        if request.get('headers'):
            print_info("\n=== Request Headers ===")
            for key, value in request['headers'].items():
                print_info(f"{key}: {value}")
        if request.get('response_headers'):
            print_info("\n=== Response Headers ===")
            for key, value in request['response_headers'].items():
                print_info(f"{key}: {value}")

        if request.get('body_text'):
            print_info(f"\n=== Request Body ({len(request['body_text'])} chars) ===")
            if args.raw:
                print_info(request['body_text'])
            else:
                body = request['body_text']
                print_info(body[:500] + "... (truncated)" if len(body) > 500 else body)

        if request.get('response_body_text'):
            print_info(f"\n=== Response Body ({len(request['response_body_text'])} chars) ===")
            if args.raw:
                print_info(request['response_body_text'])
            else:
                body = request['response_body_text']
                print_info(body[:500] + "... (truncated)" if len(body) > 500 else body)

        print_info("=" * 50)
        return True

    def _hexdump_request(self, proxy_manager: ProxyManager, args):
        request = proxy_manager.get_request_by_id(args.request_id)
        if not request:
            print_error(f"Request {args.request_id} not found")
            return False

        if args.request:
            data = request.get('body', b'')
            data_type = "Request"
        else:
            data = request.get('response_body', b'')
            data_type = "Response"

        if isinstance(data, str):
            try:
                import base64
                data = base64.b64decode(data)
            except Exception:
                data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            data = str(data).encode('utf-8')

        if not data:
            print_info(f"No {data_type.lower()} data available for request {args.request_id}")
            return True

        print_info(f"=== {data_type} Hex Dump: {args.request_id} ===")
        print_info(f"Protocol: {request['protocol']}")
        print_info(f"Data size: {len(data)} bytes")
        print_info("=" * 60)
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print_info(f"{i:08x}: {hex_str:<48} |{ascii_str}|")
        print_info("=" * 60)
        return True

    def _replay_request(self, proxy_manager: ProxyManager, args):
        print_info(f"Replaying request {args.request_id}...")
        if proxy_manager.replay_request(args.request_id):
            print_success("Request replayed successfully")
            return True
        print_error("Failed to replay request")
        return False

    def _export_requests(self, proxy_manager: ProxyManager, args):
        if proxy_manager.export_requests(args.filename):
            print_success(f"Requests exported to {args.filename}")
            return True
        print_error("Failed to export requests")
        return False

    def _clear_requests(self, proxy_manager: ProxyManager):
        proxy_manager.clear_requests()
        print_success("All captured requests cleared")
        return True
