from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import argparse
import time
from typing import List


class ProxyCommand(BaseCommand):
    """CLI-only KittyProxy command (no web interface)."""

    @property
    def name(self) -> str:
        return "proxy"

    @property
    def description(self) -> str:
        return "Start and manage KittyProxy in CLI headless mode"

    @property
    def usage(self) -> str:
        return "proxy [start|stop|status|interactive] [options]"

    def get_subcommands(self) -> List[str]:
        return ['start', 'stop', 'status', 'interactive']

    def _create_parser(self):
        parser = argparse.ArgumentParser(
            prog='proxy',
            description='Run KittyProxy in headless CLI mode (no GUI/API)'
        )
        subparsers = parser.add_subparsers(dest='action', help='Available actions')

        start_parser = subparsers.add_parser('start', help='Start headless KittyProxy')
        start_parser.add_argument('--host', default='127.0.0.1', help='Host to bind proxy to (default: 127.0.0.1)')
        start_parser.add_argument('--port', type=int, default=8080, help='Port to bind proxy to (default: 8080)')
        start_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

        subparsers.add_parser('stop', help='Stop headless KittyProxy')
        subparsers.add_parser('status', help='Show headless KittyProxy status')
        interactive_parser = subparsers.add_parser('interactive', help='Open interactive proxy console')
        interactive_parser.add_argument('--auto-start', action='store_true', help='Start proxy automatically if not running')
        interactive_parser.add_argument('--host', default='127.0.0.1', help='Host used with --auto-start (default: 127.0.0.1)')
        interactive_parser.add_argument('--port', type=int, default=8080, help='Port used with --auto-start (default: 8080)')

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
            print_error(f"Error executing proxy command: {e}")
            return False

    def _handle_action(self, args):
        if not args.action:
            print_error("No action specified. Use 'proxy --help' for usage information.")
            return False

        if args.action == 'start':
            return self._start_proxy(args)
        if args.action == 'stop':
            return self._stop_proxy()
        if args.action == 'status':
            return self._show_status()
        if args.action == 'interactive':
            return self._interactive_mode(args)

        print_error(f"Unknown action: {args.action}")
        return False

    def _get_runtime_state(self):
        if not hasattr(self.framework, 'kittyproxy_runtime'):
            self.framework.kittyproxy_runtime = {
                'instance': None,
                'host': None,
                'port': None,
                'started_at': None,
                'configured_proxy_url': None,
                'previous_proxy_config': None,
            }
        return self.framework.kittyproxy_runtime

    def _is_running(self, state) -> bool:
        instance = state.get('instance')
        if not instance:
            return False
        return bool(getattr(instance, 'thread', None) and instance.thread.is_alive())

    def _start_proxy(self, args):
        state = self._get_runtime_state()
        if self._is_running(state):
            print_warning(f"KittyProxy is already running on {state['host']}:{state['port']}")
            return True

        try:
            from core.utils.kittyproxy_path import ensure_kittyproxy_path, kittyproxy_install_hint

            if not ensure_kittyproxy_path():
                print_error("KittyProxy is not installed.")
                print_info(kittyproxy_install_hint())
                return False
            from kittyproxy.proxy_core import MitmProxyWrapper
        except ImportError as e:
            print_error(f"Could not load KittyProxy runtime: {e}")
            print_info("Install dependency with: pip install mitmproxy")
            print_info(kittyproxy_install_hint())
            return False

        try:
            proxy = MitmProxyWrapper(host=args.host, port=args.port, api_host=None, api_port=None)
            proxy.start()
            time.sleep(0.2)
            if not proxy.thread.is_alive():
                print_error("KittyProxy failed to start")
                return False

            state['instance'] = proxy
            state['host'] = args.host
            state['port'] = args.port
            state['started_at'] = time.time()
            state['configured_proxy_url'] = None
            state['previous_proxy_config'] = None

            if hasattr(self.framework, 'configure_proxy'):
                client_host = '127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host
                try:
                    if hasattr(self.framework, 'get_proxy_config'):
                        state['previous_proxy_config'] = self.framework.get_proxy_config()
                    self.framework.configure_proxy(True, client_host, args.port, scheme='http')
                    state['configured_proxy_url'] = f"http://{client_host}:{args.port}"
                    if getattr(args, 'verbose', False):
                        print_info(f"Framework HTTP proxy configured: {state['configured_proxy_url']}")
                except Exception as e:
                    print_warning(f"Proxy started, but framework proxy configuration failed: {e}")

            print_success(f"KittyProxy started on {args.host}:{args.port} (headless mode)")
            if getattr(args, 'verbose', False):
                print_info("No web interface is started in this mode.")
            return True
        except Exception as e:
            print_error(f"Failed to start KittyProxy: {e}")
            return False

    def _stop_proxy(self):
        state = self._get_runtime_state()
        if not self._is_running(state):
            print_warning("KittyProxy is not running")
            return True

        try:
            state['instance'].stop()
            self._restore_framework_proxy(state)
            state['instance'] = None
            state['host'] = None
            state['port'] = None
            state['started_at'] = None
            state['configured_proxy_url'] = None
            state['previous_proxy_config'] = None
            print_success("KittyProxy stopped")
            return True
        except Exception as e:
            print_error(f"Failed to stop KittyProxy: {e}")
            return False

    def _restore_framework_proxy(self, state):
        configured_url = state.get('configured_proxy_url')
        if not configured_url or not hasattr(self.framework, 'configure_proxy'):
            return
        try:
            current_url = self.framework.get_proxy_url() if hasattr(self.framework, 'get_proxy_url') else None
        except Exception:
            current_url = None
        if current_url and current_url != configured_url:
            return

        previous = state.get('previous_proxy_config') or {}
        if previous.get('enabled') and previous.get('http_proxy'):
            try:
                from urllib.parse import urlparse
                parsed = urlparse(previous.get('http_proxy'))
                if parsed.hostname and parsed.port:
                    self.framework.configure_proxy(
                        True,
                        parsed.hostname,
                        parsed.port,
                        scheme=parsed.scheme or previous.get('protocol') or 'http',
                        username=previous.get('username'),
                        password=previous.get('password'),
                    )
                    return
            except Exception:
                pass
        try:
            self.framework.configure_proxy(False)
        except Exception:
            pass

    def _show_status(self):
        state = self._get_runtime_state()
        running = self._is_running(state)

        print_info("=== KittyProxy (CLI) Status ===")
        print_info(f"Running: {'Yes' if running else 'No'}")
        if running:
            uptime = int(time.time() - state['started_at']) if state.get('started_at') else 0
            print_info(f"Host: {state['host']}")
            print_info(f"Port: {state['port']}")
            print_info(f"Uptime: {uptime}s")
        print_info("=" * 30)
        return True

    def _interactive_mode(self, args):
        state = self._get_runtime_state()
        if not self._is_running(state):
            if not args.auto_start:
                print_warning("KittyProxy is not running. Use 'proxy start' or 'proxy interactive --auto-start'.")
                return False
            if not self._start_proxy(args):
                return False
            state = self._get_runtime_state()

        print_success("Entering proxy interactive mode. Type 'help' for commands, 'exit' to leave.")
        while True:
            try:
                raw = input("kittyproxy> ").strip()
            except (EOFError, KeyboardInterrupt):
                print_info("")
                break

            if not raw:
                continue

            parts = raw.split()
            command = parts[0].lower()

            if command in ('exit', 'quit', 'q'):
                break
            if command == 'help':
                self._print_interactive_help()
                continue
            if command == 'status':
                self._show_status()
                continue
            if command == 'list':
                limit = 10
                if len(parts) > 1:
                    try:
                        limit = max(1, int(parts[1]))
                    except ValueError:
                        print_error("Invalid limit. Example: list 20")
                        continue
                self._interactive_list_flows(limit=limit)
                continue
            if command == 'show':
                if len(parts) < 2:
                    print_error("Usage: show <flow_id>")
                    continue
                self._interactive_show_flow(parts[1])
                continue
            if command == 'clear':
                self._interactive_clear_flows()
                continue
            if command == 'stop':
                self._stop_proxy()
                continue
            if command == 'start':
                if self._is_running(state):
                    print_warning("KittyProxy is already running")
                    continue
                start_args = argparse.Namespace(host=args.host, port=args.port, verbose=False)
                self._start_proxy(start_args)
                state = self._get_runtime_state()
                continue

            print_warning(f"Unknown interactive command: {command}. Type 'help'.")

        print_info("Leaving proxy interactive mode.")
        return True

    def _print_interactive_help(self):
        print_info("Interactive commands:")
        print_info("  help           Show this help")
        print_info("  status         Show proxy status")
        print_info("  list [limit]   List latest captured flows (default: 10)")
        print_info("  show <flow_id> Show one flow details")
        print_info("  clear          Clear captured flows")
        print_info("  start          Start proxy (uses --host/--port from interactive command)")
        print_info("  stop           Stop proxy")
        print_info("  exit           Leave interactive mode")

    def _interactive_list_flows(self, limit: int = 10):
        try:
            from core.utils.kittyproxy_path import ensure_kittyproxy_path

            ensure_kittyproxy_path()
            from kittyproxy.flow_manager import flow_manager
            flows = flow_manager.get_flows()
        except Exception as e:
            print_error(f"Failed to access flow manager: {e}")
            return

        if not flows:
            print_info("No captured flows yet.")
            return

        rows = flows[:limit]
        print_info(f"{'ID':<12} {'Method':<7} {'Status':<6} {'Host':<24} URL")
        print_info("-" * 90)
        for f in rows:
            fid = (f.get('id') or '')[:12]
            method = (f.get('method') or '-')[:7]
            status = str(f.get('status_code') or '-')[:6]
            host = (f.get('host') or '-')[:24]
            url = f.get('url') or '-'
            print_info(f"{fid:<12} {method:<7} {status:<6} {host:<24} {url}")

    def _interactive_show_flow(self, flow_id: str):
        try:
            from core.utils.kittyproxy_path import ensure_kittyproxy_path

            ensure_kittyproxy_path()
            from kittyproxy.flow_manager import flow_manager
            flow = flow_manager.get_flow(flow_id)
        except Exception as e:
            print_error(f"Failed to access flow manager: {e}")
            return

        if not flow:
            print_error(f"Flow not found: {flow_id}")
            return

        print_info(f"ID: {flow.get('id')}")
        print_info(f"Method: {flow.get('method')}")
        print_info(f"URL: {flow.get('url')}")
        print_info(f"Status: {flow.get('status_code')}")
        print_info(f"Duration(ms): {flow.get('duration_ms')}")
        req = flow.get('request') or {}
        res = flow.get('response') or {}
        print_info(f"Request bytes: {req.get('content_length', 0)}")
        print_info(f"Response bytes: {res.get('content_length', 0)}")

    def _interactive_clear_flows(self):
        try:
            from core.utils.kittyproxy_path import ensure_kittyproxy_path

            ensure_kittyproxy_path()
            from kittyproxy.flow_manager import flow_manager
            flow_manager.clear()
            print_success("Captured flows cleared.")
        except Exception as e:
            print_error(f"Failed to clear flows: {e}")
