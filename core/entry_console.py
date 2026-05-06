#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Entry point for KittySploit console (CLI). Used by kittyconsole.py and by the
pip-installed 'kittysploit' command.
"""

import argparse
import os
import sys
from core.framework.framework import Framework
from interfaces.cli import CLI
from interfaces.rpc_server import RpcServer
from interfaces.api_server import ApiServer
from core.proxy_manager import ProxyManager
from core.session import Session
from core.output_handler import OutputHandler
from core.output_handler import print_info, print_success, print_error, print_warning, print_debug, print_status
from interfaces.command_system.command_registry import CommandRegistry


def parse_arguments():
    parser = argparse.ArgumentParser(description='KittySploit - A modular penetration testing framework')
    parser.add_argument('command', nargs='?', help='Optional command (e.g. agent)')
    parser.add_argument('command_args', nargs='*', help='Optional command arguments')
    parser.add_argument('-q', '--quiet', action='store_true', help='Start without banner')
    parser.add_argument('-m', '--module', help='Specify a module to use directly')
    parser.add_argument('-o', '--options', help='Module options in format "option1=value1,option2=value2"')
    parser.add_argument('-e', '--execute', action='store_true', help='Execute the module and exit')
    parser.add_argument('-v', '--version', action='store_true', help='Show version information')

    # Options for the RPC server
    parser.add_argument('-r', '--rpc', action='store_true', help='Start the RPC server')
    parser.add_argument('--rpc-port', type=int, default=8888, help='Port for the RPC server (default: 8888)')
    parser.add_argument('--rpc-host', default='127.0.0.1', help='Host for the RPC server (default: 127.0.0.1)')

    # Options for the API server
    parser.add_argument('-a', '--api', action='store_true', help='Start the API server')
    parser.add_argument('--api-port', type=int, default=5000, help='Port for the API server (default: 5000)')
    parser.add_argument('--api-host', default='127.0.0.1', help='Host for the API server (default: 127.0.0.1)')
    parser.add_argument(
        '--api-key',
        help='API key for RPC/API servers (or set KITTYSPLOIT_API_KEY)',
    )

    # Embedded proxy options for kittyconsole
    parser.add_argument('--proxy', action='store_true', help='Start integrated proxy with interactive CLI')
    parser.add_argument('--proxy-host', default='127.0.0.1', help='Proxy bind host (default: 127.0.0.1)')
    parser.add_argument('--proxy-port', type=int, default=8888, help='Proxy bind port (default: 8888)')
    parser.add_argument('--proxy-mode', choices=['http', 'socks'], default='http',
                        help='Proxy mode (default: http)')
    parser.add_argument('--proxy-socks-user', help='SOCKS username (optional)')
    parser.add_argument('--proxy-socks-pass', help='SOCKS password (optional)')
    parser.add_argument('--proxy-verbose', action='store_true', help='Enable verbose proxy logs')

    args, unknown_args = parser.parse_known_args()
    if getattr(args, 'command', None) and unknown_args:
        # Forward unparsed command-specific arguments (e.g. agent --llm-local).
        args.command_args = list(getattr(args, 'command_args', [])) + unknown_args
    return args


def _resolve_server_api_key(cli_value):
    k = (cli_value or "").strip()
    if k:
        return k
    return (os.environ.get("KITTYSPLOIT_API_KEY") or "").strip() or None


def main():
    args = parse_arguments()

    # Initialize the framework.
    framework = Framework()

    # Display the version and exit if requested
    if args.version:
        print_info(f"KittySploit v{framework.version}")
        return

    # Check charter acceptance for all modes except --version
    if not framework.check_charter_acceptance():
        print_info("FIRST STARTUP OF KITTYSPLOIT")
        if not framework.prompt_charter_acceptance():
            print_error("[!] Charter not accepted. Stopping framework.")
            return

    # Avoid startup overhead for autonomous scanning commands: Zig is only
    # required for specific payload compilation paths and can be checked on-demand.
    command_name = str(getattr(args, "command", "") or "").lower()
    skip_zig_startup_check = command_name in ("agent", "scanner")
    if not skip_zig_startup_check:
        try:
            from core.lib.compiler.zig_installer import install_zig_if_needed
            print_info("Checking Zig compiler installation...")
            if install_zig_if_needed():
                print_success("Zig compiler is ready!")
            else:
                print_warning("Zig compiler installation failed or was cancelled.")
                print_info("Zig will be automatically installed when needed, or you can install it manually.")
        except Exception as e:
            print_warning(f"Could not check Zig compiler installation: {e}")
            print_info("Zig will be automatically installed when needed.")

    # Handle encryption setup/loading for RPC and API modes only
    # CLI mode handles encryption in interfaces/cli.py
    if args.rpc or args.api:
        if not framework.is_encryption_initialized():
            print_info("Setting up encryption for sensitive data protection...")
            if not framework.initialize_encryption():
                print_error("Failed to initialize encryption. Stopping framework.")
                return
        else:
            # Load existing encryption
            if not framework.load_encryption():
                print_error("Failed to load encryption. Stopping framework.")
                return

    # Start the RPC server if requested
    if args.rpc:
        try:
            api_key = _resolve_server_api_key(getattr(args, "api_key", None))
            if not api_key:
                print_error("RPC server requires --api-key or KITTYSPLOIT_API_KEY environment variable.")
                return
            print_info(f"Starting RPC server on {args.rpc_host}:{args.rpc_port}...")
            rpc_server = RpcServer(framework, host=args.rpc_host, port=args.rpc_port, api_key=api_key)
            rpc_server.start()
            return
        except ImportError:
            print_error("Error: RPC server module not found")
            return
        except Exception as e:
            print_error(f"Error starting RPC server: {str(e)}")
            return

    # Start the API server if requested
    if args.api:
        try:
            api_key = _resolve_server_api_key(getattr(args, "api_key", None))
            if not api_key:
                print_error("API server requires --api-key or KITTYSPLOIT_API_KEY environment variable.")
                return
            print_info(f"Starting API server on {args.api_host}:{args.api_port}...")
            api_server = ApiServer(framework, host=args.api_host, port=args.api_port, api_key=api_key)
            api_server.start()
            return
        except ImportError:
            print_error("Error: API server module not found")
            return
        except Exception as e:
            print_error(f"Error starting API server: {str(e)}")
            return

    # Direct command mode (e.g. kittysploit agent target.com)
    if args.command:
        session = Session()
        output_handler = OutputHandler()
        command_registry = CommandRegistry(framework, session, output_handler)
        ok = command_registry.execute_command(args.command, args.command_args, framework=framework)
        if not ok:
            print_error(f"Command '{args.command}' failed")
        return

    # Mode CLI interactif
    if not args.module:
        quiet = bool(args.quiet)
        auto_started_proxy = False
        proxy_manager = None

        if args.proxy:
            proxy_manager = getattr(framework, 'proxy_manager', None)
            if proxy_manager is None:
                proxy_manager = ProxyManager(verbose=args.proxy_verbose)
                framework.proxy_manager = proxy_manager
            else:
                proxy_manager.verbose = bool(args.proxy_verbose)

            if proxy_manager.is_running:
                print_warning(
                    f"Proxy is already running on {proxy_manager.proxy_host}:{proxy_manager.proxy_port} ({proxy_manager.mode.upper()})"
                )
            else:
                if not proxy_manager.start(
                    args.proxy_host,
                    args.proxy_port,
                    mode=args.proxy_mode,
                    socks_username=args.proxy_socks_user,
                    socks_password=args.proxy_socks_pass
                ):
                    print_error("Failed to start integrated proxy. Aborting interactive CLI startup.")
                    return
                auto_started_proxy = True
                print_success(
                    f"Integrated {args.proxy_mode.upper()} proxy started on {args.proxy_host}:{args.proxy_port}"
                )

        cli = CLI(framework, quiet)
        try:
            cli.start()
        finally:
            if auto_started_proxy and proxy_manager and proxy_manager.is_running:
                proxy_manager.stop()
                print_info("Integrated proxy stopped.")
        return

    # Non-interactive mode with a specified module
    try:
        module = framework.load_module(args.module)

        # Set the options if provided
        if args.options:
            options = args.options.split(',')
            for option in options:
                if '=' in option:
                    key, value = option.split('=', 1)
                    module.set_option(key.strip(), value.strip())

        # Execute the module if requested
        if args.execute:
            if not module.check_options():
                print_error("Error: Missing required options. Use interactive mode to see which options are required.")
                return

            result = module.run()
            if result:
                print_success("Module execution completed successfully.")
            else:
                print_error("Module execution failed.")

    except Exception as e:
        print_error(f"Error: {str(e)}")
