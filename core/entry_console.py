#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Entry point for KittySploit console (CLI). Used by kittyconsole.py and by the
pip-installed 'kittysploit' command.
"""

import argparse
from core.framework.framework import Framework
from interfaces.cli import CLI
from interfaces.rpc_server import RpcServer
from interfaces.api_server import ApiServer
from core.output_handler import print_info, print_success, print_error, print_warning, print_debug, print_status


def parse_arguments():
    parser = argparse.ArgumentParser(description='KittySploit - A modular penetration testing framework')
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
    parser.add_argument('--api-key', help='API key for authentication (optional)')

    return parser.parse_args()


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

    # Check and install Zig compiler if needed (non-blocking)
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
            print_info(f"Starting RPC server on {args.rpc_host}:{args.rpc_port}...")
            rpc_server = RpcServer(framework, host=args.rpc_host, port=args.rpc_port)
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
            print_info(f"Starting API server on {args.api_host}:{args.api_port}...")
            api_server = ApiServer(framework, host=args.api_host, port=args.api_port, api_key=args.api_key)
            api_server.start()
            return
        except ImportError:
            print_error("Error: API server module not found")
            return
        except Exception as e:
            print_error(f"Error starting API server: {str(e)}")
            return

    # Mode CLI interactif
    if not args.module:
        quiet = bool(args.quiet)
        cli = CLI(framework, quiet)
        cli.start()
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
