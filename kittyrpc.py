#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os

# Add project root to path (before importing venv_helper)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure we're using the project's venv if it exists
from core.utils.venv_helper import ensure_venv
ensure_venv(__file__)

import argparse
import logging
import signal
from core.framework.framework import Framework
from interfaces.rpc_server import RpcServer
from core.output_handler import print_info, print_success, print_error, print_warning, print_debug, print_status

def setup_logging(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def parse_arguments():
    parser = argparse.ArgumentParser(description='KittySploit RPC Server')
    parser.add_argument('-H', '--host', default='127.0.0.1', help='Host to bind the RPC server (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=8888, help='Port for the RPC server (default: 8888)')
    parser.add_argument('-k', '--api-key', help='API key for authentication (optional)')
    parser.add_argument('-m', '--master-key', help='Master key to unlock the database (optional, will prompt if not provided)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    return parser.parse_args()

def main():
    args = parse_arguments()
    setup_logging(args.debug)
    
    rpc_server = None
    
    def signal_handler(signum, frame):
        """Handle interrupt signals (Ctrl+C)"""
        print_info("Interrupt received, shutting down RPC server...")
        if rpc_server:
            rpc_server.stop()
        sys.exit(0)
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        framework = Framework()
        
        if not framework.check_charter_acceptance():
            print_info("First startup of KittySploit")
            if not framework.prompt_charter_acceptance():
                print_error("Charter not accepted. Stopping framework.")
                return 1
        
        if not framework.is_encryption_initialized():
            print_info("Setting up encryption for sensitive data protection...")
            if not framework.initialize_encryption(args.master_key):
                print_error("Failed to initialize encryption. Stopping framework.")
                return 1
        else:
            if not framework.load_encryption(args.master_key):
                print_error("Failed to load encryption. Database remains locked. Stopping framework.")
                return 1
        
        print_success(f"Starting RPC server on {args.host}:{args.port}...")
        if args.api_key:
            print_success("RPC authentication enabled")
        
        print_info("Press Ctrl+C to stop the server")
            
        rpc_server = RpcServer(
            framework=framework,
            host=args.host,
            port=args.port,
            api_key=args.api_key
        )
        
        rpc_server.start()
        
        # Keep the main thread alive and responsive to interrupts
        try:
            while rpc_server.running:
                import time
                time.sleep(0.1)  # Shorter sleep for better responsiveness
        except KeyboardInterrupt:
            print_info("Keyboard interrupt received")
        finally:
            print_info("Shutting down RPC server...")
            if rpc_server:
                rpc_server.stop()
            
    except KeyboardInterrupt:
        print_error("Interrupt received during startup")
        if rpc_server:
            rpc_server.stop()
        return 0
    except Exception as e:
        print_error(f"Error: {str(e)}")
        if rpc_server:
            rpc_server.stop()
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main()) 