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
import time
from core.framework.framework import Framework
from core.output_handler import print_info, print_success, print_error, print_warning, print_debug, print_status
from interfaces.api_server import ApiServer

def parse_arguments():
    parser = argparse.ArgumentParser(description='KittySploit API Server')
    parser.add_argument('-H', '--host', default='127.0.0.1', help='Host to bind the API server (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Port for the API server (default: 5000)')
    parser.add_argument('-k', '--api-key', help='API key for authentication (optional)')
    parser.add_argument('-m', '--master-key', help='Master key to unlock the database (optional, will prompt if not provided)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    try:
        # Initialiser le framework
        framework = Framework()
        
        # Check charter acceptance
        if not framework.check_charter_acceptance():
            print_info("First startup of KittySploit")
            if not framework.prompt_charter_acceptance():
                print_error("Charter not accepted. Stopping framework.")
                return 1
        
        # Handle encryption setup/loading for database unlock
        if not framework.is_encryption_initialized():
            print_info("Setting up encryption for sensitive data protection...")
            if not framework.initialize_encryption(args.master_key):
                print_error("Failed to initialize encryption. Stopping framework.")
                return 1
        else:
            # Load existing encryption with master key to unlock database
            if not framework.load_encryption(args.master_key):
                print_error("Failed to load encryption. Database remains locked. Stopping framework.")
                return 1
        
        # Créer et démarrer le serveur API
        print_success(f"Starting API server on {args.host}:{args.port}...")
        if args.api_key:
            print_success("API authentication enabled")
            
        api_server = ApiServer(
            framework=framework,
            host=args.host,
            port=args.port,
            api_key=args.api_key
        )
        
        # Démarrer le serveur
        api_server.start()
        
        # Garder le script actif pour que le serveur continue de tourner
        print_info("API server is running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print_info("\nShutting down API server...")
            api_server.stop()
        
    except Exception as e:
        print_error(f"Error: {str(e)}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main()) 