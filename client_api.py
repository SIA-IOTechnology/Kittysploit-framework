#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import time
import argparse
import sys
import os
from datetime import datetime
from colorama import init, Fore, Style
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style as PromptStyle
import uuid
import getpass

init(autoreset=True)

class KittyApiClient:
    """ KittySploit API Client"""
    
    def __init__(self, host='127.0.0.1', port=5000, api_key=None):
        """Initialize the API client
        
        Args:
            host (str): API server address
            port (int): API server port
            api_key (str): API key for authentication
        """
        self.base_url = f"http://{host}:{port}/api"
        self.api_key = api_key
        self.session = requests.Session()
        
        self.prompt_style = PromptStyle.from_dict({
            'prompt': 'ansired bold',
            'completion-menu.completion': 'bg:#008800 #ffffff',
            'completion-menu.completion.current': 'bg:#00aaaa #000000',
        })
        
        # Commands available
        self.commands = {
            'help': self.show_help,
            'modules': self.list_modules,
            'use': self.use_module,
            'info': self.show_module_info,
            'set': self.set_option,
            'options': self.show_options,
            'run': self.run_module,
            'sessions': self.list_sessions,
            'interpreter': self.start_interpreter,
            'market': self.market_command,
            'exit': self.exit_client
        }
        
        # Client state
        self.current_module = None
        self.module_options = {}
        self.running = True
        
        # Default headers configuration
        self.headers = {}
        if api_key:
            self.headers['X-API-Key'] = api_key
    
    def get_prompt(self):
        """Return the prompt based on the context"""
        if self.current_module:
            return f"kittyapi({self.current_module})> "
        return "kittyapi> "
    
    def show_help(self, *args):
        """Show the help for the commands"""
        print(f"\n{Fore.CYAN}=== KittySploit API Client Help ===")
        print(f"{Fore.WHITE}Available commands:")
        print(f"  {Fore.GREEN}help{Fore.WHITE}        - Show this help message")
        print(f"  {Fore.GREEN}modules{Fore.WHITE}     - List available modules")
        print(f"  {Fore.GREEN}use <module>{Fore.WHITE} - Select a module to use")
        print(f"  {Fore.GREEN}info{Fore.WHITE}        - Show current module info")
        print(f"  {Fore.GREEN}options{Fore.WHITE}     - Show module options")
        print(f"  {Fore.GREEN}set <option> <value>{Fore.WHITE} - Set module option")
        print(f"  {Fore.GREEN}run{Fore.WHITE}         - Run current module")
        print(f"  {Fore.GREEN}sessions{Fore.WHITE}    - List active sessions")
        print(f"  {Fore.GREEN}interpreter{Fore.WHITE} - Start Python interpreter")
        print(f"  {Fore.GREEN}market{Fore.WHITE}      - Access the extension marketplace")
        print(f"  {Fore.GREEN}exit{Fore.WHITE}        - Exit the client\n")
    
    def list_modules(self, *args):
        """List all available modules"""
        try:
            response = self.session.get(f"{self.base_url}/modules", headers=self.headers)
            if response.status_code == 200:
                modules = response.json()
                print(f"\n{Fore.CYAN}=== Available Modules ===")
                for module_name, info in modules.items():
                    description = info.get('description', 'No description available')
                    print(f"{Fore.GREEN}{module_name}{Fore.WHITE} - {description}")
                print()
            else:
                print(f"{Fore.RED}[!] Error: {response.text}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def use_module(self, *args):
        if not args:
            print(f"{Fore.RED}[!] Usage: use <module_name>")
            return
        
        module_name = args[0]
        try:
            response = self.session.get(f"{self.base_url}/modules/{module_name}", headers=self.headers)
            if response.status_code == 200:
                module_info = response.json()
                self.current_module = module_name
                self.module_options = module_info.get('options', {})
                print(f"{Fore.GREEN}[+] Using module: {module_name}")
            else:
                print(f"{Fore.RED}[!] Error: {response.text}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def show_module_info(self, *args):
        """Show the information of the current module"""
        if not self.current_module:
            print(f"{Fore.RED}[!] No module selected")
            return
        
        try:
            response = self.session.get(f"{self.base_url}/modules/{self.current_module}", headers=self.headers)
            if response.status_code == 200:
                info = response.json()['info']
                print(f"\n{Fore.CYAN}=== Module Information ===")
                print(f"{Fore.WHITE}Name: {Fore.GREEN}{info.get('name', 'N/A')}")
                print(f"{Fore.WHITE}Description: {info.get('description', 'N/A')}")
                print(f"{Fore.WHITE}Author: {info.get('author', 'N/A')}")
                print(f"{Fore.WHITE}References:")
                for ref in info.get('references', []):
                    print(f"  - {ref}")
                print()
            else:
                print(f"{Fore.RED}[!] Error: {response.text}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def set_option(self, *args):
        if not self.current_module:
            print(f"{Fore.RED}[!] No module selected")
            return
        
        if len(args) < 2:
            print(f"{Fore.RED}[!] Usage: set <option_name> <value>")
            return
        
        option_name = args[0]
        option_value = ' '.join(args[1:])
        
        if option_name in self.module_options:
            self.module_options[option_name] = option_value
            print(f"{Fore.GREEN}[+] Set {option_name} => {option_value}")
        else:
            print(f"{Fore.RED}[!] Invalid option: {option_name}")
    
    def show_options(self, *args):
        """Show the options of the current module"""
        if not self.current_module:
            print(f"{Fore.RED}[!] No module selected")
            return
        
        print(f"\n{Fore.CYAN}=== Module Options ===")
        print(f"{'Name':<20} {'Required':<10} {'Value':<20} {'Description'}")
        print("="*70)
        
        for name, info in self.module_options.items():
            required = info.get('required', False)
            value = info.get('value', '')
            description = info.get('description', '')
            print(f"{Fore.GREEN}{name:<20}{Fore.WHITE} {str(required):<10} {str(value):<20} {description}")
        print()
    
    def run_module(self, *args):
        if not self.current_module:
            print(f"{Fore.RED}[!] No module selected")
            return
        
        try:
            response = self.session.post(
                f"{self.base_url}/modules/{self.current_module}/run",
                json={'options': self.module_options},
                headers=self.headers
            )
            
            if response.status_code == 200:
                result = response.json()
                client_id = result.get('client_id')
                print(f"{Fore.GREEN}[+] Module started. Client ID: {client_id}")
                self._stream_output(client_id)
            else:
                print(f"{Fore.RED}[!] Error: {response.text}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def _stream_output(self, client_id):
        """Retrieve and display the output continuously"""
        try:
            while True:
                response = self.session.get(f"{self.base_url}/output/{client_id}", headers=self.headers)
                if response.status_code == 200:
                    outputs = response.json()
                    for output in outputs:
                        output_type = output.get('type', 'unknown')
                        text = output.get('text', '')
                        timestamp = datetime.fromtimestamp(output.get('timestamp', time.time()))
                        
                        if output_type == 'error':
                            print(f"{Fore.RED}[{timestamp:%H:%M:%S}] {text}")
                        elif output_type == 'result':
                            print(f"{Fore.GREEN}[{timestamp:%H:%M:%S}] {text}")
                        else:
                            print(f"{Fore.WHITE}[{timestamp:%H:%M:%S}] {text}")
                        
                    if not outputs:
                        break
                        
                time.sleep(0.1)
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[*] Output streaming interrupted")
    
    def list_sessions(self, *args):
        """List the active sessions"""
        try:
            response = self.session.get(f"{self.base_url}/sessions", headers=self.headers)
            if response.status_code == 200:
                sessions = response.json()
                print(f"\n{Fore.CYAN}=== Active Sessions ===")
                for session_id, info in sessions.items():
                    print(f"{Fore.GREEN}Session {session_id}:")
                    for key, value in info.items():
                        print(f"  {Fore.WHITE}{key}: {value}")
                print()
            else:
                print(f"{Fore.RED}[!] Error: {response.text}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def start_interpreter(self, *args):
        print(f"{Fore.CYAN}=== KittySploit Interactive Python Session ===")
        print(f"{Fore.WHITE}Type 'exit' to return to the API client\n")
        
        session_id = str(uuid.uuid4())
        session_headers = self.headers.copy()
        session_headers['X-Session-ID'] = session_id
        
        interpreter_session = PromptSession(
            style=self.prompt_style,
            message=lambda: f"ipk >>> "
        )
        
        while True:
            try:
                code = interpreter_session.prompt().strip()
                
                if code.lower() in ('exit', 'quit'):
                    break
                
                if not code:
                    continue
                
                try:
                    response = self.session.post(
                        f"{self.base_url}/interpreter/execute",
                        json={'code': code},
                        headers=session_headers,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        
                        if result.get('output'):
                            print(result['output'].rstrip())
                            
                        if result.get('error'):
                            print(f"{Fore.RED}{result['error'].rstrip()}{Fore.RESET}")
                            
                        if result.get('result'):
                            print(f"{Fore.GREEN}{result['result']}{Fore.RESET}")
                            
                    else:
                        error_msg = response.json().get('error', response.text)
                        print(f"{Fore.RED}[!] Error: {error_msg}{Fore.RESET}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"{Fore.RED}[!] Connection error: {str(e)}{Fore.RESET}")
                    
            except KeyboardInterrupt:
                print("\n")
                continue
            except EOFError:
                break
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {str(e)}{Fore.RESET}")
        
        print(f"{Fore.YELLOW}[*] Returning to API client...{Fore.RESET}")
    
    def market_command(self, *args):
        """Marketplace command - access to the extension registry"""
        # Vérifier si un compte est enregistré
        config = self._load_config()
        has_account = config and config.get('api_key')
        
        # If no account and no argument, offer registration/login
        if not has_account and not args:
            print(f"\n{Fore.YELLOW}[!] No account registered. You can browse extensions, but need an account to download/install.")
            choice = input(f"{Fore.WHITE}Would you like to create an account or login? (register/login/skip): ").strip().lower()
            
            if choice == 'register':
                self._register_account()
                # After registration, show the help
                self._show_marketplace_help()
            elif choice == 'login':
                self._login_account()
                # After login, show the help
                self._show_marketplace_help()
            elif choice == 'skip':
                # Show the help even without an account
                self._show_marketplace_help()
            else:
                print(f"{Fore.RED}[!] Invalid choice")
                return
        # If no account but with arguments, allow the list/info
        elif not has_account and args:
            if args[0] == 'list':
                self._list_marketplace_extensions()
            elif args[0] == 'info' and len(args) > 1:
                self._show_extension_info(args[1])
            else:
                print(f"{Fore.RED}[!] This action requires an account. Use 'market' to register/login.")
        # If account registered or arguments provided
        else:
            if args and args[0] == 'list':
                self._list_marketplace_extensions()
            elif args and args[0] == 'info' and len(args) > 1:
                self._show_extension_info(args[1])
            elif args and args[0] == 'install' and len(args) > 1:
                self._install_extension(args[1])
            else:
                self._show_marketplace_help()
    
    def _show_marketplace_help(self):
        """Show the help for the marketplace"""
        print(f"\n{Fore.CYAN}=== Extension Marketplace ===")
        print(f"{Fore.WHITE}Available commands:")
        print(f"  {Fore.GREEN}market list{Fore.WHITE}              - List all available extensions")
        print(f"  {Fore.GREEN}market info <extension_id>{Fore.WHITE} - Show extension details")
        print(f"  {Fore.GREEN}market install <extension_id>{Fore.WHITE} - Install an extension (requires account)")
        print()
    
    def _list_marketplace_extensions(self):
        """List the extensions of the marketplace"""
        try:
            # No authentication required to list
            response = self.session.get(f"{self.base_url}/registry/extensions")
            
            if response.status_code == 200:
                result = response.json()
                extensions = result.get('extensions', [])
                total = result.get('total', 0)
                
                print(f"\n{Fore.CYAN}=== Available Extensions ({total} total) ===")
                if not extensions:
                    print(f"{Fore.YELLOW}No extensions found")
                    return
                
                print(f"\n{Fore.WHITE}{'ID':<30} {'Name':<30} {'Type':<15} {'Price':<10} {'Publisher'}")
                print("=" * 100)
                
                for ext in extensions:
                    ext_id = ext.get('id', 'N/A')
                    name = ext.get('name', 'N/A')
                    ext_type = ext.get('type', 'N/A')
                    price = ext.get('price', 0.0)
                    currency = ext.get('currency', 'USD')
                    publisher = ext.get('publisher', {}).get('name', 'N/A') if isinstance(ext.get('publisher'), dict) else ext.get('publisher', 'N/A')
                    is_free = ext.get('is_free', True)
                    
                    price_str = f"{Fore.GREEN}FREE{Fore.WHITE}" if is_free else f"{price} {currency}"
                    print(f"{Fore.GREEN}{ext_id:<30}{Fore.WHITE} {name:<30} {ext_type:<15} {price_str:<10} {publisher}")
                
                print()
            else:
                error = response.json().get('error', response.text) if response.headers.get('content-type', '').startswith('application/json') else response.text
                print(f"{Fore.RED}[!] Error listing extensions: {error}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def _show_extension_info(self, extension_id):
        """Show the details of an extension"""
        try:
            # No authentication required to see the details
            response = self.session.get(f"{self.base_url}/registry/extensions/{extension_id}")
            
            if response.status_code == 200:
                ext = response.json()
                print(f"\n{Fore.CYAN}=== Extension Details ===")
                print(f"{Fore.WHITE}ID: {Fore.GREEN}{ext.get('id')}")
                print(f"{Fore.WHITE}Name: {Fore.GREEN}{ext.get('name')}")
                print(f"{Fore.WHITE}Description: {Fore.WHITE}{ext.get('description', 'N/A')}")
                print(f"{Fore.WHITE}Type: {Fore.GREEN}{ext.get('type')}")
                print(f"{Fore.WHITE}Publisher: {Fore.GREEN}{ext.get('publisher', {}).get('name', 'N/A') if isinstance(ext.get('publisher'), dict) else ext.get('publisher', 'N/A')}")
                print(f"{Fore.WHITE}Price: {Fore.GREEN}{'FREE' if ext.get('is_free') else f\"{ext.get('price')} {ext.get('currency')}\"}")
                print(f"{Fore.WHITE}License: {Fore.GREEN}{ext.get('license_type', 'N/A')}")
                
                versions = ext.get('versions', [])
                if versions:
                    print(f"\n{Fore.WHITE}Versions:")
                    for v in versions:
                        latest = " (latest)" if v.get('is_latest') else ""
                        print(f"  {Fore.GREEN}{v.get('version')}{latest}{Fore.WHITE} - Downloads: {v.get('download_count', 0)}")
                print()
            else:
                error = response.json().get('error', response.text) if response.headers.get('content-type', '').startswith('application/json') else response.text
                print(f"{Fore.RED}[!] Error: {error}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def _install_extension(self, extension_id):
        """Install an extension (requires an account)"""
        config = self._load_config()
        if not config or not config.get('api_key'):
            print(f"{Fore.RED}[!] You need to be logged in to install extensions")
            print(f"{Fore.YELLOW}Use 'market' command and choose 'login' or 'register'")
            return
        
        # Update the headers with the API key
        headers = self.headers.copy()
        if not headers.get('X-API-Key'):
            headers['X-API-Key'] = config.get('api_key')
        
        try:
            print(f"{Fore.CYAN}[*] Downloading extension {extension_id}...")
            response = self.session.get(
                f"{self.base_url}/registry/extensions/{extension_id}/download",
                headers=headers,
                stream=True
            )
            
            if response.status_code == 200:
                # Save the file
                filename = f"{extension_id}.kext"
                with open(filename, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                print(f"{Fore.GREEN}[+] Extension downloaded: {filename}")
                print(f"{Fore.YELLOW}[!] To install, use the framework's extension installation command")
            else:
                error = response.json().get('error', response.text) if response.headers.get('content-type', '').startswith('application/json') else response.text
                print(f"{Fore.RED}[!] Error downloading extension: {error}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def _register_account(self):
        """Registration of a new account on the registry"""
        try:
            print(f"\n{Fore.CYAN}=== Registry Account Registration ===")
            email = input(f"{Fore.WHITE}Email: ").strip()
            if not email:
                print(f"{Fore.RED}[!] Email is required")
                return
            
            username = input(f"{Fore.WHITE}Username (optional): ").strip() or None
            password = getpass.getpass(f"{Fore.WHITE}Password: ")
            if not password:
                print(f"{Fore.RED}[!] Password is required")
                return
            
            password_confirm = getpass.getpass(f"{Fore.WHITE}Confirm password: ")
            if password != password_confirm:
                print(f"{Fore.RED}[!] Passwords do not match")
                return
            
            # Send the registration request
            response = self.session.post(
                f"{self.base_url}/auth/register",
                json={
                    "email": email,
                    "password": password,
                    "username": username
                }
            )
            
            if response.status_code == 201:
                result = response.json()
                api_key = result.get('api_key')
                user = result.get('user', {})
                print(f"\n{Fore.GREEN}[+] Account created successfully!")
                print(f"{Fore.WHITE}User ID: {user.get('id')}")
                print(f"{Fore.WHITE}Email: {user.get('email')}")
                
                # Save automatically
                self._save_account_info(api_key, user.get('email'), user.get('username'))
                
                # Update the API key of the client
                self.api_key = api_key
                self.headers['X-API-Key'] = api_key
                
                print(f"{Fore.GREEN}[+] Account information saved")
            else:
                error = response.json().get('error', response.text) if response.headers.get('content-type', '').startswith('application/json') else response.text
                print(f"{Fore.RED}[!] Registration failed: {error}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def _login_account(self):
        """Login to a registry account"""
        try:
            print(f"\n{Fore.CYAN}=== Registry Account Login ===")
            email = input(f"{Fore.WHITE}Email: ").strip()
            if not email:
                print(f"{Fore.RED}[!] Email is required")
                return
            
            password = getpass.getpass(f"{Fore.WHITE}Password: ")
            if not password:
                print(f"{Fore.RED}[!] Password is required")
                return
            
            # Send the login request
            response = self.session.post(
                f"{self.base_url}/auth/login",
                json={
                    "email": email,
                    "password": password
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                api_key = result.get('api_key')
                user = result.get('user', {})
                print(f"\n{Fore.GREEN}[+] Login successful!")
                print(f"{Fore.WHITE}User ID: {user.get('id')}")
                print(f"{Fore.WHITE}Email: {user.get('email')}")
                if user.get('username'):
                    print(f"{Fore.WHITE}Username: {user.get('username')}")
                
                # Save automatically
                self._save_account_info(api_key, user.get('email'), user.get('username'))
                
                # Update the API key of the client
                self.api_key = api_key
                self.headers['X-API-Key'] = api_key
                
                print(f"{Fore.GREEN}[+] Account information saved")
            else:
                error = response.json().get('error', response.text) if response.headers.get('content-type', '').startswith('application/json') else response.text
                print(f"{Fore.RED}[!] Login failed: {error}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def _load_config(self):
        """Load the configuration from the file"""
        try:
            config_file = os.path.join(os.path.expanduser("~"), ".kittysploit", "registry_config.json")
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return None
    
    def _save_account_info(self, api_key, email, username=None):
        """Save the account information in a configuration file"""
        try:
            config_dir = os.path.join(os.path.expanduser("~"), ".kittysploit")
            os.makedirs(config_dir, exist_ok=True)
            
            config_file = os.path.join(config_dir, "registry_config.json")
            config = {}
            
            # Load the existing config if it exists
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
            
            # Update the information
            config['api_key'] = api_key
            config['registry_url'] = self.base_url.replace('/api', '')
            config['email'] = email
            if username:
                config['username'] = username
            
            # Save the information
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving account info: {str(e)}")
            return False
    
    
    def exit_client(self, *args):
        """Exit the client"""
        print(f"{Fore.YELLOW}[*] Exiting...")
        self.running = False
    
    def run(self):
        """Start the interactive client"""
        print(f"{Fore.CYAN}=== KittySploit API Client ===")
        print(f"{Fore.WHITE}Type 'help' for available commands\n")
        
        command_completer = WordCompleter(list(self.commands.keys()))
        session = PromptSession(completer=command_completer, style=self.prompt_style)
        
        while self.running:
            try:

                command_line = session.prompt(self.get_prompt())
                command_parts = command_line.strip().split()
                
                if not command_parts:
                    continue
                
                command = command_parts[0].lower()
                args = command_parts[1:]
                
                if command in self.commands:
                    self.commands[command](*args)
                else:
                    print(f"{Fore.RED}[!] Unknown command: {command}")
                    
            except KeyboardInterrupt:
                print("\n")
                continue
            except EOFError:
                break
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {str(e)}")
        
        print(f"{Fore.CYAN}Goodbye!")


def parse_arguments():
    """Parse the arguments from the command line"""
    parser = argparse.ArgumentParser(description='KittySploit API Client')
    
    parser.add_argument('-H', '--host', default='127.0.0.1', help='API server host (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=5000, help='API server port (default: 5000)')
    parser.add_argument('-k', '--api-key', help='API key for authentication')
    
    return parser.parse_args()


def load_api_key_from_config():
    """Load the API key from the configuration file"""
    try:
        config_file = os.path.join(os.path.expanduser("~"), ".kittysploit", "registry_config.json")
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                return config.get('api_key')
    except Exception:
        pass
    return None


def main():
    args = parse_arguments()
    
    # Load the API key from the config if not provided
    api_key = args.api_key or load_api_key_from_config()
    
    try:
        client = KittyApiClient(
            host=args.host,
            port=args.port,
            api_key=api_key
        )
        client.run()
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {str(e)}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
