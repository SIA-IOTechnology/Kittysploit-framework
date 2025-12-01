#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import uuid
import xmlrpc.client
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from colorama import init, Fore, Style as ColorStyle
import sys

init(autoreset=True)

class KittyRpcClient:
    """Client RPC for KittySploit"""
    
    def __init__(self, host='127.0.0.1', port=5000, api_key=None):
        """Initialize the RPC client
        
        Args:
            host (str): RPC server address
            port (int): RPC server port
            api_key (str): API key for authentication
        """
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.api_key = api_key
        
        # Check the connection to the server
        if not self.check_server():
            print(f"{Fore.RED}[!] Cannot connect to RPC server at {self.base_url}")
            print(f"{Fore.YELLOW}[*] Make sure to start the server first with:")
            print(f"{Fore.WHITE}    python -m interfaces.rpc_server")
            sys.exit(1)
            
        self.server = xmlrpc.client.ServerProxy(self.base_url, allow_none=True)
        
        # prompt_toolkit configuration
        self.prompt_style = Style.from_dict({
            'prompt': 'ansired bold',
            'completion-menu.completion': 'bg:#008800 #ffffff',
            'completion-menu.completion.current': 'bg:#00aaaa #000000',
        })
        
        # Available commands
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
            'exit': self.exit_client
        }
        
        # Client state
        self.current_module = None
        self.module_options = {}
        self.running = True
    
    def check_server(self):
        """Check if the RPC server is accessible"""
        import socket
        try:
            # Create a TCP connection to test the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # 2 seconds timeout
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            return result == 0
        except:
            return False
            
    def safe_rpc_call(self, method, *args, **kwargs):
        """Make a RPC call with error handling
        
        Args:
            method: RPC method to call
            *args: Positional arguments
            **kwargs: Named arguments
            
        Returns:
            The result of the RPC call or None in case of error
        """
        try:
            if not self.check_server():
                print(f"{Fore.RED}[!] Lost connection to RPC server")
                print(f"{Fore.YELLOW}[*] Make sure the server is running and try again")
                return None
                
            return method(*args, **kwargs)
            
        except xmlrpc.client.Fault as e:
            print(f"{Fore.RED}[!] RPC Error: {str(e)}")
            return None
        except ConnectionRefusedError:
            print(f"{Fore.RED}[!] Connection refused. Is the server running?")
            return None
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
            return None
            
    def get_prompt(self):
        """Return the prompt based on the context"""
        if self.current_module:
            return f"kittyrpc({self.current_module})> "
        return "kittyrpc> "
    
    def show_help(self, *args):
        """Show the help for the commands"""
        print(f"\n{Fore.CYAN}=== KittySploit RPC Client Help ===")
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
        print(f"  {Fore.GREEN}exit{Fore.WHITE}        - Exit the client\n")
    
    def list_modules(self, *args):
        """List all available modules"""
        modules = self.safe_rpc_call(self.server.get_modules)
        if not modules:
            return
            
        # Organize the modules by category
        categories = {}
        for module_name, info in modules.items():
            # Extract the category from the module name (ex: 'misc/hello_world' -> 'misc')
            category = module_name.split('/')[0] if '/' in module_name else 'other'
            if category not in categories:
                categories[category] = []
            categories[category].append((module_name, info))
        
        # Show the modules by category
        print(f"\n{Fore.CYAN}=== Available Modules ===")
        for category in sorted(categories.keys()):
            print(f"\n{Fore.YELLOW}[{category.upper()}]")
            for module_name, info in sorted(categories[category]):
                name = info.get('name', module_name)
                description = info.get('description', 'No description available')
                author = info.get('author', 'Unknown')
                print(f"{Fore.GREEN}{module_name}{Fore.WHITE}")
                print(f"  Description: {description}")
                print(f"  Author: {author}")
                
                # Show the references if available
                references = info.get('references', [])
                if references:
                    print("  References:")
                    for ref in references:
                        print(f"    - {ref}")
        
        print(f"\n{Fore.CYAN}Total: {len(modules)} module(s) available\n")
    
    def use_module(self, *args):
        """Select a module to use"""
        if not args:
            print(f"{Fore.RED}[!] Usage: use <module_name>")
            return
        
        module_name = args[0]
        module_info = self.safe_rpc_call(self.server.get_module_info, module_name)
        if module_info:
            self.current_module = module_name
            self.module_options = module_info.get('options', {})
            print(f"{Fore.GREEN}[+] Using module: {module_name}")
    
    def show_module_info(self, *args):
        """Show the information of the current module"""
        if not self.current_module:
            print(f"{Fore.RED}[!] No module selected")
            return
        
        try:
            info = self.server.get_module_info(self.current_module)
            print(f"\n{Fore.CYAN}=== Module Information ===")
            print(f"{Fore.WHITE}Name: {Fore.GREEN}{info.get('name', 'N/A')}")
            print(f"{Fore.WHITE}Description: {info.get('description', 'N/A')}")
            print(f"{Fore.WHITE}Author: {info.get('author', 'N/A')}")
            print(f"{Fore.WHITE}References:")
            for ref in info.get('references', []):
                print(f"  - {ref}")
            print()
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def set_option(self, *args):
        """Define an option of the module"""
        if not self.current_module:
            print(f"{Fore.RED}[!] No module selected")
            return
        
        if len(args) < 2:
            print(f"{Fore.RED}[!] Usage: set <option_name> <value>")
            return
        
        option_name = args[0]
        option_value = ' '.join(args[1:])
        
        if option_name in self.module_options:
            try:
                self.server.set_module_option(self.current_module, option_name, option_value)
                print(f"{Fore.GREEN}[+] Set {option_name} => {option_value}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {str(e)}")
        else:
            print(f"{Fore.RED}[!] Invalid option: {option_name}")
    
    def show_options(self, *args):
        """Show the options of the current module"""
        if not self.current_module:
            print(f"{Fore.RED}[!] No module selected")
            return
        
        try:
            options = self.server.get_module_options(self.current_module)
            print(f"\n{Fore.CYAN}=== Module Options ===")
            print(f"{'Name':<20} {'Required':<10} {'Value':<20} {'Description'}")
            print("="*70)
            
            for name, info in options.items():
                required = info.get('required', False)
                value = info.get('value', '')
                description = info.get('description', '')
                print(f"{Fore.GREEN}{name:<20}{Fore.WHITE} {str(required):<10} {str(value):<20} {description}")
            print()
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def run_module(self, *args):
        """Run the current module"""
        if not self.current_module:
            print(f"{Fore.RED}[!] No module selected")
            return
        
        try:
            result = self.server.run_module(self.current_module)
            print(f"{Fore.GREEN}[+] Module result: {result}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def list_sessions(self, *args):
        """List the active sessions"""
        try:
            sessions = self.server.get_sessions()
            print(f"\n{Fore.CYAN}=== Active Sessions ===")
            for session_id, info in sessions.items():
                print(f"{Fore.GREEN}Session {session_id}:")
                for key, value in info.items():
                    print(f"  {Fore.WHITE}{key}: {value}")
            print()
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
    
    def start_interpreter(self, *args):
        """Start an interactive session with the Python interpreter"""
        print(f"{Fore.CYAN}=== KittySploit Interactive Python Session ===")
        print(f"{Fore.WHITE}Type 'exit' to return to the RPC client\n")
        
        # Create a unique session ID
        session_id = str(uuid.uuid4())
        
        interpreter_session = PromptSession(
            style=self.prompt_style,
            message=lambda: f"python>>> "
        )
        
        while True:
            try:
                # Get the Python code
                code = interpreter_session.prompt().strip()
                
                # Check if we quit the interpreter
                if code.lower() in ('exit', 'quit'):
                    break
                
                # Ignore empty lines
                if not code:
                    continue
                
                # Execute the code via RPC
                try:
                    result = self.server.execute_interpreter(code, session_id)
                    
                    # Show the standard output
                    if result.get('output'):
                        print(result['output'].rstrip())
                        
                    # Show the errors in red
                    if result.get('error'):
                        print(f"{Fore.RED}{result['error'].rstrip()}{Fore.RESET}")
                        
                    # Show the result in green
                    if result.get('result'):
                        print(f"{Fore.GREEN}{result['result']}{Fore.RESET}")
                        
                except xmlrpc.client.Fault as e:
                    print(f"{Fore.RED}[!] RPC Error: {str(e)}{Fore.RESET}")
                    
            except KeyboardInterrupt:
                print("\n")
                continue
            except EOFError:
                break
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {str(e)}{Fore.RESET}")
        
        print(f"{Fore.YELLOW}[*] Returning to RPC client...{Fore.RESET}")
    
    def exit_client(self, *args):
        """Exit the client"""
        print(f"{Fore.YELLOW}[*] Exiting...")
        self.running = False
    
    def run(self):
        """Start the interactive client"""
        print(f"{Fore.CYAN}=== KittySploit RPC Client ===")
        print(f"{Fore.WHITE}Type 'help' for available commands\n")
        
        # Create the completer
        command_completer = WordCompleter(list(self.commands.keys()))
        session = PromptSession(completer=command_completer, style=self.prompt_style)
        
        while self.running:
            try:
                # Get the command
                command_line = session.prompt(self.get_prompt())
                command_parts = command_line.strip().split()
                
                if not command_parts:
                    continue
                
                # Extract the command and the arguments
                command = command_parts[0].lower()
                args = command_parts[1:]
                
                # Execute the command
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
    parser = argparse.ArgumentParser(description='KittySploit RPC Client')
    
    # General arguments
    parser.add_argument('-H', '--host', default='127.0.0.1', help='RPC server host (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=5000, help='RPC server port (default: 8888)')
    parser.add_argument('-k', '--api-key', help='API key for authentication')
    
    return parser.parse_args()


def main():
    """Main function"""
    args = parse_arguments()
    
    try:
        client = KittyRpcClient(
            host=args.host,
            port=args.port,
            api_key=args.api_key
        )
        client.run()
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {str(e)}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
