#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import code
import inspect
import sys
from typing import Any, Dict, List, Optional
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import Style
from core.output_handler import print_info, print_success, print_error, print_warning, print_debug
try:
    from pygments.lexers.python import PythonLexer
except:
    pass

# Import the appropriate readline implementation
if sys.platform == 'win32':
    try:
        import pyreadline3 as readline
    except ImportError:
        print("[!] Warning: pyreadline3 not found. Tab completion may not work properly.")
        readline = None
else:
    try:
        import readline
    except ImportError:
        print("[!] Warning: readline not found. Tab completion may not work properly.")
        readline = None

class KittyInterpreter(code.InteractiveInterpreter):
    """
    Interactive Python interpreter customized for KittySploit framework
    """
    
    def __init__(self, framework, locals: Optional[Dict[str, Any]] = None):
        """
        Initialize the interpreter with framework access
        
        Args:
            framework: KittySploit framework instance
            locals: Optional dictionary of local variables
        """
        # Initialize base interpreter
        if locals is None:
            locals = {}
        
        # Add framework components to locals
        self.framework = framework
        locals.update({
            'framework': framework,
            'module_loader': framework.module_loader,
            'workspace_manager': framework.workspace_manager,
            'db_manager': framework.db_manager,
            'current_module': getattr(framework, 'current_module', None),
            'current_workspace': framework.workspace_manager.get_current_workspace(),
            # Helper functions
            'print_info': self._print_info,
            'print_success': self._print_success,
            'print_error': self._print_error,
            'print_warning': self._print_warning
        })
        
        super().__init__(locals)
        
        # Setup key bindings for Tab handling
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.keys import Keys
        
        self.kb = KeyBindings()
        
        # Make Tab insert spaces for indentation instead of triggering completion
        @self.kb.add(Keys.Tab)
        def _(event):
            # Insert 4 spaces for indentation
            event.app.current_buffer.insert_text('    ')
        
        # Setup prompt toolkit
        self.session = PromptSession(
            lexer=PygmentsLexer(PythonLexer),
            style=self._get_style(),
            completer=self._create_completer(),
            key_bindings=self.kb,  # Use custom key bindings
            complete_while_typing=False  # Disable auto-completion while typing
        )
        
        # Command history
        self.history = []
        
        # Output redirection
        self.output_callbacks = {
            'stdout': [],
            'stderr': [],
            'result': []
        }
        
    def _get_style(self) -> Style:
        """Get the prompt style configuration"""
        return Style.from_dict({
            'prompt': 'ansired bold',
            'completion-menu.completion': 'bg:#008800 #ffffff',
            'completion-menu.completion.current': 'bg:#00aaaa #000000',
        })
        
    def _create_completer(self) -> WordCompleter:
        """Create command completer with framework-specific commands"""
        commands = [
            # Basic commands
            'modules', 'sessions', 'help', 'debug',
            'show', 'use', 'run', 'exit',
            # Framework components
            'framework', 'current_module', 'plugins',
            # Helper functions
            'generate_payload', 'encode_string',
            # Python builtins
            'print', 'dir', 'help', 'type'
        ]
        
        # Add module names
#        commands.extend(self.framework.modules.get_all_names())
        
        return WordCompleter(commands)
        
    def get_prompt(self) -> str:
        """Get the customized prompt string"""
        context = ""
        module = self.framework.get_current_module()
        if module:
            return f'kittypy({context}:{module.name})> '
        return f'kittypy({context})> '
        
    def runsource(self, source: str, filename: str = "<input>", symbol: str = "single") -> bool:
        """Execute source code with error handling"""
        try:
            # Add to history (only if not empty)
            if source.strip():
                self.history.append(source)
            
            # Execute code using the parent's runsource method
            # This handles multi-line blocks correctly
            return super().runsource(source, filename, symbol)
            
        except Exception as e:
            self.showtraceback()
            return False
            
    def showsyntaxerror(self, filename: Optional[str] = None, **kwargs) -> None:
        """Display syntax errors with custom formatting"""
        type, value, tb = sys.exc_info()
        sys.stderr.write(f'\033[91mSyntax Error: {str(value)}\033[0m\n')
        
    def showtraceback(self) -> None:
        """Display tracebacks with custom formatting and callbacks"""
        type, value, tb = sys.exc_info()
        error_msg = f'\033[91mError: {str(value)}\033[0m\n'
        for callback in self.output_callbacks['stderr']:
            callback(error_msg)
        sys.stderr.write(error_msg)
        
    def run(self) -> None:
        """Start the interactive interpreter"""
        banner = """
╔═══════════════════════════════════════════╗
║ KittyPy Interactive Interpreter           ║
║ Type 'help' for list of functions         ║
║ Use Ctrl+D or 'exit' to exit              ║
╚═══════════════════════════════════════════╝
"""
        print(banner)
        
        # Buffer for multi-line code blocks
        code_buffer = []
        
        while True:
            try:
                # Get input with prompt toolkit
                if code_buffer:
                    # Continuation prompt for multi-line blocks
                    prompt = "... "
                else:
                    prompt = self.get_prompt()
                
                code = self.session.prompt(prompt)
                
                # Handle exit command
                if code.strip() in ('exit', 'quit'):
                    break
                
                # Handle help command
                if code.strip() == 'help':
                    self.kitty_help()
                    continue
                
                # Skip empty lines unless we're in a multi-line block
                if not code.strip() and not code_buffer:
                    continue
                
                # Add line to buffer
                code_buffer.append(code)
                
                # Join all lines in buffer preserving structure
                full_code = '\n'.join(code_buffer)
                
                # Try to compile to check if we need more input
                try:
                    # Try to compile with 'exec' mode for multi-line blocks
                    # This allows proper handling of indented blocks
                    compile(full_code, '<input>', 'exec')
                    
                    # If compilation succeeds, execute the code
                    # Use 'exec' mode for multi-line blocks
                    self.runsource(full_code, symbol='exec')
                    code_buffer = []  # Clear buffer after execution
                    
                except SyntaxError as e:
                    # Check if we need more input (incomplete statement)
                    error_msg = str(e.msg) if hasattr(e, 'msg') else str(e)
                    if 'unexpected EOF while parsing' in error_msg or 'EOF' in error_msg:
                        # Continue reading more lines
                        continue
                    else:
                        # Real syntax error, execute to show error
                        self.runsource(full_code, symbol='exec')
                        code_buffer = []  # Clear buffer
                        
                except Exception:
                    # Other error, try to execute anyway
                    self.runsource(full_code, symbol='exec')
                    code_buffer = []  # Clear buffer
                
            except KeyboardInterrupt:
                print("\nKeyboardInterrupt")
                continue
            except EOFError:
                break
                
        print("\nExiting KittyPy...")
        
    # Helper Methods
    def generate_payload(self, payload_type: str, options: Optional[Dict] = None) -> bytes:
        """Generate a payload with the given options"""
        payload = self.framework.payloads.create(payload_type)
        if options:
            payload.set_options(options)
        return payload.generate()
        
    def encode_string(self, string: str, encoder: str = "default") -> str:
        """Encode a string using the specified encoder"""
        return self.framework.encoders.encode(string, encoder)
        
    def debug(self, obj: Any) -> None:
        """Print detailed object information"""
        print(f"\033[94mObject: {obj.__class__.__name__}\033[0m")
        print("\033[94mAttributes:\033[0m")
        for name, value in inspect.getmembers(obj):
            if not name.startswith('_'):
                print(f"  \033[92m{name}\033[0m: {value}")
                
    def _print_info(self, message):
        """Print info message"""
        from core.output_handler import print_info
        print_info(message)
    
    def _print_success(self, message):
        """Print success message"""
        from core.output_handler import print_success
        print_success(message)
    
    def _print_error(self, message):
        """Print error message"""
        from core.output_handler import print_error
        print_error(message)
    
    def _print_warning(self, message):
        """Print warning message"""
        from core.output_handler import print_warning
        print_warning(message)

    def kitty_help(self) -> None:
        """Display KittyPy specific help"""
        help_text = """
KittyPy Help
===========

Framework Access:
- framework          : Main framework instance
- module_loader      : Module loader for discovering and loading modules
- workspace_manager  : Workspace manager for database-driven workspaces
- db_manager         : Database manager
- current_module     : Currently selected module
- current_workspace  : Current workspace

Helper Functions:
- print_info(message)    : Print info message
- print_success(message) : Print success message
- print_error(message)   : Print error message
- print_warning(message) : Print warning message

Basic Commands:
- help()      : Show this help
- exit/quit   : Exit interpreter

Example Usage:
>>> module_loader.discover_modules()           # List all modules
>>> module = module_loader.load_module('auxiliary/example')  # Load module
>>> current_workspace.name                     # Show current workspace
>>> print_success('Hello from interpreter!')   # Print colored message
"""
        print(help_text)

    def add_output_callback(self, output_type: str, callback):
        """Add output callback for a specific type"""
        if output_type in self.output_callbacks:
            self.output_callbacks[output_type].append(callback)
            
    def remove_output_callback(self, output_type: str, callback):
        """Remove output callback"""
        if output_type in self.output_callbacks:
            self.output_callbacks[output_type].remove(callback)
            
    def write(self, data: str):
        """Override write to use output callbacks"""
        for callback in self.output_callbacks['stderr']:
            callback(data)
        return super().write(data)

# Utility functions
def start_interpreter(framework) -> None:
    """Start a new interpreter instance"""
    interpreter = KittyInterpreter(framework)
    interpreter.run() 