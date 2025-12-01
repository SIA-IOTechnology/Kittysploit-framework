#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Help command implementation with improved organization and formatting
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_error, print_success, print_status, print_warning
from colorama import Fore, Style

class HelpCommand(BaseCommand):
    """Command to display help information"""
    
    # Command categories for better organization
    COMMAND_CATEGORIES = {
        'Core Commands': [
            'help', 'clear', 'exit', 'banner', 'status', 'interpreter'
        ],
        'Module Management': [
            'use', 'search', 'show', 'set', 'run', 'back', 'check', 'reload'
        ],
        'Workspace & Data': [
            'workspace', 'sync', 'host', 'vuln', 'history', 'portal'
        ],
        'Sessions & Shells': [
            'sessions', 'shell'
        ],
        'Docker Environments': [
            'environments'
        ],
        'Network & Discovery': [
            'network_discover', 'myip', 'proxy'
        ],
        'Development & Tools': [
            'edit', 'generate', 'pattern', 'syscall', 'compatible_payloads'
        ],
        'Jobs & Background': [
            'jobs'
        ],
        'Collaboration': [
            'collab_server', 'collab_connect', 'collab_chat', 'collab_disconnect',
            'collab_share_module', 'collab_sync_module', 'collab_edit_module', 'collab_sync_edit',
            'irc'
        ],
        'Advanced Features': [
            'debug', 'browser_server', 'demo', 'guardian', 'market',
            'plugin', 'reset', 'sound'
        ]
    }
    
    @property
    def name(self) -> str:
        return "help"
    
    @property
    def description(self) -> str:
        return "Display help information for commands"
    
    @property
    def usage(self) -> str:
        return "help [command_name]"
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the help command"""
        # Get command registry from kwargs if available
        if 'command_registry' in kwargs:
            self.command_registry = kwargs['command_registry']
        
        if len(args) == 0:
            # Show general help
            self._show_general_help()
        else:
            # Show help for specific command
            command_name = args[0]
            self._show_command_help(command_name)
        
        return True
    
    def _show_general_help(self):
        """Show general help information with categorized commands"""
        try:
            # Get all available commands from the registry
            if hasattr(self, 'command_registry') and self.command_registry:
                available_commands = self.command_registry.get_available_commands()
            else:
                raise AttributeError("No command registry available")
            
            if not available_commands:
                print_error("No commands available.")
                return
            
            # Print header
            self._print_header()
            
            # Organize commands by category
            categorized = self._categorize_commands(available_commands)
            
            # Display each category
            for category, commands in categorized.items():
                if commands:  # Only show categories that have commands
                    self._print_category(category, commands)
            
            # Show uncategorized commands if any
            all_categorized = set()
            for commands in categorized.values():
                all_categorized.update(cmd[0] for cmd in commands)
            
            uncategorized = [
                (cmd, self._get_command_description(cmd))
                for cmd in sorted(available_commands)
                if cmd not in all_categorized
            ]
            
            if uncategorized:
                self._print_category("Other Commands", uncategorized)
            
            # Print footer
            self._print_footer(len(available_commands))
            
        except Exception as e:
            # Fallback to static help if registry fails
            self._show_fallback_help(str(e))
    
    def _categorize_commands(self, available_commands):
        """Categorize commands based on COMMAND_CATEGORIES"""
        categorized = {cat: [] for cat in self.COMMAND_CATEGORIES.keys()}
        
        for cmd_name in sorted(available_commands):
            description = self._get_command_description(cmd_name)
            cmd_info = (cmd_name, description)
            
            # Find which category this command belongs to
            categorized_flag = False
            for category, commands in self.COMMAND_CATEGORIES.items():
                if cmd_name in commands:
                    categorized[category].append(cmd_info)
                    categorized_flag = True
                    break
            
            # If not found in any category, it will be added to "Other Commands" later
        
        return categorized
    
    def _get_command_description(self, command_name):
        """Get description for a command"""
        try:
            if hasattr(self, 'command_registry') and self.command_registry:
                command = self.command_registry.get_command(command_name)
                return command.description if hasattr(command, 'description') else "No description"
        except:
            pass
        return "Built-in command"
    
    def _print_header(self):
        """Print help header"""
        print_info("")
        print_info("╔" + "═" * 77 + "╗")
        print_info("║" + " " * 24 + "KittySploit Command Reference" + " " * 24 + "║")
        print_info("╚" + "═" * 77 + "╝")
        print_info("")
    
    def _print_category(self, category_name, commands):
        """Print a category of commands"""
        # Category header with color
        if self._use_colors():
            category_line = f"{Fore.CYAN}┌─ {category_name}{Style.RESET_ALL}"
        else:
            category_line = f"┌─ {category_name}"
        
        print_info(category_line)
        print_info("│")
        
        # Print commands in single column with full descriptions
        for cmd_name, description in commands:
            line = self._format_command_single((cmd_name, description))
            print_info(f"│  {line}")
        
        print_info("│")
        print_info("")
    
    def _format_command_single(self, cmd):
        """Format a single command with full description"""
        name, desc = cmd
        
        if self._use_colors():
            name_formatted = f"{Fore.GREEN}{name:<25}{Style.RESET_ALL}"
        else:
            name_formatted = f"{name:<25}"
        
        # Keep full description, no truncation
        return f"{name_formatted} {desc}"
    
    def _print_footer(self, total_commands):
        """Print help footer"""
        print_info("")
        print_status(f"Total: {total_commands} commands available")
        print_info("")
        print_info("  Usage examples:")
        if self._use_colors():
            print_info(f"    {Fore.YELLOW}help <command>{Style.RESET_ALL}     - Show detailed help for a specific command")
            print_info(f"    {Fore.YELLOW}help use{Style.RESET_ALL}          - Show help for the 'use' command")
        else:
            print_info("    help <command>     - Show detailed help for a specific command")
            print_info("    help use          - Show help for the 'use' command")
        print_info("")
    
    def _show_command_help(self, command_name: str):
        """Show help for a specific command"""
        try:
            if hasattr(self, 'command_registry') and self.command_registry:
                command = self.command_registry.get_command(command_name)
                
                if command:
                    self._print_command_details(command_name, command)
                else:
                    print_error(f"Command '{command_name}' not found")
            else:
                print_error(f"No help available for command '{command_name}'")
        except Exception as e:
            print_error(f"Error getting help for '{command_name}': {str(e)}")
    
    def _print_command_details(self, command_name, command):
        """Print detailed help for a specific command"""
        print_info()
        print_info("╔" + "═" * 78 + "╗")
        
        if self._use_colors():
            title = f"║  {Fore.CYAN}Command: {Fore.GREEN}{command_name}{Style.RESET_ALL}" + " " * (78 - len(command_name) - 11) + "║"
        else:
            title = f"║  Command: {command_name}" + " " * (78 - len(command_name) - 11) + "║"
        print_info(title)
        print_info("╠" + "═" * 78 + "╣")
        
        # Description
        description = getattr(command, 'description', 'No description available')
        print_info(f"║  {Fore.YELLOW}Description:{Style.RESET_ALL if self._use_colors() else ''}")
        self._print_wrapped_text(description, "║  ")
        
        # Usage
        usage = getattr(command, 'usage', f"{command_name} [options]")
        print_info("║")
        if self._use_colors():
            print_info(f"║  {Fore.YELLOW}Usage:{Style.RESET_ALL} {Fore.CYAN}{usage}{Style.RESET_ALL}")
        else:
            print_info(f"║  Usage: {usage}")
        
        # Help text if available
        help_text = getattr(command, 'help_text', None)
        if help_text and help_text != description:
            print_info("║")
            print_info(f"║  {Fore.YELLOW}Details:{Style.RESET_ALL if self._use_colors() else ''}")
            self._print_wrapped_text(help_text, "║  ")
        
        print_info("╚" + "═" * 78 + "╝")
        print_info("")
    
    def _print_wrapped_text(self, text, prefix="", width=76):
        """Print text with word wrapping"""
        words = text.split()
        line = prefix
        for word in words:
            if len(line) + len(word) + 1 > width:
                print_info(line)
                line = prefix + word
            else:
                if line != prefix:
                    line += " "
                line += word
        if line != prefix:
            print_info(line)
    
    def _use_colors(self):
        """Check if colors should be used"""
        try:
            from core.output_handler import is_interactive_terminal, USE_COLORS
            return USE_COLORS and is_interactive_terminal()
        except:
            return False
    
    def _show_fallback_help(self, error_msg=""):
        """Show fallback help when registry is not available"""
        print_warning("Built-in Commands (fallback mode):")
        print_info("=" * 50)
        print_info("help                                       Print this help menu")
        print_info("banner                                     Print the banner")
        print_info("clear                                      Clean screen")
        print_info("exit                                       Exit kittysploit")
        print_info("status                                     Display framework status")
        if error_msg:
            print_info(f"\nNote: Could not load dynamic command list ({error_msg})")
