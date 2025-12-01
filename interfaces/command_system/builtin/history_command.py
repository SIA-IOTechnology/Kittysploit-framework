#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
History command implementation - Display command history
"""

import os
import json
import time
from datetime import datetime
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class HistoryCommand(BaseCommand):
    """Command to display command history"""
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.history_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'history.json')
    
    @property
    def name(self) -> str:
        return "history"
    
    @property
    def description(self) -> str:
        return "Display command history"
    
    @property
    def usage(self) -> str:
        return "history [--clear] [--save] [--load] [--limit <num>] [--search <term>]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command displays the history of executed commands with timestamps and results.

Options:
    --clear              Clear the command history
    --save               Save current history to file
    --load               Load history from file
    --limit <num>        Limit number of commands to show (default: 50)
    --search <term>      Search for commands containing the term
    --json               Output in JSON format

Examples:
    history                      # Show last 50 commands
    history --limit 10          # Show last 10 commands
    history --search "use"      # Search for commands containing "use"
    history --clear             # Clear history
    history --json              # Output in JSON format

Note: History is automatically saved and loaded between sessions.
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the history command"""
        try:
            # Parse arguments
            options = self._parse_args(args)
            
            # Get command registry for history access
            command_registry = kwargs.get('command_registry')
            if not command_registry:
                print_error("Command registry not available")
                return False
            
            # Handle different options
            if options['clear']:
                return self._clear_history(command_registry)
            elif options['save']:
                return self._save_history(command_registry)
            elif options['load']:
                return self._load_history(command_registry)
            else:
                return self._display_history(command_registry, options)
            
        except Exception as e:
            print_error(f"Error executing history command: {str(e)}")
            return False
    
    def _parse_args(self, args):
        """Parse command line arguments"""
        options = {
            'clear': False,
            'save': False,
            'load': False,
            'limit': 50,
            'search': None,
            'json': False
        }
        
        i = 0
        while i < len(args):
            if args[i] == '--clear':
                options['clear'] = True
                i += 1
            elif args[i] == '--save':
                options['save'] = True
                i += 1
            elif args[i] == '--load':
                options['load'] = True
                i += 1
            elif args[i] == '--limit' and i + 1 < len(args):
                try:
                    options['limit'] = int(args[i + 1])
                except ValueError:
                    print_warning(f"Invalid limit value: {args[i + 1]}, using default")
                i += 2
            elif args[i] == '--search' and i + 1 < len(args):
                options['search'] = args[i + 1]
                i += 2
            elif args[i] == '--json':
                options['json'] = True
                i += 1
            else:
                i += 1
        
        return options
    
    def _get_history(self, command_registry):
        """Get command history from database via HistoryManager with fallback"""
        history = []
        
        # Try to get from database first
        if hasattr(command_registry, 'history_manager'):
            try:
                db_history = command_registry.history_manager.get_history(limit=1000)
                if db_history:
                    # Convert database format to standard format
                    for entry in db_history:
                        history.append({
                            'timestamp': entry.get('timestamp', time.time()),
                            'command': entry.get('command', ''),
                            'success': entry.get('success', True),
                            'args': entry.get('args', [])
                        })
            except Exception as e:
                # If database fails, fall back to local history
                pass
        
        # Fallback to local history if database is empty or failed
        if not history and hasattr(command_registry, 'command_history'):
            local_history = command_registry.command_history
            if local_history:
                history = local_history
        
        # Try to load from file if still empty
        if not history and os.path.exists(self.history_file):
            try:
                # Check if file is not empty
                if os.path.getsize(self.history_file) == 0:
                    return history
                
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if not content:
                        return history
                    file_history = json.loads(content)
                    if file_history:
                        history = file_history
            except (json.JSONDecodeError, ValueError):
                # Invalid JSON, skip file
                pass
            except Exception:
                pass
        
        return history
    
    def _clear_history(self, command_registry):
        """Clear command history"""
        if hasattr(command_registry, 'history_manager'):
            # Clear from database
            cleared_count = command_registry.history_manager.clear_history()
            print_success(f"Cleared {cleared_count} commands from database history")
        elif hasattr(command_registry, 'command_history'):
            command_registry.command_history = []
            print_success("Command history cleared")
        else:
            print_warning("No history to clear")
        return True
    
    def _save_history(self, command_registry):
        """Save history to file"""
        try:
            history = self._get_history(command_registry)
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
            print_success(f"History saved to {self.history_file}")
            return True
        except Exception as e:
            print_error(f"Error saving history: {e}")
            return False
    
    def _load_history(self, command_registry):
        """Load history from file"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    history = json.load(f)
                if hasattr(command_registry, 'command_history'):
                    command_registry.command_history = history
                    print_success(f"History loaded from {self.history_file}")
                else:
                    print_warning("Command registry does not support history")
                return True
            else:
                print_warning("No history file found")
                return True
        except Exception as e:
            print_error(f"Error loading history: {e}")
            return False
    
    def _display_history(self, command_registry, options):
        """Display command history"""
        # Get history using improved method with fallbacks
        history = self._get_history(command_registry)
        
        # If we have a history_manager and want to use database search
        if hasattr(command_registry, 'history_manager') and not history:
            try:
                # Try database with search and limit
                db_history = command_registry.history_manager.get_history(
                    limit=options['limit'],
                    search_term=options['search']
                )
                if db_history:
                    # Convert database format to standard format
                    history = []
                    for entry in db_history:
                        history.append({
                            'timestamp': entry.get('timestamp', time.time()),
                            'command': entry.get('command', ''),
                            'success': entry.get('success', True),
                            'args': entry.get('args', [])
                        })
            except Exception:
                # If database search fails, use local history
                pass
        
        # Filter by search term if provided and not using database search
        if options['search'] and history:
            search_term = options['search'].lower()
            history = [entry for entry in history if search_term in entry.get('command', '').lower()]
        
        # Limit results if not using database limit
        if options['limit'] > 0 and history:
            # Sort by timestamp (newest first) if timestamps are available
            try:
                history.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
            except:
                pass
            history = history[:options['limit']]
        
        if not history:
            print_info("No command history found")
            print_info("History will be recorded as you execute commands.")
            print_info("Use 'history --help' for more information.")
            return True
        
        if options['json']:
            self._display_json(history)
        else:
            self._display_formatted(history)
        
        return True
    
    def _display_formatted(self, history):
        """Display history in formatted text"""
        print_info("Command History")
        print_info("=" * 80)
        print_info(f"{'#':<4} {'Time':<20} {'Command':<50} {'Result':<8}")
        print_info("-" * 80)
        
        for i, entry in enumerate(history, 1):
            timestamp = entry.get('timestamp', 'Unknown')
            command = entry.get('command', 'Unknown')
            result = 'Success' if entry.get('success', False) else 'Failed'
            
            # Format timestamp - handle both Unix timestamp and ISO string
            # Use European date format (DD/MM/YYYY)
            time_str = 'Unknown'
            try:
                if isinstance(timestamp, (int, float)):
                    # Unix timestamp
                    dt = datetime.fromtimestamp(timestamp)
                    time_str = dt.strftime('%d/%m/%Y %H:%M:%S')
                elif isinstance(timestamp, str):
                    # ISO format string from database
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        time_str = dt.strftime('%d/%m/%Y %H:%M:%S')
                    except:
                        # Try parsing as Unix timestamp string
                        try:
                            dt = datetime.fromtimestamp(float(timestamp))
                            time_str = dt.strftime('%d/%m/%Y %H:%M:%S')
                        except:
                            time_str = timestamp[:19] if len(timestamp) > 19 else timestamp
                else:
                    time_str = str(timestamp)
            except Exception:
                time_str = str(timestamp)[:19] if len(str(timestamp)) > 19 else str(timestamp)
            
            # Truncate long commands
            display_command = command
            if len(display_command) > 50:
                display_command = display_command[:47] + "..."
            
            print_info(f"{i:<4} {time_str:<20} {display_command:<50} {result:<8}")
        
        print_info("=" * 80)
        print_info(f"Total: {len(history)} commands")
    
    def _display_json(self, history):
        """Display history in JSON format"""
        import json
        print(json.dumps(history, indent=2, ensure_ascii=False))
