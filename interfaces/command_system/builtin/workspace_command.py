#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Workspace command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from interfaces.command_system.command_parser import CommandParserHelper
from core.output_handler import print_info, print_success, print_error, print_warning
from core.utils.exceptions import KittyException

class WorkspaceCommand(BaseCommand):
    """Command to manage workspaces"""
    
    @property
    def name(self) -> str:
        return "workspace"
    
    @property
    def description(self) -> str:
        return "Manage workspaces (create, delete, list, switch, stats)"
    
    @property
    def usage(self) -> str:
        return "workspace <action> [options]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command manages workspaces entirely in the database. Workspaces are logical
containers for your penetration testing data (hosts, services, vulnerabilities, etc.).

Actions:
    list                    List all workspaces
    create <name>           Create a new workspace
    delete <name>           Delete a workspace
    switch <name>           Switch to a workspace
    stats [name]            Show workspace statistics
    current                 Show current workspace

Global Options:
    -v, --verbose          Enable verbose output
    -h, --help            Show this help message

Examples:
    workspace list                    # List all workspaces
    workspace create myproject        # Create a new workspace
    workspace switch myproject        # Switch to a workspace
    workspace stats                   # Show current workspace stats
    workspace delete oldproject --force  # Delete a workspace
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the workspace command"""
        # Check if we're in collaboration mode
        if hasattr(self.framework, 'current_collab') and self.framework.current_collab:
            print_warning("Cannot manage local workspaces while connected to a collaboration server")
            print_info(f"Currently connected to collaboration workspace: {self.framework.current_collab}")
            print_info("Use 'collab_disconnect' to disconnect from the collaboration server first")
            return False
        
        # Handle help before parsing
        if not args or (len(args) > 0 and args[0].lower() in ['help', '--help', '-h']):
            print_info(self.help_text)
            return True
        
        # Use the helper to create a parser with subcommands
        parser, subparsers = CommandParserHelper.create_subcommand_parser(
            self.name,
            self.description
        )
        
        # Add custom subcommands
        list_parser = subparsers.add_parser(
            "list",
            help="List all workspaces"
        )
        
        create_parser = subparsers.add_parser(
            "create",
            help="Create a new workspace"
        )
        create_parser.add_argument(
            "name",
            help="Name of the workspace to create"
        )
        create_parser.add_argument(
            "-d", "--description",
            help="Description of the workspace"
        )
        
        delete_parser = subparsers.add_parser(
            "delete",
            help="Delete a workspace"
        )
        delete_parser.add_argument(
            "name",
            help="Name of the workspace to delete"
        )
        delete_parser.add_argument(
            "-f", "--force",
            action="store_true",
            help="Force deletion without confirmation"
        )
        
        switch_parser = subparsers.add_parser(
            "switch",
            help="Switch to a workspace"
        )
        switch_parser.add_argument(
            "name",
            help="Name of the workspace to switch to"
        )
        
        stats_parser = subparsers.add_parser(
            "stats",
            help="Show workspace statistics"
        )
        stats_parser.add_argument(
            "name",
            nargs="?",
            help="Name of the workspace (uses current if not specified)"
        )
        
        current_parser = subparsers.add_parser(
            "current",
            help="Show current workspace"
        )
        
        try:
            # Parse arguments
            parsed_args, unknown_args = parser.parse_known_args(args)
            
            # Handle case where parsing failed (SystemExit was caught by parser)
            if parsed_args is None:
                # Check if "help" was in args
                if args and args[0].lower() in ['help', '--help', '-h']:
                    print_info(self.help_text)
                    return True
                return False
            
            # Handle help (if --help flag was used)
            if hasattr(parsed_args, 'help') and parsed_args.help:
                print_info(self.help_text)
                return True
            
            # Handle case where no action is provided
            if not hasattr(parsed_args, 'action') or not parsed_args.action:
                print_info(self.help_text)
                return True
            
            # Handle unknown arguments
            if unknown_args:
                print_error(f"Unknown arguments: {' '.join(unknown_args)}")
                return False
            
            # Handle verbose output
            if parsed_args.verbose:
                print_info("Verbose mode enabled")
                print_info(f"Action: {parsed_args.action}")
            
            # Get workspace manager from framework
            if not hasattr(self.framework, 'workspace_manager'):
                print_error("Workspace manager not available")
                return False
            
            workspace_manager = self.framework.workspace_manager
            
            # Handle different actions
            if parsed_args.action == "list":
                return self._handle_list(parsed_args, workspace_manager)
            elif parsed_args.action == "create":
                return self._handle_create(parsed_args, workspace_manager)
            elif parsed_args.action == "delete":
                return self._handle_delete(parsed_args, workspace_manager)
            elif parsed_args.action == "switch":
                return self._handle_switch(parsed_args, workspace_manager)
            elif parsed_args.action == "stats":
                return self._handle_stats(parsed_args, workspace_manager)
            elif parsed_args.action == "current":
                return self._handle_current(parsed_args, workspace_manager)
            else:
                print_error(f"Unknown action: {parsed_args.action}")
                return False
                
        except (SystemExit, KittyException) as e:
            # argparse/CommandArgumentParser raises SystemExit/KittyException on --help or invalid arguments
            error_str = str(e)
            # Check if error is about invalid choice and if it's "help"
            if "invalid choice" in error_str.lower() and "help" in error_str.lower():
                print_info(self.help_text)
                return True
            # Check if "help" was in args
            if args and len(args) > 0 and args[0].lower() in ['help', '--help', '-h']:
                print_info(self.help_text)
                return True
            # Otherwise, show the error
            print_error(f"Error: {error_str}")
            return False
        except Exception as e:
            # Check if error is about invalid choice and if it's "help"
            error_str = str(e)
            if "invalid choice" in error_str.lower() and "help" in error_str.lower():
                print_info(self.help_text)
                return True
            # Check if "help" was in args
            if args and len(args) > 0 and args[0].lower() in ['help', '--help', '-h']:
                print_info(self.help_text)
                return True
            print_error(f"Error: {e}")
            return False
    
    def _handle_list(self, args, workspace_manager):
        """Handle list action"""
        workspaces = workspace_manager.list_workspaces()
        
        if not workspaces:
            print_info("No workspaces found")
            return True
        
        print_info("Available workspaces:")
        print_info("=" * 50)
        
        current_workspace = workspace_manager.get_current_workspace()
        
        for workspace in workspaces:
            status = " (current)" if current_workspace and current_workspace.name == workspace.name else ""
            print_info(f"{workspace.name:<20} {workspace.description or 'No description'}{status}")
        
        return True
    
    def _handle_create(self, args, workspace_manager):
        """Handle create action"""
        return workspace_manager.create_workspace(args.name, args.description)
    
    def _handle_delete(self, args, workspace_manager):
        """Handle delete action"""
        return workspace_manager.delete_workspace(args.name, args.force)
    
    def _handle_switch(self, args, workspace_manager):
        """Handle switch action"""
        return workspace_manager.switch_workspace(args.name)
    
    def _handle_stats(self, args, workspace_manager):
        """Handle stats action"""
        workspace_name = args.name
        stats = workspace_manager.get_workspace_stats(workspace_name)
        
        if not stats:
            print_error("No statistics available")
            return False
        
        if workspace_name:
            print_info(f"Statistics for workspace '{workspace_name}':")
        else:
            current = workspace_manager.get_current_workspace()
            if current:
                print_info(f"Statistics for current workspace '{current.name}':")
            else:
                print_info("Statistics for current workspace:")
        
        print_info("=" * 40)
        print_info(f"Hosts:      {stats.get('hosts', 0)}")
        print_info(f"Tasks:      {stats.get('tasks', 0)}")
        print_info(f"Notes:      {stats.get('notes', 0)}")
        print_info(f"Loot:       {stats.get('loot', 0)}")
        
        return True
    
    def _handle_current(self, args, workspace_manager):
        """Handle current action"""
        current_workspace = workspace_manager.get_current_workspace()
        
        if not current_workspace:
            print_info("No current workspace")
            return True
        
        print_info(f"Current workspace: {current_workspace.name}")
        if current_workspace.description:
            print_info(f"Description: {current_workspace.description}")
        
        return True
