#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Syscall command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import sys
import os
from pathlib import Path

# Add data directory to path
current_file = Path(__file__).resolve()
project_root = current_file.parent.parent.parent.parent
data_dir = project_root / 'data'
sys.path.insert(0, str(data_dir))

try:
    from syscall import get_database, get_syscall, list_syscalls, search_syscalls
    SYSCALL_AVAILABLE = True
    IMPORT_ERROR = None
except ImportError as e:
    SYSCALL_AVAILABLE = False
    IMPORT_ERROR = str(e)

class SyscallCommand(BaseCommand):
    """Command to query syscall information"""
    
    @property
    def name(self) -> str:
        return "syscall"
    
    @property
    def description(self) -> str:
        return "Query syscall information for different architectures"
    
    @property
    def usage(self) -> str:
        return "syscall <action> [options]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Actions:
    list <arch>              List all syscalls for an architecture
    search <arch> <query>    Search syscalls by name
    get <arch> <number>      Get syscall by number
    info <arch>              Show architecture information
    architectures             List available architectures

Architectures:
    x86_64    - Intel/AMD 64-bit
    x86       - Intel/AMD 32-bit
    arm64     - ARM 64-bit
    arm32     - ARM 32-bit

Examples:
    syscall architectures                    # List all architectures
    syscall info x86_64                      # Show x86_64 info
    syscall list x86_64                      # List all x86_64 syscalls
    syscall get x86_64 59                    # Get syscall 59 (execve)
    syscall search x86_64 exec               # Search for 'exec' syscalls
    syscall get x86_64 execve                # Get execve syscall by name
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the syscall command"""
        if not SYSCALL_AVAILABLE:
            print_error("Syscall database not available. Make sure data/syscall module is accessible.")
            if IMPORT_ERROR:
                print_error(f"Import error: {IMPORT_ERROR}")
            return False
        
        if len(args) == 0:
            print_info(self.help_text)
            return True
        
        action = args[0].lower()
        
        if action in ['-h', '--help', 'help']:
            print_info(self.help_text)
            return True
        
        if action == 'architectures':
            return self._list_architectures()
        
        if len(args) < 2:
            print_error(f"Missing argument for action '{action}'")
            print_info(f"Use '{self.name} --help' for usage information")
            return False
        
        arch = args[1].lower()
        
        if action == 'info':
            return self._show_architecture_info(arch)
        elif action == 'list':
            limit = None
            if len(args) >= 3:
                try:
                    limit = int(args[2])
                except ValueError:
                    print_error(f"Invalid limit: {args[2]}")
                    return False
            return self._list_syscalls(arch, limit)
        elif action == 'get':
            if len(args) < 3:
                print_error("Missing syscall number or name")
                return False
            identifier = args[2]
            # Try as number first
            try:
                number = int(identifier)
                return self._get_syscall_by_number(arch, number)
            except ValueError:
                # Try as name
                return self._get_syscall_by_name(arch, identifier)
        elif action == 'search':
            if len(args) < 3:
                print_error("Missing search query")
                return False
            query = args[2]
            return self._search_syscalls(arch, query)
        else:
            print_error(f"Unknown action: {action}")
            print_info(f"Use '{self.name} --help' for usage information")
            return False
    
    def _list_architectures(self) -> bool:
        """List all available architectures"""
        try:
            db = get_database()
            architectures = db.get_architectures()
            
            print_info("\nAvailable architectures:")
            print_info("=" * 60)
            for arch in architectures:
                info = db.get_architecture_info(arch)
                if info:
                    print_info(f"  {arch:10s} - {info['count']:3d} syscalls")
                else:
                    print_info(f"  {arch:10s}")
            return True
        except Exception as e:
            print_error(f"Error listing architectures: {e}")
            return False
    
    def _show_architecture_info(self, arch: str) -> bool:
        """Show information about an architecture"""
        try:
            db = get_database()
            info = db.get_architecture_info(arch)
            
            if not info:
                print_error(f"Unknown architecture: {arch}")
                print_info("Use 'syscall architectures' to list available architectures")
                return False
            
            print_info(f"\nArchitecture: {info['architecture']}")
            print_info(f"Total syscalls: {info['count']}")
            return True
        except Exception as e:
            print_error(f"Error getting architecture info: {e}")
            return False
    
    def _list_syscalls(self, arch: str, limit: int = None) -> bool:
        """List syscalls for an architecture"""
        try:
            syscalls = list_syscalls(arch)
            
            if not syscalls:
                print_error(f"No syscalls found for architecture: {arch}")
                print_info("Use 'syscall architectures' to list available architectures")
                return False
            
            if limit:
                syscalls = syscalls[:limit]
            
            print_info(f"\nSyscalls for {arch} ({len(syscalls)} shown):")
            print_info("=" * 80)
            print_info(f"{'Number':<8} {'Hex':<8} {'Name':<30} {'Parameters'}")
            print_info("-" * 80)
            
            for syscall in syscalls:
                num = syscall.get('number', 'N/A')
                hex_val = syscall.get('hex', 'N/A')
                name = syscall.get('name', 'N/A')
                params = ', '.join(syscall.get('parameters', []))[:40]
                if len(params) > 40:
                    params = params[:37] + "..."
                
                print_info(f"{num:<8} {hex_val:<8} {name:<30} {params}")
            
            return True
        except Exception as e:
            print_error(f"Error listing syscalls: {e}")
            return False
    
    def _get_syscall_by_number(self, arch: str, number: int) -> bool:
        """Get a syscall by its number"""
        try:
            syscall = get_syscall(arch, number=number)
            
            if not syscall:
                print_error(f"Syscall {number} not found for architecture: {arch}")
                return False
            
            self._print_syscall_details(syscall, arch)
            return True
        except Exception as e:
            print_error(f"Error getting syscall: {e}")
            return False
    
    def _get_syscall_by_name(self, arch: str, name: str) -> bool:
        """Get a syscall by its name"""
        try:
            syscall = get_syscall(arch, name=name)
            
            if not syscall:
                print_error(f"Syscall '{name}' not found for architecture: {arch}")
                return False
            
            self._print_syscall_details(syscall, arch)
            return True
        except Exception as e:
            print_error(f"Error getting syscall: {e}")
            return False
    
    def _search_syscalls(self, arch: str, query: str) -> bool:
        """Search syscalls by name"""
        try:
            results = search_syscalls(arch, query)
            
            if not results:
                print_error(f"No syscalls found matching '{query}' for architecture: {arch}")
                return False
            
            print_info(f"\nFound {len(results)} syscall(s) matching '{query}':")
            print_info("=" * 80)
            print_info(f"{'Number':<8} {'Hex':<8} {'Name':<30} {'Parameters'}")
            print_info("-" * 80)
            
            for syscall in results:
                num = syscall.get('number', 'N/A')
                hex_val = syscall.get('hex', 'N/A')
                name = syscall.get('name', 'N/A')
                params = ', '.join(syscall.get('parameters', []))[:40]
                if len(params) > 40:
                    params = params[:37] + "..."
                
                print_info(f"{num:<8} {hex_val:<8} {name:<30} {params}")
            
            return True
        except Exception as e:
            print_error(f"Error searching syscalls: {e}")
            return False
    
    def _print_syscall_details(self, syscall: dict, arch: str):
        """Print detailed information about a syscall"""
        print_info(f"\nSyscall Details ({arch}):")
        print_info("=" * 60)
        print_info(f"Number:     {syscall.get('number', 'N/A')}")
        print_info(f"Name:       {syscall.get('name', 'N/A')}")
        print_info(f"Hex:        {syscall.get('hex', 'N/A')}")
        
        params = syscall.get('parameters', [])
        if params:
            print_info(f"Parameters: {len(params)}")
            for i, param in enumerate(params, 1):
                print_info(f"  {i}. {param}")
        else:
            print_info("Parameters: None")
        
        source = syscall.get('source')
        if source:
            print_info(f"Source:     {source}")

