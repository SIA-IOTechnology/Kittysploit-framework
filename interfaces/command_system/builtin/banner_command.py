#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Banner command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success

class BannerCommand(BaseCommand):
    """Command to display the KittySploit banner"""
    
    @property
    def name(self) -> str:
        return "banner"
    
    @property
    def description(self) -> str:
        return "Display the KittySploit framework banner"
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the banner command"""
        # ASCII version for Windows compatibility
        banner = r"""
        ██╗  ██╗██╗████████╗████████╗██╗   ██╗███████╗██████╗ ██╗      ██████╗ ██╗████████╗
        ██║ ██╔╝██║╚══██╔══╝╚══██╔══╝╚██╗ ██╔╝██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
        █████╔╝ ██║   ██║      ██║    ╚████╔╝ ███████╗██████╔╝██║     ██║   ██║██║   ██║   
        ██╔═██╗ ██║   ██║      ██║     ╚██╔╝  ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   
        ██║  ██╗██║   ██║      ██║      ██║   ███████║██║     ███████╗╚██████╔╝██║   ██║   
        ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝      ╚═╝   ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
        """
        
        if 'framework' in kwargs and kwargs['framework']:
            version = f"v{kwargs['framework'].version}"
        else:
            version = "v1.0.0"  # Fallback version
        
        tagline = "Advanced Penetration Testing Framework"
        author = "Developed by KittySploit Team"
        website = "https://kittysploit.com"
        
        print_info("\033[95m" + banner + "\033[0m")
        print_info("\033[1m\033[94m{:^80}\033[0m".format(tagline))
        print_info("\033[1m\033[94m{:^80}\033[0m".format(version))
        print_info("\033[93m{:^80}\033[0m".format(author))
        print_info("\033[93m{:^80}\033[0m".format(website))
        
        if 'framework' in kwargs and kwargs['framework']:
            framework = kwargs['framework']
            try:
                module_counts = framework.get_module_counts_by_type()
                if module_counts:
                    print_info("\033[92m" + "="*80 + "\033[0m")
                    print_info("\033[1m\033[96m{:^80}\033[0m".format("Available Modules"))
                    print_info("\033[92m" + "="*80 + "\033[0m")
                    
                    # Display modules in the specified order
                    module_order = [
                        'exploits', 'auxiliary', 'browser_exploits', 'browser_auxiliary', 
                        'payloads', 'encoders', 'listeners', 'workflow', 'backdoors', 'docker_environment', 'post', 
                        'scanner', 'shortcut', 'plugins'
                    ]
                    
                    # Mapping for display names
                    display_name_map = {
                        'docker_environment': 'Docker environments',
                        'browser_exploits': 'Browser Exploits',
                        'browser_auxiliary': 'Browser Auxiliary',
                    }
                    
                    module_info = []
                    for module_type in module_order:
                        # Check both the exact type and 'environments' for backward compatibility
                        count = module_counts.get(module_type, 0)
                        if module_type == 'docker_environment' and count == 0:
                            # Also check for 'environments' key (backward compatibility)
                            count = module_counts.get('environments', 0)
                        
                        # Get display name from map or generate from type
                        display_name = display_name_map.get(module_type, module_type.replace('_', ' ').title())
                        module_info.append(f"{display_name}: {count}")
                    
                    # Display in two columns with visual alignment
                    for i in range(0, len(module_info), 2):
                        line_parts = module_info[i:i+2]
                        if len(line_parts) == 2:
                            # Split into name and count for better alignment
                            left_name, left_count = line_parts[0].split(': ')
                            right_name, right_count = line_parts[1].split(': ')
                            
                            # Create aligned columns (left column: 25 chars, right column: 25 chars)
                            left_part = f"{left_name}: {left_count}".ljust(25)
                            right_part = f"{right_name}: {right_count}".ljust(25)
                            modules_line = f"{left_part} | {right_part}"
                        else:
                            # Single item, center it
                            modules_line = line_parts[0]
                        # Center the entire line
                        print_info("\033[93m{:^80}\033[0m".format(modules_line))
                    
                    # Display total
                    total_modules = sum(module_counts.values())
                    print_info("\033[1m\033[92m{:^80}\033[0m".format(f"Total: {total_modules} modules"))
                    print_info("\033[92m" + "="*80 + "\033[0m")
                else:
                    print_info("\033[93m{:^80}\033[0m".format("No modules loaded"))
            except Exception as e:
                print_info("\033[91m{:^80}\033[0m".format(f"Error loading module counts: {str(e)}"))
        
        print("\n")
        
        return True