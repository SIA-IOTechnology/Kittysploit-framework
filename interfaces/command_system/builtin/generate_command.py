#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate command implementation - Generate payloads
"""

import os
import argparse
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class GenerateCommand(BaseCommand):
    """Command to generate payloads from the current payload module"""
    
    @property
    def name(self) -> str:
        return "generate"
    
    @property
    def description(self) -> str:
        return "Generate payload from the current payload module"
    
    @property
    def usage(self) -> str:
        return "generate [--output <file>] [--format <format>] [--encoder <encoder>] [--nops <nops>] [--iterations <count>]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command generates a payload using the currently selected payload module.
The command is only available when a payload module is loaded.

Options:
    --output <file>        Save generated payload to file
    --format <format>      Output format (raw, hex, base64, c, python, etc.)
    --encoder <encoder>    Apply encoder to the payload
    --nops <nops>          Add NOP sled of specified length
    --iterations <count>   Number of encoding iterations
    --preview              Preview the payload without generating
    --verbose              Show detailed generation information

Examples:
    generate                           # Generate payload with default settings
    generate --output payload.bin      # Save payload to file
    generate --format hex              # Generate payload in hex format
    generate --encoder xor --iterations 3  # Apply XOR encoder 3 times
    generate --nops 100                # Add 100-byte NOP sled
    generate --preview                 # Preview payload without generating

Note: This command only works when a payload module is selected.
        """
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command parser"""
        parser = argparse.ArgumentParser(
            description="Generate payload from current payload module",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  generate                           # Generate payload with default settings
  generate --output payload.bin      # Save payload to file
  generate --format hex              # Generate payload in hex format
  generate --encoder xor --iterations 3  # Apply XOR encoder 3 times
  generate --nops 100                # Add 100-byte NOP sled
  generate --preview                 # Preview payload without generating
            """
        )
        
        parser.add_argument("--output", "-o", metavar="<file>", help="Save generated payload to file")
        parser.add_argument("--format", "-f", metavar="<format>", 
                          choices=["raw", "hex", "base64", "c", "python", "powershell", "bash"],
                          default="raw", help="Output format (default: raw)")
        parser.add_argument("--encoder", "-e", metavar="<encoder>", help="Apply encoder to the payload")
        parser.add_argument("--nops", "-n", type=int, metavar="<length>", help="Add NOP sled of specified length")
        parser.add_argument("--iterations", "-i", type=int, default=1, metavar="<count>", 
                          help="Number of encoding iterations (default: 1)")
        parser.add_argument("--preview", "-p", action="store_true", help="Preview the payload without generating")
        parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed generation information")
        
        return parser
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the generate command"""
        try:
            parsed_args = self.parser.parse_args(args)
        except SystemExit:
            return True
        
        # Check if a payload module is selected
        if not hasattr(self.framework, 'current_module') or not self.framework.current_module:
            print_error("No module selected. Use 'use <payload>' first.")
            return False
        
        # Check if current module is a payload
        current_module = self.framework.current_module
        if not hasattr(current_module, 'type') or current_module.type != 'payload':
            print_error("Current module is not a payload. Please select a payload module first.")
            print_info("Use 'use <payload_path>' to select a payload module")
            return False
        
        # Check if payload has generate method
        if not hasattr(current_module, 'generate') or not callable(getattr(current_module, 'generate')):
            print_error("Current payload module does not support generation.")
            return False
        
        try:
            # Show generation info
            if parsed_args.verbose:
                self._show_generation_info(current_module, parsed_args)
            
            # Preview mode
            if parsed_args.preview:
                return self._preview_payload(current_module, parsed_args)
            
            # Generate the payload
            return self._generate_payload(current_module, parsed_args)
            
        except Exception as e:
            print_error(f"Error generating payload: {str(e)}")
            return False
    
    def _show_generation_info(self, payload_module, parsed_args):
        """Show detailed generation information"""
        print_info("Payload Generation Information:")
        print_info("=" * 50)
        print_info(f"Payload: {payload_module.name}")
        print_info(f"Description: {payload_module.description}")
        print_info(f"Author: {payload_module.author}")
        print_info(f"Version: {payload_module.version}")
        
        # Show payload metadata
        if hasattr(payload_module, '__info__'):
            info = payload_module.__info__
            if 'arch' in info:
                print_info(f"Architecture: {info['arch']}")
            if 'platform' in info:
                print_info(f"Platform: {info['platform']}")
            if 'handler' in info:
                print_info(f"Handler: {info['handler']}")
            if 'session_type' in info:
                print_info(f"Session Type: {info['session_type']}")
        
        print_info(f"Output Format: {parsed_args.format}")
        if parsed_args.encoder:
            print_info(f"Encoder: {parsed_args.encoder} ({parsed_args.iterations} iterations)")
        if parsed_args.nops:
            print_info(f"NOP Sled: {parsed_args.nops} bytes")
        if parsed_args.output:
            print_info(f"Output File: {parsed_args.output}")
        print_info("=" * 50)
    
    def _preview_payload(self, payload_module, parsed_args):
        """Preview payload without generating"""
        print_info("Payload Preview:")
        print_info("=" * 30)
        
        # Show payload options
        options = payload_module.get_options()
        if options:
            print_info("Payload Options:")
            for name, option_data in options.items():
                if len(option_data) >= 4:
                    default, required, description, advanced = option_data[:4]
                    req_text = " (required)" if required else ""
                    adv_text = " (advanced)" if advanced else ""
                    print_info(f"  {name:<15} {default:<15} {description}{req_text}{adv_text}")
        
        # Show generation parameters
        print_info("\nGeneration Parameters:")
        print_info(f"  Format: {parsed_args.format}")
        if parsed_args.encoder:
            print_info(f"  Encoder: {parsed_args.encoder} ({parsed_args.iterations} iterations)")
        if parsed_args.nops:
            print_info(f"  NOP Sled: {parsed_args.nops} bytes")
        if parsed_args.output:
            print_info(f"  Output: {parsed_args.output}")
        
        print_info("\nUse 'generate' (without --preview) to actually generate the payload.")
        return True
    
    def _generate_payload(self, payload_module, parsed_args):
        """Generate the actual payload"""
        try:
            print_info(f"Generating payload: {payload_module.name}")
            
            # Check if all required options are set
            if not payload_module.check_options():
                missing = payload_module.get_missing_options()
                if missing:
                    print_error(f"Missing required options: {', '.join(missing)}")
                else:
                    print_error("Not all required options are set")
                print_info("Use 'show options' to see required options")
                return False
            
            # Generate the raw payload
            raw_payload = payload_module.generate()
            
            if not raw_payload:
                print_error("Failed to generate payload")
                return False
            
            # Apply NOP sled if requested
            if parsed_args.nops and parsed_args.nops > 0:
                raw_payload = self._add_nop_sled(raw_payload, parsed_args.nops)
            
            # Apply encoder if requested
            if parsed_args.encoder:
                raw_payload = self._apply_encoder(raw_payload, parsed_args.encoder, parsed_args.iterations)
            
            # Format the payload
            formatted_payload = self._format_payload(raw_payload, parsed_args.format)
            
            # Display or save the payload
            if parsed_args.output:
                self._save_payload(formatted_payload, parsed_args.output, parsed_args.format)
            else:
                self._display_payload(formatted_payload, parsed_args.format)
            
            print_success("Payload generated successfully!")
            return True
            
        except Exception as e:
            print_error(f"Error during payload generation: {str(e)}")
            return False
    
    def _add_nop_sled(self, payload, nop_length):
        """Add NOP sled to payload"""
        try:
            # Convert string to bytes if needed
            if isinstance(payload, str):
                payload_bytes = payload.encode('utf-8')
            else:
                payload_bytes = payload
            
            # Get NOP sled from framework
            if hasattr(self.framework, 'nops') and hasattr(self.framework.nops, 'get_nops'):
                nop_bytes = self.framework.nops.get_nops(nop_length)
                return nop_bytes + payload_bytes
            else:
                # Fallback: use simple NOP instruction (0x90 for x86)
                nop_bytes = b'\x90' * nop_length
                return nop_bytes + payload_bytes
        except Exception as e:
            print_warning(f"Could not add NOP sled: {e}")
            return payload
    
    def _apply_encoder(self, payload, encoder_name, iterations):
        """Apply encoder to payload"""
        try:
            # This is a simplified implementation
            # In a real framework, you would have encoder modules
            if encoder_name.lower() == 'xor':
                # Simple XOR encoding
                key = 0xAA
                encoded = bytearray()
                for _ in range(iterations):
                    for byte in payload:
                        encoded.append(byte ^ key)
                    payload = bytes(encoded)
                    encoded = bytearray()
                print_info(f"Applied XOR encoder ({iterations} iterations)")
            else:
                print_warning(f"Encoder '{encoder_name}' not supported, skipping encoding")
            
            return payload
        except Exception as e:
            print_warning(f"Could not apply encoder: {e}")
            return payload
    
    def _format_payload(self, payload, format_type):
        """Format payload according to specified format"""
        try:
            # Convert string to bytes if needed
            if isinstance(payload, str):
                payload_bytes = payload.encode('utf-8')
            else:
                payload_bytes = payload
            
            if format_type == "raw":
                return payload  # Return original (string or bytes)
            elif format_type == "hex":
                return payload_bytes.hex()
            elif format_type == "base64":
                import base64
                return base64.b64encode(payload_bytes).decode('utf-8')
            elif format_type == "c":
                hex_str = payload_bytes.hex()
                hex_pairs = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
                return "\\x" + "\\x".join(hex_pairs)
            elif format_type == "python":
                return repr(payload_bytes)
            elif format_type == "powershell":
                hex_str = payload_bytes.hex()
                hex_pairs = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
                return "[byte[]](" + ",".join([f"0x{pair}" for pair in hex_pairs]) + ")"
            elif format_type == "bash":
                hex_str = payload_bytes.hex()
                hex_pairs = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
                return "\\x" + "\\x".join(hex_pairs)
            else:
                print_warning(f"Unknown format '{format_type}', using raw format")
                return payload
        except Exception as e:
            print_warning(f"Could not format payload: {e}")
            return payload
    
    def _display_payload(self, payload, format_type):
        """Display the generated payload"""
        print_info(f"\nGenerated Payload ({format_type} format):")
        print_info("=" * 50)
        
        if format_type == "raw":
            # For raw binary, show hex representation
            if isinstance(payload, str):
                # If it's a string (like instructions), display it directly
                print_info(payload)
            else:
                # If it's bytes, show hex representation
                hex_payload = payload.hex()
                for i in range(0, len(hex_payload), 32):
                    chunk = hex_payload[i:i+32]
                    formatted_chunk = ' '.join([chunk[j:j+2] for j in range(0, len(chunk), 2)])
                    print_info(f"{i//2:04x}: {formatted_chunk}")
        else:
            # For text formats, display directly
            if isinstance(payload, bytes):
                print_info(payload.decode('utf-8', errors='replace'))
            else:
                print_info(str(payload))
        
        print_info("=" * 50)
        print_info(f"Payload size: {len(payload) if isinstance(payload, (bytes, str)) else len(str(payload))} bytes")
    
    def _save_payload(self, payload, filename, format_type):
        """Save payload to file"""
        try:
            with open(filename, 'wb' if format_type == "raw" else 'w') as f:
                if format_type == "raw" and isinstance(payload, str):
                    # Convert hex string back to bytes
                    payload_bytes = bytes.fromhex(payload)
                    f.write(payload_bytes)
                else:
                    f.write(payload if isinstance(payload, bytes) else str(payload).encode('utf-8'))
            
            print_success(f"Payload saved to: {filename}")
            print_info(f"File size: {os.path.getsize(filename)} bytes")
        except Exception as e:
            print_error(f"Could not save payload to file: {e}")
