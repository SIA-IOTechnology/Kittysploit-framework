#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pattern command implementation
"""

import string
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
from core.utils.exceptions import MaxLengthException, WasNotFoundException

MAX_PATTERN_LENGTH = 20280

def pattern_create(length: int):
    """Create a cyclic pattern of specified length"""
    if int(length) >= MAX_PATTERN_LENGTH:
        raise MaxLengthException(f'ERROR: Pattern length exceeds maximum of {MAX_PATTERN_LENGTH}')
    
    pattern = ''
    for upper in string.ascii_uppercase:
        for lower in string.ascii_lowercase:
            for digit in string.digits:
                if len(pattern) < int(length):
                    pattern += upper + lower + digit
                else:
                    out = pattern[:int(length)]
                    return out
    
    return pattern[:int(length)]

def pattern_offset(search_pattern):
    """Find the offset of a pattern in the cyclic pattern"""
    needle = search_pattern
    is_hex = False
    
    try:
        if needle.startswith('0x'):
            is_hex = True
            needle = needle[2:]
            # Convert hex to bytes, then to ASCII string (little-endian)
            # 0x414243 -> bytes [0x41, 0x42, 0x43] -> "ABC" -> reverse to "CBA" (little-endian)
            hex_bytes = bytearray.fromhex(needle)
            # Reverse for little-endian (as seen in memory)
            hex_bytes.reverse()
            needle = hex_bytes.decode('ascii', errors='ignore')
    except (ValueError, TypeError) as e:
        raise
    
    # Build the full pattern haystack (same as pattern_create)
    haystack = ''
    for upper in string.ascii_uppercase:
        for lower in string.ascii_lowercase:
            for digit in string.digits:
                haystack += upper + lower + digit
    
    # Search for the needle in the haystack
    found_at = haystack.find(needle)
    if found_at > -1:
        return found_at
    
    # Provide helpful error message
    error_msg = f'Couldn\'t find {search_pattern}'
    if is_hex:
        error_msg += f' (decoded as "{needle}" in little-endian)'
    else:
        error_msg += f' ("{needle}")'
    error_msg += ' anywhere in the pattern.'
    error_msg += '\nNote: The pattern uses format [A-Z][a-z][0-9] (e.g., Aa0, Aa1, Bb0, etc.)'
    if is_hex:
        error_msg += '\nExample: Try "0x306141" which represents "Aa0" in little-endian'
    raise WasNotFoundException(error_msg)

class PatternCommand(BaseCommand):
    """Command to create patterns and find offsets"""
    
    @property
    def name(self) -> str:
        return "pattern"
    
    @property
    def description(self) -> str:
        return "Create cyclic patterns and find offsets (useful for buffer overflow exploitation)"
    
    @property
    def usage(self) -> str:
        return "pattern [create <length>|offset <pattern>]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Commands:
    create <length>  - Create a cyclic pattern of specified length
    offset <pattern> - Find the offset of a pattern in the cyclic sequence
                       Pattern can be a string or hex value (e.g., 0x414243)

Examples:
    pattern create 100        # Generate a 100-byte pattern
    pattern offset Aa0        # Find offset of "Aa0"
    pattern offset 0x414243   # Find offset of hex value 0x414243
    pattern offset 0x634241   # Find offset of little-endian hex value

Note: Maximum pattern length is {MAX_PATTERN_LENGTH} bytes
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the pattern command"""
        if len(args) == 0:
            # Show help when no arguments provided
            print_info(self.help_text)
            return True
        
        command = args[0].lower()
        
        # Handle help flags
        if command in ['--help', '-h', 'help']:
            print_info(self.help_text)
            return True
        
        if command == "create":
            if len(args) < 2:
                print_error("Usage: pattern create <length>")
                return False
            
            try:
                length = int(args[1])
                if length <= 0:
                    print_error("Length must be a positive integer")
                    return False
                
                pattern = pattern_create(length)
                print_success(f"Pattern created ({length} bytes):")
                print_info(pattern)
                return True
            except ValueError:
                print_error(f"Invalid length: {args[1]}")
                return False
            except MaxLengthException as e:
                print_error(str(e))
                return False
            except Exception as e:
                print_error(f"Error creating pattern: {str(e)}")
                return False
        
        elif command == "offset":
            if len(args) < 2:
                print_error("Usage: pattern offset <pattern>")
                return False
            
            search_pattern = args[1]
            
            try:
                offset = pattern_offset(search_pattern)
                print_success(f"Pattern found at offset: {offset}")
                return True
            except WasNotFoundException as e:
                print_error(str(e))
                return False
            except Exception as e:
                print_error(f"Error finding offset: {str(e)}")
                return False
        
        else:
            print_error(f"Unknown command: {command}")
            print_info(f"Usage: {self.usage}")
            print_info("Use 'pattern --help' for more information")
            return False

