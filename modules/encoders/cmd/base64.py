#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64

class Module(Encoder):
    
    __info__ = {
        "name": "CMD Base64 Encoder",
        "description": "Encodes command-line payloads in base64 to avoid bad characters. Supports Unix/Linux shells with multiple decoding methods.",
        "author": "KittySploit Team",
        "platform": Platform.UNIX,
    }
    
    # Base64 character set
    BASE64_BYTES = list(range(ord('A'), ord('Z') + 1)) + \
                   list(range(ord('a'), ord('z') + 1)) + \
                   list(range(ord('0'), ord('9') + 1)) + \
                   [ord('+'), ord('/'), ord('=')]
    
    # Options
    badchars = OptString("", "Bad characters to avoid (e.g., '\\x00\\x0a')", False)
    base64_decoder = OptChoice("auto", "Base64 decoder to use: 'auto', 'base64', 'base64-long', 'base64-short', 'openssl'", False, 
                               choices=['auto', 'base64', 'base64-long', 'base64-short', 'openssl'])
    
    def encode(self, payload):
        """
        Encode the payload using base64 with badchar avoidance.
        
        Args:
            payload: Command string to encode (bytes or str)
            
        Returns:
            Encoded command that decodes and executes the payload
        """
        # Convert bytes to string if needed
        if isinstance(payload, bytes):
            payload_str = payload.decode('utf-8', errors='ignore')
        else:
            payload_str = str(payload)
        
        # Parse badchars
        badchars_str = self.badchars if self.badchars else ""
        badchars_set = self._parse_badchars(badchars_str)
        
        # Check if payload contains badchars
        payload_bytes = payload_str.encode('utf-8')
        if badchars_set and any(b in badchars_set for b in payload_bytes):
            # Need to encode
            pass
        elif not badchars_set:
            # No badchars specified, encode anyway for obfuscation
            pass
        else:
            # No badchars in payload, return as-is
            return payload_str
        
        # Check if badchars conflict with base64 encoding
        if badchars_set:
            if any(b in self.BASE64_BYTES for b in badchars_set):
                raise ValueError("Badchars contain base64 characters (A-Z, a-z, 0-9, +, /, =). Cannot encode.")
            if ord('-') in badchars_set:
                raise ValueError("Badchars contain '-'. Cannot use base64 decoder.")
        
        # Encode to base64
        encoded_bytes = base64.b64encode(payload_bytes)
        encoded_str = encoded_bytes.decode('ascii')
        
        # Determine if we need to encode spaces with ${IFS}
        ifs_encode_spaces = badchars_set and ord(' ') in badchars_set
        if ifs_encode_spaces:
            if badchars_set and any(b in [ord('$'), ord('{'), ord('}')] for b in badchars_set):
                raise ValueError("Badchars contain '${}' but spaces need encoding. Cannot encode.")
        
        # Select decoder method
        decoder_method = self.base64_decoder.lower() if hasattr(self.base64_decoder, 'lower') else str(self.base64_decoder).lower()
        
        if decoder_method == 'base64':
            if badchars_set and any(b in [ord('('), ord('|'), ord(')')] for b in badchars_set):
                raise ValueError("Badchars contain '(|)'. Cannot use base64 decoder with fallback.")
            base64_decoder = '(base64 --decode||base64 -d)'
        elif decoder_method == 'base64-long':
            base64_decoder = 'base64 --decode'
        elif decoder_method == 'base64-short':
            base64_decoder = 'base64 -d'
        elif decoder_method == 'openssl':
            base64_decoder = 'openssl enc -base64 -d'
        else:  # auto
            # Find a decoder at runtime if we can use the necessary characters
            if not badchars_set or all(b not in [ord('('), ord('|'), ord(')'), ord('>'), ord('/'), ord('&')] for b in badchars_set):
                base64_decoder = '((command -v base64>/dev/null&&(base64 --decode||base64 -d))||(command -v openssl>/dev/null&&openssl enc -base64 -d))'
            elif not badchars_set or all(b not in [ord('('), ord('|'), ord(')')] for b in badchars_set):
                base64_decoder = '(base64 --decode||base64 -d)'
            else:
                base64_decoder = 'openssl enc -base64 -d'
        
        # Select injection method based on available characters
        if not badchars_set or ord('|') not in badchars_set:
            # Use pipe method: echo <base64>|decoder|sh
            result = f'echo {encoded_str}|{base64_decoder}|sh'
        elif not badchars_set or all(b not in [ord('<'), ord('('), ord(')')] for b in badchars_set):
            # Use process substitution: sh < <(decoder < <(echo <base64>))
            result = f'sh < <({base64_decoder} < <(echo {encoded_str}))'
        elif not badchars_set or all(b not in [ord('<'), ord('`'), ord("'")] for b in badchars_set):
            # Use heredoc with backticks: sh<<<`decoder<<<'<base64>'`
            result = f"sh<<<`{base64_decoder}<<<'{encoded_str}'`"
        else:
            raise ValueError("Cannot encode: badchars prevent all injection methods.")
        
        # Encode spaces with ${IFS} if needed
        if ifs_encode_spaces:
            result = result.replace(' ', '${IFS}')
        
        return result
    
    def _parse_badchars(self, badchars_str):
        """
        Parse badchars string into a set of byte values.
        
        Supports formats:
        - "\\x00\\x0a" (hex escape sequences)
        - "00 0a" (hex bytes)
        - "abc" (literal characters)
        """
        if not badchars_str:
            return set()
        
        badchars_set = set()
        
        # Handle hex escape sequences (\x00, \x0a, etc.)
        import re
        hex_escapes = re.findall(r'\\x([0-9a-fA-F]{2})', badchars_str)
        for hex_val in hex_escapes:
            badchars_set.add(int(hex_val, 16))
        
        # Handle hex bytes separated by spaces (00 0a ff)
        hex_bytes = re.findall(r'\b([0-9a-fA-F]{2})\b', badchars_str)
        for hex_val in hex_bytes:
            badchars_set.add(int(hex_val, 16))
        
        # Handle literal characters (remove already processed hex sequences)
        remaining = badchars_str
        remaining = re.sub(r'\\x[0-9a-fA-F]{2}', '', remaining)
        remaining = re.sub(r'\b[0-9a-fA-F]{2}\b', '', remaining)
        remaining = remaining.strip()
        
        for char in remaining:
            if char and char not in [' ', '\t', '\n', '\r']:
                badchars_set.add(ord(char))
        
        return badchars_set