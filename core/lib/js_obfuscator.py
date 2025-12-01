#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JavaScript Obfuscator for XSS injection scripts
Provides various obfuscation techniques to make JavaScript code harder to detect
"""

import re
import random
import string
from typing import Dict, Any, Optional


class JavaScriptObfuscator:
    """JavaScript code obfuscator"""
    
    def __init__(self):
        self.variable_map = {}
        self.string_encoder_map = {}
        self.counter = 0
    
    def obfuscate(self, code: str, options: Optional[Dict[str, Any]] = None) -> str:
        """
        Obfuscate JavaScript code
        
        Args:
            code: JavaScript code to obfuscate
            options: Obfuscation options dict with keys:
                - minify: bool - Remove whitespace and comments
                - rename_variables: bool - Rename variable names
                - encode_strings: bool - Encode string literals
                - add_dead_code: bool - Add dead code to confuse analysis
                - string_encoding: str - Encoding method ('hex', 'unicode', 'base64')
                
        Returns:
            str: Obfuscated JavaScript code
        """
        if not options:
            options = {}
        
        obfuscated = code
        
        # Minify code (remove comments and extra whitespace)
        if options.get('minify', False):
            obfuscated = self._minify(obfuscated)
        
        # Encode strings
        if options.get('encode_strings', False):
            encoding = options.get('string_encoding', 'hex')
            obfuscated = self._encode_strings(obfuscated, encoding)
        
        # Rename variables
        if options.get('rename_variables', False):
            obfuscated = self._rename_variables(obfuscated)
        
        # Add dead code
        if options.get('add_dead_code', False):
            obfuscated = self._add_dead_code(obfuscated)
        
        return obfuscated
    
    def _minify(self, code: str) -> str:
        """Minify JavaScript code (preserve placeholders and template literals)"""
        # First, protect placeholders and template literals
        placeholder_map = {}
        placeholder_counter = 0
        
        def protect_placeholder(match):
            nonlocal placeholder_counter
            placeholder = match.group(0)
            key = f'__PLACEHOLDER_{placeholder_counter}__'
            placeholder_map[key] = placeholder
            placeholder_counter += 1
            return key
        
        # Protect SERVER_HOST_PLACEHOLDER and SERVER_PORT_PLACEHOLDER
        code = re.sub(r'SERVER_[A-Z_]+PLACEHOLDER', protect_placeholder, code)
        
        # Protect template literals (backticks) - they contain ${} expressions
        # Match template literals: `...${...}...`
        template_pattern = r'`[^`]*(?:\$\{[^}]*\}[^`]*)*`'
        code = re.sub(template_pattern, protect_placeholder, code)
        
        # Protect function parameters with default values (e.g., function name(param = value))
        # This prevents minification from breaking function syntax
        func_default_pattern = r'function\s+\w*\s*\([^)]*=\s*[^)]*\)'
        code = re.sub(func_default_pattern, protect_placeholder, code)
        
        # Remove single-line comments (but preserve ones in strings)
        lines = code.split('\n')
        minified_lines = []
        for line in lines:
            # Simple comment removal (doesn't handle strings with //)
            if '//' in line:
                # Check if // is in a string
                in_string = False
                quote_char = None
                for i, char in enumerate(line):
                    if char in ['"', "'"] and (i == 0 or line[i-1] != '\\'):
                        if not in_string:
                            in_string = True
                            quote_char = char
                        elif char == quote_char:
                            in_string = False
                            quote_char = None
                    elif char == '/' and i + 1 < len(line) and line[i+1] == '/' and not in_string:
                        line = line[:i]
                        break
            minified_lines.append(line)
        code = '\n'.join(minified_lines)
        
        # Remove multi-line comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        
        # Remove extra whitespace (but be careful)
        code = re.sub(r'[ \t]+', ' ', code)  # Multiple spaces/tabs to single space
        code = re.sub(r'\n\s*\n', '\n', code)  # Multiple newlines to single
        
        # Restore placeholders and template literals
        for key, value in placeholder_map.items():
            code = code.replace(key, value)
        
        # Put everything on a single line (minified)
        # First, protect strings to avoid breaking them
        string_map = {}
        string_counter = 0
        
        def protect_string(match):
            nonlocal string_counter
            string_content = match.group(0)
            key = f'__STRING_{string_counter}__'
            string_map[key] = string_content
            string_counter += 1
            return key
        
        # Protect string literals (single and double quotes, but not template literals which are already protected)
        code = re.sub(r'["\'](?:[^"\'\\]|\\.)*["\']', protect_string, code)
        
        # Replace newlines and surrounding whitespace with single space
        code = re.sub(r'\s*\n\s*', ' ', code)
        # Remove multiple consecutive spaces
        code = re.sub(r' +', ' ', code)
        # Remove spaces around operators and punctuation (safe now that strings are protected)
        code = re.sub(r'\s*([{}();,=+\-*/%<>!&|?:\[\]])\s*', r'\1', code)
        # Fix cases where we removed necessary spaces (e.g., "if(" should be "if (")
        code = re.sub(r'\b(if|else|for|while|switch|function|return|var|let|const|new|typeof|instanceof|in|of)\s*\(', r'\1 (', code)
        code = re.sub(r'\b(catch|finally)\s*\(', r'\1 (', code)
        # Remove spaces around dots (but keep them for number literals)
        code = re.sub(r'\s*\.\s*', '.', code)
        # Remove spaces at start and end
        code = code.strip()
        
        # Restore protected strings
        for key, value in string_map.items():
            code = code.replace(key, value)
        
        return code
    
    def _encode_strings(self, code: str, encoding: str = 'hex') -> str:
        """Encode string literals (but skip placeholders, URLs, and template literals)"""
        # First, protect template literals (backticks) - they should not be encoded
        template_map = {}
        template_counter = 0
        
        def protect_template(match):
            nonlocal template_counter
            template = match.group(0)
            key = f'__TEMPLATE_{template_counter}__'
            template_map[key] = template
            template_counter += 1
            return key
        
        # Protect template literals
        template_pattern = r'`[^`]*(?:\$\{[^}]*\}[^`]*)*`'
        code = re.sub(template_pattern, protect_template, code)
        
        def encode_string(match):
            string_content = match.group(2)  # group(2) is the content, group(1) is the quote
            quote = match.group(1)  # group(1) is the quote character
            
            # Skip placeholders to avoid breaking functionality
            if 'PLACEHOLDER' in string_content:
                return match.group(0)
            
            # Skip only complete URLs (with protocol and path/port) to avoid breaking fetch calls
            # But encode partial URLs and other strings
            if string_content.startswith('http://') or string_content.startswith('https://'):
                # Only skip if it's a complete URL with path (contains / after protocol)
                if len(string_content) > 8 and ('/' in string_content[8:] or ':' in string_content[8:]):
                    return match.group(0)
            
            # Encode all other strings, even short ones
            try:
                if encoding == 'hex':
                    # Hex encoding
                    encoded = ''.join(f'\\x{ord(c):02x}' for c in string_content)
                    return f'{quote}{encoded}{quote}'
                elif encoding == 'unicode':
                    # Unicode encoding
                    encoded = ''.join(f'\\u{ord(c):04x}' for c in string_content)
                    return f'{quote}{encoded}{quote}'
                elif encoding == 'base64':
                    # Base64 encoding (requires atob in browser)
                    import base64
                    encoded = base64.b64encode(string_content.encode()).decode()
                    return f'atob("{encoded}")'
                else:
                    return match.group(0)
            except Exception:
                # If encoding fails, return original
                return match.group(0)
        
        # Match string literals (both single and double quotes, but NOT backticks)
        # Handle escaped quotes properly
        # Pattern: quote, then any characters (including escaped quotes), then matching quote
        pattern = r'(["\'])((?:\\.|[^\\])*?)\1'
        code = re.sub(pattern, encode_string, code)
        
        # Restore template literals
        for key, value in template_map.items():
            code = code.replace(key, value)
        
        return code
    
    def _rename_variables(self, code: str) -> str:
        """Rename variable names to obfuscated names (but skip function parameters with defaults and object properties)"""
        # Reset variable map for this obfuscation
        self.variable_map = {}
        
        # First, protect function parameters with default values to avoid breaking syntax
        protected_map = {}
        protected_counter = 0
        
        def protect_function(match):
            nonlocal protected_counter
            func_def = match.group(0)
            key = f'__FUNC_{protected_counter}__'
            protected_map[key] = func_def
            protected_counter += 1
            return key
        
        # Protect functions with default parameters
        code = re.sub(r'function\s+\w*\s*\([^)]*=\s*[^)]*\)', protect_function, code)
        
        # Protect object properties (e.g., window.kittysploit = {...})
        # Match patterns like: object.property or object['property']
        object_prop_pattern = r'\w+\.\w+|\w+\[\'[^\']+\'\]|\w+\["[^"]+"\]'
        code = re.sub(object_prop_pattern, protect_function, code)
        
        # Find all variable declarations (let, const, var) but exclude object properties
        # Only match standalone declarations, not object properties
        variable_pattern = r'\b(let|const|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\b'
        
        def replace_var(match):
            var_type = match.group(1)
            var_name = match.group(2)
            
            # Skip if already mapped or is a reserved word
            reserved_words = [
                'function', 'return', 'if', 'else', 'for', 'while', 'switch', 'case', 'break', 'continue',
                'window', 'document', 'navigator', 'localStorage', 'fetch', 'setTimeout', 'setInterval', 
                'clearInterval', 'Math', 'Date', 'Error', 'JSON', 'eval', 'alert', 'console', 'Object',
                'String', 'Number', 'Boolean', 'Array', 'Promise', 'Response', 'Request', 'AbortSignal'
            ]
            
            # Also skip common variable names that are likely object properties or methods
            common_names = ['data', 'response', 'error', 'command', 'result', 'sessionId', 'session_id']
            
            if var_name in self.variable_map or var_name in reserved_words or var_name in common_names:
                return match.group(0)
            
            # Generate obfuscated name
            obfuscated_name = self._generate_obfuscated_name()
            self.variable_map[var_name] = obfuscated_name
            
            return f'{var_type} {obfuscated_name}'
        
        # Replace variable declarations (only standalone, not in object literals)
        # Process line by line to check context
        lines = code.split('\n')
        processed_lines = []
        in_object_literal = False
        brace_count = 0
        
        for line in lines:
            # Track brace balance to detect object literals
            line_braces = line.count('{') - line.count('}')
            if line_braces > 0:
                in_object_literal = True
            elif line_braces < 0:
                brace_count += line_braces
                if brace_count <= 0:
                    in_object_literal = False
                    brace_count = 0
            
            # Only replace variables if not in object literal
            if not in_object_literal:
                line = re.sub(variable_pattern, replace_var, line)
            
            processed_lines.append(line)
        
        code = '\n'.join(processed_lines)
        
        # Replace variable usages (but be careful not to replace object properties)
        for original, obfuscated in self.variable_map.items():
            # Use word boundaries and negative lookahead/lookbehind to avoid matching in object properties
            # Pattern: word boundary, variable name, word boundary, but not preceded by . or [
            pattern = r'(?<!\.)(?<!\[)\b' + re.escape(original) + r'\b(?!\s*=)'
            code = re.sub(pattern, obfuscated, code)
        
        # Restore protected functions and object properties
        for key, value in protected_map.items():
            code = code.replace(key, value)
        
        return code
    
    def _generate_obfuscated_name(self) -> str:
        """Generate an obfuscated variable name"""
        # Use short random names like _0x1a2b3c
        hex_chars = ''.join(random.choices('0123456789abcdef', k=6))
        return f'_0x{hex_chars}'
    
    def _add_dead_code(self, code: str) -> str:
        """Add dead code to confuse analysis (but only in safe locations)"""
        dead_code_snippets = [
            'if(false){var _0xdead=Math.random();}',
            'var _0xdecoy=function(){return false;};',
        ]
        
        # Insert dead code only at safe positions (after semicolons or closing braces)
        # Split by semicolons and closing braces to find safe insertion points
        lines = code.split('\n')
        safe_positions = []
        
        for i, line in enumerate(lines):
            # Safe to insert after lines ending with ; or }
            stripped = line.strip()
            # Only insert after complete statements
            if stripped and (stripped.endswith(';') or (stripped.endswith('}') and not stripped.endswith('{}'))):
                # Make sure we're not inside a function call or object literal
                # Check that the line has balanced braces/parentheses
                open_parens = stripped.count('(') - stripped.count(')')
                open_braces = stripped.count('{') - stripped.count('}')
                if open_parens == 0 and open_braces <= 0:
                    safe_positions.append(i + 1)
        
        if safe_positions and len(lines) > 3:
            # Choose a random safe position, but limit to first few safe positions
            # to avoid inserting too late in the code
            max_insert = min(3, len(safe_positions))
            if max_insert > 0:
                insert_pos = random.choice(safe_positions[:max_insert])
                # Make sure we don't insert at the very end
                if insert_pos < len(lines) - 5:  # Leave some space at the end
                    dead_code = random.choice(dead_code_snippets)
                    lines.insert(insert_pos, dead_code)
        
        return '\n'.join(lines)
    
    def simple_obfuscate(self, code: str) -> str:
        """
        Simple obfuscation: minify and basic encoding
        
        Args:
            code: JavaScript code to obfuscate
            
        Returns:
            str: Obfuscated code
        """
        return self.obfuscate(code, {
            'minify': True,
            'encode_strings': False,  # Disable by default as it can break code
            'rename_variables': False,  # Disable by default as it can break code
            'add_dead_code': False
        })
    
    def medium_obfuscate(self, code: str) -> str:
        """
        Medium obfuscation: minify + string encoding
        
        Args:
            code: JavaScript code to obfuscate
            
        Returns:
            str: Obfuscated code
        """
        return self.obfuscate(code, {
            'minify': True,
            'encode_strings': True,
            'string_encoding': 'hex',
            'rename_variables': False,
            'add_dead_code': False
        })
    
    def heavy_obfuscate(self, code: str) -> str:
        """
        Heavy obfuscation: minify + encode strings + dead code + number encoding + function wrapping
        Advanced obfuscation techniques to make code harder to analyze
        
        Args:
            code: JavaScript code to obfuscate
            
        Returns:
            str: Obfuscated code
        """
        # First apply standard obfuscation
        obfuscated = self.obfuscate(code, {
            'minify': True,
            'encode_strings': True,
            'string_encoding': 'unicode',
            'rename_variables': False,  # Disabled - too risky, can break syntax
            'add_dead_code': True
        })
        
        # Apply advanced obfuscation techniques
        obfuscated = self._encode_numbers(obfuscated)
        obfuscated = self._add_advanced_dead_code(obfuscated)
        obfuscated = self._wrap_functions(obfuscated)
        obfuscated = self._obfuscate_control_flow(obfuscated)
        
        return obfuscated
    
    def _encode_numbers(self, code: str) -> str:
        """Encode numbers in complex expressions"""
        # Protect strings and template literals first
        string_map = {}
        string_counter = 0
        
        def protect_string(match):
            nonlocal string_counter
            string_content = match.group(0)
            key = f'__NUMSTR_{string_counter}__'
            string_map[key] = string_content
            string_counter += 1
            return key
        
        # Protect strings and template literals
        code = re.sub(r'["\'`](?:[^"\'`\\]|\\.)*["\'`]', protect_string, code)
        
        # Encode simple numbers (0-100) in complex expressions
        def encode_number(match):
            num_str = match.group(0)
            try:
                num = int(num_str)
                if 0 <= num <= 100:
                    # Use various encoding methods randomly
                    methods = [
                        lambda n: f'({n}^0)',
                        lambda n: f'({n}*1)',
                        lambda n: f'({n}+0)',
                        lambda n: f'({n}-0)',
                        lambda n: f'({n}>>0)',
                        lambda n: f'({n}|0)',
                        lambda n: f'({n}&0xFFFFFFFF)',
                        lambda n: f'Math.floor({n})',
                        lambda n: f'parseInt({n})',
                    ]
                    # For some numbers, use more complex expressions
                    if num > 10:
                        methods.extend([
                            lambda n: f'({n//2}*2+{n%2})',
                            lambda n: f'({n-1}+1)',
                            lambda n: f'({n+1}-1)',
                        ])
                    return random.choice(methods)(num)
                return num_str
            except:
                return num_str
        
        # Match numbers (but not in strings, which are protected)
        code = re.sub(r'\b(\d+)\b', encode_number, code)
        
        # Restore protected strings
        for key, value in string_map.items():
            code = code.replace(key, value)
        
        return code
    
    def _add_advanced_dead_code(self, code: str) -> str:
        """Add more sophisticated dead code (keeps code on single line)"""
        dead_code_snippets = [
            'var _0xdead=function(_0xarg){return _0xarg===_0xarg;};',
            'if(false){var _0xunused=Math.random()*Math.PI;var _0xdecoy=_0xunused.toString();}',
            'var _0xdecoy=function(){var _0xa=1;var _0xb=2;return _0xa+_0xb-3;};',
            'var _0xfake=function(_0xparam){try{return eval(_0xparam);}catch(_0xe){return null;}};',
            'if(!true){var _0xhidden=function(){return String.fromCharCode(65,66,67);};}',
            'var _0xmask=function(_0xval){return _0xval!==undefined?void 0:null;};',
            'var _0xobf=function(_0xinput){return _0xinput&&!_0xinput;};',
        ]
        
        # Find safe insertion points (after semicolons or closing braces)
        # Work with the single-line code
        safe_positions = []
        i = 0
        while i < len(code):
            # Look for semicolons or closing braces
            if code[i] == ';' or (code[i] == '}' and i + 1 < len(code) and code[i+1] not in ['{', '(']):
                # Check if we're in a safe position (balanced parentheses/braces before)
                before = code[:i+1]
                open_parens = before.count('(') - before.count(')')
                open_braces = before.count('{') - before.count('}')
                if open_parens == 0 and open_braces <= 0:
                    safe_positions.append(i + 1)
            i += 1
        
        # Insert multiple dead code snippets
        if safe_positions and len(code) > 100:
            num_insertions = min(random.randint(2, 4), len(safe_positions))
            insert_positions = random.sample(safe_positions, num_insertions)
            insert_positions.sort(reverse=True)  # Insert from end to preserve indices
            
            for pos in insert_positions:
                if pos < len(code) - 50:
                    dead_code = random.choice(dead_code_snippets)
                    code = code[:pos] + dead_code + code[pos:]
        
        return code
    
    def _wrap_functions(self, code: str) -> str:
        """Wrap function calls in complex expressions"""
        # Protect strings first
        string_map = {}
        string_counter = 0
        
        def protect_string(match):
            nonlocal string_counter
            string_content = match.group(0)
            key = f'__WRAPSTR_{string_counter}__'
            string_map[key] = string_content
            string_counter += 1
            return key
        
        code = re.sub(r'["\'`](?:[^"\'`\\]|\\.)*["\'`]', protect_string, code)
        
        # Wrap some function calls in complex expressions
        # This is conservative to avoid breaking code
        def wrap_function_call(match):
            func_name = match.group(1)
            args = match.group(2)
            
            # Only wrap safe functions
            safe_functions = ['Math.random', 'Math.floor', 'Math.ceil', 'parseInt', 'parseFloat']
            if func_name in safe_functions:
                wrappers = [
                    lambda f, a: f'({f}({a})||0)',
                    lambda f, a: f'({f}({a})+0)',
                    lambda f, a: f'({f}({a})*1)',
                    lambda f, a: f'({f}({a})^0)',
                ]
                return random.choice(wrappers)(func_name, args)
            return match.group(0)
        
        # Match function calls (conservative pattern)
        code = re.sub(r'\b(Math\.\w+|parseInt|parseFloat)\s*\(([^)]*)\)', wrap_function_call, code)
        
        # Restore protected strings
        for key, value in string_map.items():
            code = code.replace(key, value)
        
        return code
    
    def _obfuscate_control_flow(self, code: str) -> str:
        """Obfuscate control flow with complex expressions"""
        # Protect strings first
        string_map = {}
        string_counter = 0
        
        def protect_string(match):
            nonlocal string_counter
            string_content = match.group(0)
            key = f'__CFSTR_{string_counter}__'
            string_map[key] = string_content
            string_counter += 1
            return key
        
        code = re.sub(r'["\'`](?:[^"\'`\\]|\\.)*["\'`]', protect_string, code)
        
        # Transform simple if statements to more complex ones (very conservative)
        # Only transform very simple patterns to avoid breaking code
        def obfuscate_if(match):
            condition = match.group(1)
            # Only transform if condition is very simple
            if condition.strip() in ['true', 'false', '!false', '!true']:
                if condition.strip() == 'true':
                    return f'if((!false)&&(true))'
                elif condition.strip() == 'false':
                    return f'if((!true)||(false))'
                elif condition.strip() == '!false':
                    return f'if((true)&&(!false))'
                elif condition.strip() == '!true':
                    return f'if((false)||(!true))'
            return match.group(0)
        
        # Very conservative pattern - only match simple if statements
        code = re.sub(r'\bif\s*\(\s*(true|false|!true|!false)\s*\)', obfuscate_if, code)
        
        # Restore protected strings
        for key, value in string_map.items():
            code = code.replace(key, value)
        
        return code

