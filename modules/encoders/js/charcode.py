from kittysploit import *

class Module(Encoder):

    
    __info__ = {
        "name": "JavaScript CharCode Encoder",
        "description": "Encodes JavaScript using String.fromCharCode() with numeric ASCII values",
        "author": "KittySploit Team",
        "platform": Platform.JAVASCRIPT,
    }
    
    # Options
    method = OptString("eval", "Execution method: 'eval', 'function', or 'constructor'", False)
    split_groups = OptBool(False, "Split character codes into groups (more evasive)", False)
    group_size = OptInteger(10, "Group size if split_groups is enabled", False)
    add_noise = OptBool(False, "Add mathematical noise to character codes", False)
    
    def encode(self, payload):

        # Convert bytes to string if needed
        if isinstance(payload, bytes):
            payload_str = payload.decode('utf-8', errors='ignore')
        else:
            payload_str = payload
        
        # Get character codes
        char_codes = [str(ord(char)) for char in payload_str]
        
        # Apply noise if requested (makes it harder to decode by eye)
        if self.add_noise:
            # Add mathematical operations that result in the same value
            # e.g., 97 becomes (100-3), 108 becomes (100+8), etc.
            noisy_codes = []
            for code in char_codes:
                code_int = int(code)
                # Randomly choose noise pattern
                import random
                noise_type = random.randint(0, 3)
                
                if noise_type == 0:
                    # Addition: code = (base + offset)
                    base = random.randint(50, 150)
                    offset = code_int - base
                    noisy_codes.append(f"({base}{offset:+d})")
                elif noise_type == 1:
                    # Multiplication: code = (base * multiplier)
                    if code_int > 0:
                        divisors = [d for d in range(2, 20) if code_int % d == 0]
                        if divisors:
                            div = random.choice(divisors)
                            noisy_codes.append(f"({code_int//div}*{div})")
                        else:
                            noisy_codes.append(code)
                    else:
                        noisy_codes.append(code)
                elif noise_type == 2:
                    # Bitwise: code = (base ^ xor_val)
                    xor_val = random.randint(1, 255)
                    base = code_int ^ xor_val
                    noisy_codes.append(f"({base}^{xor_val})")
                else:
                    # Keep original
                    noisy_codes.append(code)
            
            char_codes = noisy_codes
        
        # Build the encoded string
        method = self.method.lower() if hasattr(self.method, 'lower') else str(self.method).lower()
        
        if self.split_groups:
            # Split into groups for more obfuscation
            groups = []
            for i in range(0, len(char_codes), self.group_size):
                group = char_codes[i:i+self.group_size]
                groups.append(f"String.fromCharCode({','.join(group)})")
            
            concatenated = '+'.join(groups)
            
            if method == 'function':
                return f'Function({concatenated})()'
            elif method == 'constructor':
                return f'[].constructor.constructor({concatenated})()'
            else:  # eval (default)
                return f'eval({concatenated})'
        else:
            # Single String.fromCharCode() call
            charcode_str = ','.join(char_codes)
            
            if method == 'function':
                return f'Function(String.fromCharCode({charcode_str}))()'
            elif method == 'constructor':
                return f'[].constructor.constructor(String.fromCharCode({charcode_str}))()'
            else:  # eval (default)
                return f'eval(String.fromCharCode({charcode_str}))'


