from kittysploit import *

class Module(Encoder):
    
    __info__ = {
        "name": "JavaScript Unicode Encoder",
        "description": "Encodes JavaScript code into Unicode escape sequences (\uXXXX)",
        "author": "KittySploit Team",
        "platform": Platform.JAVASCRIPT,
    }
    
    # Options
    wrap_eval = OptBool(True, "Wrap encoded code in eval() for auto-execution", False)
    compact = OptBool(False, "Use compact format without spaces", False)
    
    def encode(self, payload)

        # Convert bytes to string if needed
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8', errors='ignore')
        
        # Encode each character to Unicode escape sequence
        encoded = ""
        for char in payload:
            # Convert character to Unicode code point
            code_point = ord(char)
            # Format as \uXXXX (4 hex digits)
            unicode_escape = f"\\u{code_point:04x}"
            encoded += unicode_escape
        
        # Wrap in eval() if requested
        if self.wrap_eval:
            if self.compact:
                return f'eval("{encoded}")'
            else:
                return f'eval("{encoded}")'
        
        return encoded
