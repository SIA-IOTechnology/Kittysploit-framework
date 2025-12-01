from kittysploit import *
import base64

class Module(Encoder):
    
    __info__ = {
        "name": "JavaScript Base64 Encoder",
        "description": "Encodes JavaScript code in base64 with atob() decoder",
        "author": "KittySploit Team",
        "platform": Platform.JAVASCRIPT,
    }
    
    # Options
    method = OptString("eval", "Decoding method: 'eval', 'function', or 'both'", False)
    split_chunks = OptBool(False, "Split base64 into chunks (more evasive)", False)
    chunk_size = OptInteger(50, "Chunk size if split_chunks is enabled", False)
    
    def encode(self, payload):

        # Convert bytes to string if needed
        if isinstance(payload, bytes):
            payload_str = payload.decode('utf-8', errors='ignore')
        else:
            payload_str = payload
        
        # Encode to base64
        encoded_bytes = base64.b64encode(payload_str.encode('utf-8'))
        encoded_str = encoded_bytes.decode('ascii')
        
        # Apply different encoding methods
        method = self.method.lower() if hasattr(self.method, 'lower') else str(self.method).lower()
        
        if self.split_chunks:
            # Split into chunks for more evasion
            chunks = []
            for i in range(0, len(encoded_str), self.chunk_size):
                chunk = encoded_str[i:i+self.chunk_size]
                chunks.append(f'"{chunk}"')
            
            concat_chunks = '+'.join(chunks)
            
            if method == 'function':
                return f'(function(){{return Function(atob({concat_chunks}))()}})();'
            elif method == 'both':
                # Use both eval and Function constructor for extra obfuscation
                return f'(function(){{var _0x1=atob({concat_chunks});eval(_0x1)}})();'
            else:  # eval (default)
                return f'eval(atob({concat_chunks}))'
        else:
            # Simple single-chunk encoding
            if method == 'function':
                return f'(function(){{return Function(atob("{encoded_str}"))()}})();'
            elif method == 'both':
                return f'(function(){{var _0x1=atob("{encoded_str}");eval(_0x1)}})();'
            else:  # eval (default)
                return f'eval(atob("{encoded_str}"))'
