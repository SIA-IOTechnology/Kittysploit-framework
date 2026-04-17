import struct
from core.framework.base_module import BaseModule

class MiniX64(BaseModule):
    """
    A minimal, standalone x64 assembler specifically designed for generating 
    polymorphic shellcode stubs without requiring Keystone/Capstone.
    """
    
    __info__ = {
        "name": "Mini x64 Assembler",
        "description": "Standalone x64 assembler for generating shellcode and stubs",
        "author": "KittySploit Team",
    }
    
    REG = {
        "rax":0, "rcx":1, "rdx":2, "rbx":3, "rsp":4, "rbp":5, "rsi":6, "rdi":7,
        "r8":8, "r9":9, "r10":10, "r11":11, "r12":12, "r13":13, "r14":14, "r15":15
    }

    def __init__(self, framework=None):
        super().__init__(framework)
        self.reset_asm()

    def reset_asm(self):
        self.code = bytearray()
        self.labels = {}
        self.jumps = [] # (offset_in_code, label_name)
        self.leas = []  # (offset_in_code, label_name)

    def run(self):
        """Not intended to be run directly."""
        return True

    def get_bytes(self):
        res = bytearray(self.code)
        
        # Resolve rel8 jumps
        for offset, label in self.jumps:
            if label not in self.labels:
                raise ValueError(f"Label {label} not found")
            target = self.labels[label]
            rel8 = target - (offset + 1)
            if rel8 < -128 or rel8 > 127:
                raise ValueError(f"Jump to {label} out of range (dist: {rel8})")
            res[offset] = rel8 & 0xFF

        # Resolve rel32 LEAs
        for offset, label in self.leas:
            if label not in self.labels:
                raise ValueError(f"Label {label} not found")
            target = self.labels[label]
            rel32 = target - (offset + 4)
            res[offset:offset+4] = struct.pack("<i", rel32)
            
        return bytes(res)

    def _rex(self, w, r, x, b, force=False):
        val = 0x40 | (int(w)<<3) | ((r>>3)<<2) | ((x>>3)<<1) | (b>>3)
        if val != 0x40 or force:
            self.code.append(val)

    def _modrm(self, mod, reg, rm):
        self.code.append((mod << 6) | ((reg & 7) << 3) | (rm & 7))

    def label(self, name):
        self.labels[name] = len(self.code)

    def nop(self):
        self.code.append(0x90)

    def xchg(self, r1, r2):
        r1, r2 = self.REG[r1], self.REG[r2]
        self._rex(1, r1, 0, r2)
        self.code.append(0x87)
        self._modrm(3, r1, r2)

    def xor(self, r1, r2):
        r1, r2 = self.REG[r1], self.REG[r2]
        self._rex(1, r2, 0, r1)
        self.code.append(0x31)
        self._modrm(3, r2, r1)

    def sub(self, r1, r2):
        r1, r2 = self.REG[r1], self.REG[r2]
        self._rex(1, r2, 0, r1)
        self.code.append(0x29)
        self._modrm(3, r2, r1)

    def add_imm32(self, r, imm32):
        r = self.REG[r]
        if r == 0:
            self._rex(1, 0, 0, 0)
            self.code.append(0x05)
            self.code.extend(struct.pack("<i", imm32))
        else:
            self._rex(1, 0, 0, r)
            self.code.append(0x81)
            self._modrm(3, 0, r)
            self.code.extend(struct.pack("<i", imm32))

    def mov_imm32(self, r, imm32):
        r = self.REG[r]
        self._rex(0, 0, 0, r)
        self.code.append(0xB8 + (r & 7))
        self.code.extend(struct.pack("<i", imm32))

    def movabs(self, r, imm64):
        r = self.REG[r]
        self._rex(1, 0, 0, r)
        self.code.append(0xB8 + (r & 7))
        self.code.extend(struct.pack("<q", imm64))

    def xor_byte_ptr(self, addr_r, key_r):
        addr_r, key_r = self.REG[addr_r], self.REG[key_r]
        if addr_r in (4, 5, 12, 13):
            raise ValueError("Registers that require SIB or disp are not supported here")
        self._rex(0, key_r, 0, addr_r, force=True)
        self.code.append(0x30)
        self._modrm(0, key_r, addr_r)

    def ror(self, r, imm8):
        r = self.REG[r]
        self._rex(1, 0, 0, r)
        self.code.append(0xC1)
        self._modrm(3, 1, r)
        self.code.append(imm8 & 0xFF)

    def inc(self, r):
        r = self.REG[r]
        self._rex(1, 0, 0, r)
        self.code.append(0xFF)
        self._modrm(3, 0, r)

    def dec(self, r):
        r = self.REG[r]
        self._rex(1, 0, 0, r)
        self.code.append(0xFF)
        self._modrm(3, 1, r)

    def add_imm8(self, r, imm8):
        r = self.REG[r]
        self._rex(1, 0, 0, r)
        self.code.append(0x83)
        self._modrm(3, 0, r)
        self.code.append(imm8 & 0xFF)

    def sub_imm8(self, r, imm8):
        r = self.REG[r]
        self._rex(1, 0, 0, r)
        self.code.append(0x83)
        self._modrm(3, 5, r)
        self.code.append(imm8 & 0xFF)

    def or_imm8(self, r, imm8):
        r = self.REG[r]
        self._rex(1, 0, 0, r)
        self.code.append(0x83)
        self._modrm(3, 1, r)
        self.code.append(imm8 & 0xFF)
        
    def shl_imm8(self, r, imm8):
        r = self.REG[r]
        self._rex(1, 0, 0, r)
        self.code.append(0xC1)
        self._modrm(3, 4, r)
        self.code.append(imm8 & 0xFF)

    def test(self, r1, r2):
        r1, r2 = self.REG[r1], self.REG[r2]
        self._rex(1, r2, 0, r1)
        self.code.append(0x85)
        self._modrm(3, r2, r1)

    def cmp_imm8(self, r, imm8):
        r = self.REG[r]
        self._rex(1, 0, 0, r)
        self.code.append(0x83)
        self._modrm(3, 7, r)
        self.code.append(imm8 & 0xFF)

    def or_reg(self, r1, r2):
        r1, r2 = self.REG[r1], self.REG[r2]
        self._rex(1, r2, 0, r1)
        self.code.append(0x09)
        self._modrm(3, r2, r1)

    def jnz(self, label):
        self.code.append(0x75)
        self.jumps.append((len(self.code), label))
        self.code.append(0x00)

    def lea_rip(self, r, label):
        r = self.REG[r]
        self._rex(1, r, 0, 0)
        self.code.append(0x8D)
        self._modrm(0, r, 5)
        self.leas.append((len(self.code), label))
        self.code.extend(b"\x00\x00\x00\x00")
