#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
x86/x64 Disassembler for ROP Library
"""

import struct
from typing import List, Dict, Any, Optional, Tuple
from core.output_handler import print_info, print_success, print_error, print_warning

class Instruction:
    """Represents a disassembled instruction"""
    
    def __init__(self, address: int, bytes: bytes, mnemonic: str, operands: List[str] = None):
        self.address = address
        self.bytes = bytes
        self.mnemonic = mnemonic
        self.operands = operands or []
        self.length = len(bytes)
        self.is_ret = mnemonic == "ret"
        self.is_call = mnemonic == "call"
        self.is_jmp = mnemonic in ["jmp", "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge", "ja", "jae", "jb", "jbe"]
        self.is_pop = mnemonic == "pop"
        self.is_push = mnemonic == "push"
        self.is_syscall = mnemonic in ["syscall", "int"]
        self.is_nop = mnemonic == "nop"
    
    def __repr__(self) -> str:
        return f"0x{self.address:x}: {self.mnemonic} {' '.join(self.operands)}"
    
    def __str__(self) -> str:
        return f"0x{self.address:x}: {self.mnemonic} {' '.join(self.operands)}"

class x86Disassembler:
    """x86/x64 disassembler"""
    
    def __init__(self, is_64bit: bool = False):
        self.is_64bit = is_64bit
        self.registers_32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
        self.registers_64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", 
                            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        
        # Opcode tables
        self.opcodes = {
            0x90: "nop",
            0xC3: "ret",
            0xC2: "ret",
            0x58: "pop",
            0x50: "push",
            0x0F: "two_byte",
            0xE8: "call",
            0xE9: "jmp",
            0xEB: "jmp",
            0x74: "je",
            0x75: "jne",
            0x7C: "jl",
            0x7E: "jle",
            0x7F: "jg",
            0x7D: "jge",
            0x77: "ja",
            0x73: "jae",
            0x72: "jb",
            0x76: "jbe",
            0xCD: "int",
            0x05: "syscall"
        }
        
        # Two-byte opcodes
        self.two_byte_opcodes = {
            0x80: "jo",
            0x81: "jno",
            0x82: "jb",
            0x83: "jae",
            0x84: "je",
            0x85: "jne",
            0x86: "jbe",
            0x87: "ja",
            0x88: "js",
            0x89: "jns",
            0x8A: "jp",
            0x8B: "jnp",
            0x8C: "jl",
            0x8D: "jge",
            0x8E: "jle",
            0x8F: "jg"
        }
    
    def disassemble(self, data: bytes, start_address: int = 0) -> List[Instruction]:
        """Disassemble bytecode into instructions"""
        instructions = []
        offset = 0
        
        while offset < len(data):
            try:
                instruction = self._disassemble_instruction(data[offset:], start_address + offset)
                if instruction:
                    instructions.append(instruction)
                    offset += instruction.length
                else:
                    offset += 1  # Skip invalid byte
            except Exception as e:
                print_warning(f"Failed to disassemble at offset {offset}: {e}")
                offset += 1
        
        return instructions
    
    def _disassemble_instruction(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble a single instruction"""
        if len(data) == 0:
            return None
        
        opcode = data[0]
        
        if opcode in self.opcodes:
            mnemonic = self.opcodes[opcode]
            
            if mnemonic == "two_byte":
                return self._disassemble_two_byte(data, address)
            elif mnemonic == "ret":
                return self._disassemble_ret(data, address)
            elif mnemonic == "pop":
                return self._disassemble_pop(data, address)
            elif mnemonic == "push":
                return self._disassemble_push(data, address)
            elif mnemonic == "call":
                return self._disassemble_call(data, address)
            elif mnemonic == "jmp":
                return self._disassemble_jmp(data, address)
            elif mnemonic in ["je", "jne", "jl", "jle", "jg", "jge", "ja", "jae", "jb", "jbe"]:
                return self._disassemble_conditional_jump(data, address, mnemonic)
            elif mnemonic == "int":
                return self._disassemble_int(data, address)
            elif mnemonic == "syscall":
                return self._disassemble_syscall(data, address)
            elif mnemonic == "nop":
                return Instruction(address, data[:1], "nop")
        
        # Try to disassemble as mov instruction
        if 0x88 <= opcode <= 0x8B:
            return self._disassemble_mov(data, address)
        
        # Try to disassemble as add/sub instructions
        if 0x00 <= opcode <= 0x05:
            return self._disassemble_arithmetic(data, address)
        
        return None
    
    def _disassemble_two_byte(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble two-byte opcode"""
        if len(data) < 2:
            return None
        
        second_byte = data[1]
        if second_byte in self.two_byte_opcodes:
            mnemonic = self.two_byte_opcodes[second_byte]
            return self._disassemble_conditional_jump(data[1:], address, mnemonic)
        
        return None
    
    def _disassemble_ret(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble ret instruction"""
        if data[0] == 0xC3:
            return Instruction(address, data[:1], "ret")
        elif data[0] == 0xC2 and len(data) >= 3:
            imm16 = struct.unpack('<H', data[1:3])[0]
            return Instruction(address, data[:3], "ret", [f"0x{imm16:x}"])
        return None
    
    def _disassemble_pop(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble pop instruction"""
        if len(data) < 1:
            return None
        
        opcode = data[0]
        
        # Direct register pop (0x58-0x5F)
        if 0x58 <= opcode <= 0x5F:
            reg_index = opcode - 0x58
            registers = self.registers_64 if self.is_64bit else self.registers_32
            if reg_index < len(registers):
                return Instruction(address, data[:1], "pop", [registers[reg_index]])
        
        # Pop with ModR/M
        if opcode == 0x8F:
            return self._disassemble_pop_rm(data, address)
        
        return None
    
    def _disassemble_push(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble push instruction"""
        if len(data) < 1:
            return None
        
        opcode = data[0]
        
        # Direct register push (0x50-0x57)
        if 0x50 <= opcode <= 0x57:
            reg_index = opcode - 0x50
            registers = self.registers_64 if self.is_64bit else self.registers_32
            if reg_index < len(registers):
                return Instruction(address, data[:1], "push", [registers[reg_index]])
        
        # Push immediate
        if opcode == 0x68 and len(data) >= 5:
            imm32 = struct.unpack('<I', data[1:5])[0]
            return Instruction(address, data[:5], "push", [f"0x{imm32:x}"])
        
        return None
    
    def _disassemble_call(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble call instruction"""
        if len(data) < 5:
            return None
        
        if data[0] == 0xE8:
            # Call relative
            rel32 = struct.unpack('<i', data[1:5])[0]
            target = address + 5 + rel32
            return Instruction(address, data[:5], "call", [f"0x{target:x}"])
        
        return None
    
    def _disassemble_jmp(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble jmp instruction"""
        if len(data) < 2:
            return None
        
        if data[0] == 0xE9 and len(data) >= 5:
            # JMP relative 32-bit
            rel32 = struct.unpack('<i', data[1:5])[0]
            target = address + 5 + rel32
            return Instruction(address, data[:5], "jmp", [f"0x{target:x}"])
        elif data[0] == 0xEB and len(data) >= 2:
            # JMP relative 8-bit
            rel8 = struct.unpack('<b', data[1:2])[0]
            target = address + 2 + rel8
            return Instruction(address, data[:2], "jmp", [f"0x{target:x}"])
        
        return None
    
    def _disassemble_conditional_jump(self, data: bytes, address: int, mnemonic: str) -> Optional[Instruction]:
        """Disassemble conditional jump instruction"""
        if len(data) < 2:
            return None
        
        if data[0] == 0x0F and len(data) >= 3:
            # Two-byte conditional jump
            rel8 = struct.unpack('<b', data[2:3])[0]
            target = address + 3 + rel8
            return Instruction(address, data[:3], mnemonic, [f"0x{target:x}"])
        elif len(data) >= 2:
            # One-byte conditional jump
            rel8 = struct.unpack('<b', data[1:2])[0]
            target = address + 2 + rel8
            return Instruction(address, data[:2], mnemonic, [f"0x{target:x}"])
        
        return None
    
    def _disassemble_int(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble int instruction"""
        if len(data) < 2:
            return None
        
        if data[0] == 0xCD:
            imm8 = data[1]
            return Instruction(address, data[:2], "int", [f"0x{imm8:x}"])
        
        return None
    
    def _disassemble_syscall(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble syscall instruction"""
        if len(data) < 2:
            return None
        
        if data[0] == 0x0F and data[1] == 0x05:
            return Instruction(address, data[:2], "syscall")
        
        return None
    
    def _disassemble_mov(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble mov instruction"""
        if len(data) < 2:
            return None
        
        opcode = data[0]
        modrm = data[1]
        
        # Simple mov register to register
        if 0x88 <= opcode <= 0x8B:
            reg1 = (modrm >> 3) & 0x7
            reg2 = modrm & 0x7
            registers = self.registers_64 if self.is_64bit else self.registers_32
            
            if reg1 < len(registers) and reg2 < len(registers):
                return Instruction(address, data[:2], "mov", 
                                 [registers[reg2], registers[reg1]])
        
        return None
    
    def _disassemble_arithmetic(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble arithmetic instructions"""
        if len(data) < 2:
            return None
        
        opcode = data[0]
        modrm = data[1]
        
        # ADD instruction
        if opcode == 0x01:
            reg1 = (modrm >> 3) & 0x7
            reg2 = modrm & 0x7
            registers = self.registers_64 if self.is_64bit else self.registers_32
            
            if reg1 < len(registers) and reg2 < len(registers):
                return Instruction(address, data[:2], "add", 
                                 [registers[reg2], registers[reg1]])
        
        return None
    
    def _disassemble_pop_rm(self, data: bytes, address: int) -> Optional[Instruction]:
        """Disassemble pop with ModR/M"""
        if len(data) < 2:
            return None
        
        modrm = data[1]
        reg = (modrm >> 3) & 0x7
        registers = self.registers_64 if self.is_64bit else self.registers_32
        
        if reg < len(registers):
            return Instruction(address, data[:2], "pop", [registers[reg]])
        
        return None

class ROPGadgetFinder:
    """Find ROP gadgets in disassembled code"""
    
    def __init__(self, disassembler: x86Disassembler):
        self.disassembler = disassembler
        self.gadgets = []
    
    def find_gadgets(self, instructions: List[Instruction], max_length: int = 5) -> List[Dict[str, Any]]:
        """Find ROP gadgets in instructions"""
        gadgets = []
        
        for i, instruction in enumerate(instructions):
            if instruction.is_ret:
                # Single instruction gadget
                gadget = {
                    'address': instruction.address,
                    'instructions': [instruction],
                    'length': 1,
                    'stack_operations': 0,
                    'registers': [],
                    'type': 'ret'
                }
                gadgets.append(gadget)
            
            # Multi-instruction gadgets
            for length in range(2, max_length + 1):
                if i + length > len(instructions):
                    break
                
                gadget_instructions = instructions[i:i+length]
                if gadget_instructions[-1].is_ret:
                    gadget = self._analyze_gadget(gadget_instructions)
                    if gadget:
                        gadgets.append(gadget)
        
        self.gadgets = gadgets
        return gadgets
    
    def _analyze_gadget(self, instructions: List[Instruction]) -> Optional[Dict[str, Any]]:
        """Analyze a potential gadget"""
        if not instructions or not instructions[-1].is_ret:
            return None
        
        stack_operations = 0
        registers = set()
        gadget_type = "unknown"
        
        for instruction in instructions:
            if instruction.is_pop:
                stack_operations += 1
                if instruction.operands:
                    registers.add(instruction.operands[0])
            elif instruction.is_push:
                stack_operations -= 1
                if instruction.operands:
                    registers.add(instruction.operands[0])
            elif instruction.is_syscall:
                gadget_type = "syscall"
            elif instruction.mnemonic == "mov":
                if instruction.operands:
                    registers.update(instruction.operands)
        
        if gadget_type == "unknown":
            if stack_operations > 0:
                gadget_type = "pop_chain"
            elif stack_operations < 0:
                gadget_type = "push_chain"
            else:
                gadget_type = "ret"
        
        return {
            'address': instructions[0].address,
            'instructions': instructions,
            'length': len(instructions),
            'stack_operations': stack_operations,
            'registers': list(registers),
            'type': gadget_type
        }
    
    def find_pop_gadgets(self, count: int = 1) -> List[Dict[str, Any]]:
        """Find gadgets that pop a specific number of values"""
        return [g for g in self.gadgets if g['stack_operations'] == count]
    
    def find_syscall_gadgets(self) -> List[Dict[str, Any]]:
        """Find syscall gadgets"""
        return [g for g in self.gadgets if g['type'] == 'syscall']
    
    def find_gadgets_by_register(self, register: str) -> List[Dict[str, Any]]:
        """Find gadgets that use a specific register"""
        return [g for g in self.gadgets if register in g['registers']]
    
    def get_gadget_info(self, gadget: Dict[str, Any]) -> str:
        """Get human-readable gadget information"""
        instruction_strs = [str(inst) for inst in gadget['instructions']]
        return " ; ".join(instruction_strs)
