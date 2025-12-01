#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Assembly to C Pseudo-code Converter
Converts assembly instructions to readable C-like pseudo-code
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from kittysploit.disassembler import Instruction, x86Disassembler

class CCodeGenerator:
    """Converts assembly instructions to C pseudo-code"""
    
    def __init__(self, is_64bit: bool = False):
        self.is_64bit = is_64bit
        self.registers = self._get_register_mapping()
        self.variables = {}
        self.functions = {}
        self.current_function = None
        self.indent_level = 0
        
    def _get_register_mapping(self) -> Dict[str, str]:
        """Get register to C variable mapping"""
        if self.is_64bit:
            return {
                "rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx",
                "rsi": "esi", "rdi": "edi", "rbp": "ebp", "rsp": "esp",
                "r8": "r8", "r9": "r9", "r10": "r10", "r11": "r11",
                "r12": "r12", "r13": "r13", "r14": "r14", "r15": "r15"
            }
        else:
            return {
                "eax": "eax", "ebx": "ebx", "ecx": "ecx", "edx": "edx",
                "esi": "esi", "edi": "edi", "ebp": "ebp", "esp": "esp"
            }
    
    def convert_instruction(self, instruction: Instruction) -> str:
        """Convert a single instruction to C pseudo-code"""
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.operands
        
        if mnemonic == "nop":
            return "// NOP - No operation"
        
        elif mnemonic == "ret":
            return "return;"
        
        elif mnemonic == "pop":
            if operands:
                reg = operands[0]
                c_reg = self.registers.get(reg, reg)
                return f"{c_reg} = *esp++;"
            return "esp++; // pop"
        
        elif mnemonic == "push":
            if operands:
                reg = operands[0]
                c_reg = self.registers.get(reg, reg)
                return f"*--esp = {c_reg};"
            return "*--esp = value; // push"
        
        elif mnemonic == "mov":
            if len(operands) >= 2:
                dest = operands[0]
                src = operands[1]
                c_dest = self.registers.get(dest, dest)
                c_src = self.registers.get(src, src)
                return f"{c_dest} = {c_src};"
            return "// mov instruction"
        
        elif mnemonic == "add":
            if len(operands) >= 2:
                dest = operands[0]
                src = operands[1]
                c_dest = self.registers.get(dest, dest)
                c_src = self.registers.get(src, src)
                return f"{c_dest} += {c_src};"
            return "// add instruction"
        
        elif mnemonic == "sub":
            if len(operands) >= 2:
                dest = operands[0]
                src = operands[1]
                c_dest = self.registers.get(dest, dest)
                c_src = self.registers.get(src, src)
                return f"{c_dest} -= {c_src};"
            return "// sub instruction"
        
        elif mnemonic == "call":
            if operands:
                target = operands[0]
                return f"call {target};"
            return "call function;"
        
        elif mnemonic == "jmp":
            if operands:
                target = operands[0]
                return f"goto {target};"
            return "goto label;"
        
        elif mnemonic in ["je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge", "ja", "jae", "jb", "jbe"]:
            if operands:
                target = operands[0]
                condition = self._get_condition(mnemonic)
                return f"if ({condition}) goto {target};"
            return f"if ({self._get_condition(mnemonic)}) goto label;"
        
        elif mnemonic == "int":
            if operands:
                interrupt = operands[0]
                return f"int {interrupt}; // System call"
            return "int 0x80; // System call"
        
        elif mnemonic == "syscall":
            return "syscall(); // System call"
        
        elif mnemonic == "cmp":
            if len(operands) >= 2:
                op1 = operands[0]
                op2 = operands[1]
                c_op1 = self.registers.get(op1, op1)
                c_op2 = self.registers.get(op2, op2)
                return f"// Compare {c_op1} with {c_op2}"
            return "// compare instruction"
        
        elif mnemonic == "test":
            if len(operands) >= 2:
                op1 = operands[0]
                op2 = operands[1]
                c_op1 = self.registers.get(op1, op1)
                c_op2 = self.registers.get(op2, op2)
                return f"// Test {c_op1} & {c_op2}"
            return "// test instruction"
        
        elif mnemonic == "and":
            if len(operands) >= 2:
                dest = operands[0]
                src = operands[1]
                c_dest = self.registers.get(dest, dest)
                c_src = self.registers.get(src, src)
                return f"{c_dest} &= {c_src};"
            return "// and instruction"
        
        elif mnemonic == "or":
            if len(operands) >= 2:
                dest = operands[0]
                src = operands[1]
                c_dest = self.registers.get(dest, dest)
                c_src = self.registers.get(src, src)
                return f"{c_dest} |= {c_src};"
            return "// or instruction"
        
        elif mnemonic == "xor":
            if len(operands) >= 2:
                dest = operands[0]
                src = operands[1]
                c_dest = self.registers.get(dest, dest)
                c_src = self.registers.get(src, src)
                return f"{c_dest} ^= {c_src};"
            return "// xor instruction"
        
        elif mnemonic == "shl":
            if len(operands) >= 2:
                dest = operands[0]
                src = operands[1]
                c_dest = self.registers.get(dest, dest)
                c_src = self.registers.get(src, src)
                return f"{c_dest} <<= {c_src};"
            return "// shift left instruction"
        
        elif mnemonic == "shr":
            if len(operands) >= 2:
                dest = operands[0]
                src = operands[1]
                c_dest = self.registers.get(dest, dest)
                c_src = self.registers.get(src, src)
                return f"{c_dest} >>= {c_src};"
            return "// shift right instruction"
        
        else:
            return f"// {mnemonic.upper()} instruction"
    
    def _get_condition(self, mnemonic: str) -> str:
        """Get C condition for jump instruction"""
        conditions = {
            "je": "eax == 0", "jne": "eax != 0",
            "jz": "eax == 0", "jnz": "eax != 0",
            "jl": "eax < 0", "jle": "eax <= 0",
            "jg": "eax > 0", "jge": "eax >= 0",
            "ja": "eax > 0", "jae": "eax >= 0",
            "jb": "eax < 0", "jbe": "eax <= 0"
        }
        return conditions.get(mnemonic, "condition")
    
    def convert_instructions(self, instructions: List[Instruction]) -> str:
        """Convert a list of instructions to C pseudo-code"""
        c_code = []
        
        # Add function header
        c_code.append("void gadget() {")
        c_code.append("    // Assembly to C pseudo-code")
        c_code.append("")
        
        for instruction in instructions:
            c_line = self.convert_instruction(instruction)
            c_code.append(f"    {c_line}")
        
        c_code.append("}")
        
        return "\n".join(c_code)
    
    def convert_gadget(self, gadget_info: Dict[str, Any]) -> str:
        """Convert a ROP gadget to C pseudo-code"""
        instructions = gadget_info.get('instructions', [])
        address = gadget_info.get('address', 0)
        gadget_type = gadget_info.get('type', 'unknown')
        
        c_code = []
        c_code.append(f"// ROP Gadget at 0x{address:x}")
        c_code.append(f"// Type: {gadget_type}")
        c_code.append(f"// Stack operations: {gadget_info.get('stack_operations', 0)}")
        c_code.append("")
        
        if gadget_type == "ret":
            c_code.append("void gadget() {")
            c_code.append("    return;")
            c_code.append("}")
        elif gadget_type == "pop_chain":
            c_code.append("void gadget() {")
            for i in range(gadget_info.get('stack_operations', 0)):
                c_code.append(f"    // Pop value {i+1} from stack")
                c_code.append(f"    reg{i+1} = *esp++;")
            c_code.append("    return;")
            c_code.append("}")
        elif gadget_type == "syscall":
            c_code.append("void gadget() {")
            c_code.append("    // Set up syscall parameters")
            for instruction in instructions:
                c_line = self.convert_instruction(instruction)
                c_code.append(f"    {c_line}")
            c_code.append("}")
        else:
            c_code.append("void gadget() {")
            for instruction in instructions:
                c_line = self.convert_instruction(instruction)
                c_code.append(f"    {c_line}")
            c_code.append("}")
        
        return "\n".join(c_code)
    
    def convert_rop_chain(self, gadgets: List[Dict[str, Any]]) -> str:
        """Convert a ROP chain to C pseudo-code"""
        c_code = []
        c_code.append("// ROP Chain Pseudo-code")
        c_code.append("void rop_chain() {")
        c_code.append("    // Buffer overflow payload")
        c_code.append("    char payload[BUFFER_SIZE];")
        c_code.append("    memset(payload, 'A', BUFFER_SIZE);")
        c_code.append("")
        c_code.append("    // ROP gadgets")
        
        for i, gadget in enumerate(gadgets):
            address = gadget.get('address', 0)
            gadget_type = gadget.get('type', 'unknown')
            stack_ops = gadget.get('stack_operations', 0)
            
            c_code.append(f"    // Gadget {i+1}: 0x{address:x} ({gadget_type})")
            
            if gadget_type == "ret":
                c_code.append("    return;")
            elif gadget_type == "pop_chain":
                for j in range(stack_ops):
                    c_code.append(f"    reg{j+1} = *esp++;")
                c_code.append("    return;")
            elif gadget_type == "syscall":
                c_code.append("    // System call setup")
                c_code.append("    syscall();")
            else:
                c_code.append("    // Custom gadget logic")
                c_code.append("    return;")
            
            c_code.append("")
        
        c_code.append("}")
        return "\n".join(c_code)

class AssemblyAnalyzer:
    """Analyzes assembly code and generates C pseudo-code"""
    
    def __init__(self, is_64bit: bool = False):
        self.is_64bit = is_64bit
        self.disassembler = x86Disassembler(is_64bit)
        self.c_generator = CCodeGenerator(is_64bit)
    
    def analyze_bytecode(self, bytecode: bytes, start_address: int = 0) -> str:
        """Analyze bytecode and generate C pseudo-code"""
        instructions = self.disassembler.disassemble(bytecode, start_address)
        return self.c_generator.convert_instructions(instructions)
    
    def analyze_gadgets(self, bytecode: bytes, start_address: int = 0) -> str:
        """Analyze ROP gadgets and generate C pseudo-code"""
        instructions = self.disassembler.disassemble(bytecode, start_address)
        
        from kittysploit.disassembler import ROPGadgetFinder
        gadget_finder = ROPGadgetFinder(self.disassembler)
        gadgets = gadget_finder.find_gadgets(instructions)
        
        c_code = []
        c_code.append("// ROP Gadgets Analysis")
        c_code.append("// ====================")
        c_code.append("")
        
        for i, gadget in enumerate(gadgets):
            c_code.append(f"// Gadget {i+1}")
            c_code.append(self.c_generator.convert_gadget(gadget))
            c_code.append("")
        
        return "\n".join(c_code)
    
    def analyze_function(self, bytecode: bytes, start_address: int = 0, function_name: str = "function") -> str:
        """Analyze a function and generate C pseudo-code"""
        instructions = self.disassembler.disassemble(bytecode, start_address)
        
        c_code = []
        c_code.append(f"// Function: {function_name}")
        c_code.append(f"// Address: 0x{start_address:x}")
        c_code.append("")
        
        c_code.append(f"void {function_name}() {{")
        c_code.append("    // Function prologue")
        c_code.append("")
        
        for instruction in instructions:
            c_line = self.c_generator.convert_instruction(instruction)
            c_code.append(f"    {c_line}")
        
        c_code.append("    // Function epilogue")
        c_code.append("}")
        
        return "\n".join(c_code)

def asm_to_c(bytecode: bytes, start_address: int = 0, is_64bit: bool = False) -> str:
    """Convert assembly bytecode to C pseudo-code"""
    analyzer = AssemblyAnalyzer(is_64bit)
    return analyzer.analyze_bytecode(bytecode, start_address)

def gadgets_to_c(bytecode: bytes, start_address: int = 0, is_64bit: bool = False) -> str:
    """Convert ROP gadgets to C pseudo-code"""
    analyzer = AssemblyAnalyzer(is_64bit)
    return analyzer.analyze_gadgets(bytecode, start_address)

def function_to_c(bytecode: bytes, start_address: int = 0, function_name: str = "function", is_64bit: bool = False) -> str:
    """Convert a function to C pseudo-code"""
    analyzer = AssemblyAnalyzer(is_64bit)
    return analyzer.analyze_function(bytecode, start_address, function_name)
