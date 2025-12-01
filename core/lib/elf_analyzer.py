#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ELF Binary Analyzer for ROP Library
"""

import struct
import os
from typing import List, Dict, Any, Optional, Tuple
from core.output_handler import print_info, print_success, print_error, print_warning

class ELFHeader:
    """ELF Header parser"""
    
    def __init__(self, data: bytes):
        """Parse ELF header from binary data"""
        if len(data) < 52:  # Minimum ELF header size
            raise ValueError("Invalid ELF header size")
        
        # Parse ELF header
        self.e_ident = data[0:16]
        self.e_type = struct.unpack('<H', data[16:18])[0]
        self.e_machine = struct.unpack('<H', data[18:20])[0]
        self.e_version = struct.unpack('<I', data[20:24])[0]
        self.e_entry = struct.unpack('<I', data[24:28])[0]
        self.e_phoff = struct.unpack('<I', data[28:32])[0]
        self.e_shoff = struct.unpack('<I', data[32:36])[0]
        self.e_flags = struct.unpack('<I', data[36:40])[0]
        self.e_ehsize = struct.unpack('<H', data[40:42])[0]
        self.e_phentsize = struct.unpack('<H', data[42:44])[0]
        self.e_phnum = struct.unpack('<H', data[44:46])[0]
        self.e_shentsize = struct.unpack('<H', data[46:48])[0]
        self.e_shnum = struct.unpack('<H', data[48:50])[0]
        self.e_shstrndx = struct.unpack('<H', data[50:52])[0]
        
        # Determine if 64-bit
        self.is_64bit = self.e_ident[4] == 2  # EI_CLASS = 2 for 64-bit
        
        # Parse 64-bit specific fields if needed
        if self.is_64bit and len(data) >= 64:
            self.e_entry = struct.unpack('<Q', data[24:32])[0]
            self.e_phoff = struct.unpack('<Q', data[32:40])[0]
            self.e_shoff = struct.unpack('<Q', data[40:48])[0]
            self.e_flags = struct.unpack('<I', data[48:52])[0]
            self.e_ehsize = struct.unpack('<H', data[52:54])[0]
            self.e_phentsize = struct.unpack('<H', data[54:56])[0]
            self.e_phnum = struct.unpack('<H', data[56:58])[0]
            self.e_shentsize = struct.unpack('<H', data[58:60])[0]
            self.e_shnum = struct.unpack('<H', data[60:62])[0]
            self.e_shstrndx = struct.unpack('<H', data[62:64])[0]
    
    def get_architecture(self) -> str:
        """Get architecture string"""
        arch_map = {
            0x03: "x86",
            0x3E: "x64",
            0x28: "ARM",
            0xB7: "AArch64",
            0x08: "MIPS"
        }
        return arch_map.get(self.e_machine, "unknown")
    
    def is_executable(self) -> bool:
        """Check if binary is executable"""
        return self.e_type == 2  # ET_EXEC
    
    def is_dynamic(self) -> bool:
        """Check if binary is dynamically linked"""
        return self.e_type == 3  # ET_DYN

class ProgramHeader:
    """Program Header parser"""
    
    def __init__(self, data: bytes, is_64bit: bool = False):
        """Parse program header"""
        if is_64bit:
            if len(data) < 56:
                raise ValueError("Invalid 64-bit program header size")
            self.p_type = struct.unpack('<I', data[0:4])[0]
            self.p_flags = struct.unpack('<I', data[4:8])[0]
            self.p_offset = struct.unpack('<Q', data[8:16])[0]
            self.p_vaddr = struct.unpack('<Q', data[16:24])[0]
            self.p_paddr = struct.unpack('<Q', data[24:32])[0]
            self.p_filesz = struct.unpack('<Q', data[32:40])[0]
            self.p_memsz = struct.unpack('<Q', data[40:48])[0]
            self.p_align = struct.unpack('<Q', data[48:56])[0]
        else:
            if len(data) < 32:
                raise ValueError("Invalid 32-bit program header size")
            self.p_type = struct.unpack('<I', data[0:4])[0]
            self.p_offset = struct.unpack('<I', data[4:8])[0]
            self.p_vaddr = struct.unpack('<I', data[8:12])[0]
            self.p_paddr = struct.unpack('<I', data[12:16])[0]
            self.p_filesz = struct.unpack('<I', data[16:20])[0]
            self.p_memsz = struct.unpack('<I', data[20:24])[0]
            self.p_flags = struct.unpack('<I', data[24:28])[0]
            self.p_align = struct.unpack('<I', data[28:32])[0]
    
    def is_loadable(self) -> bool:
        """Check if segment is loadable"""
        return self.p_type == 1  # PT_LOAD
    
    def is_executable(self) -> bool:
        """Check if segment is executable"""
        return bool(self.p_flags & 0x1)  # PF_X flag
    
    def is_writable(self) -> bool:
        """Check if segment is writable"""
        return bool(self.p_flags & 0x2)  # PF_W flag

class SectionHeader:
    """Section Header parser"""
    
    def __init__(self, data: bytes, is_64bit: bool = False):
        """Parse section header"""
        if is_64bit:
            if len(data) < 64:
                raise ValueError("Invalid 64-bit section header size")
            self.sh_name = struct.unpack('<I', data[0:4])[0]
            self.sh_type = struct.unpack('<I', data[4:8])[0]
            self.sh_flags = struct.unpack('<Q', data[8:16])[0]
            self.sh_addr = struct.unpack('<Q', data[16:24])[0]
            self.sh_offset = struct.unpack('<Q', data[24:32])[0]
            self.sh_size = struct.unpack('<Q', data[32:40])[0]
            self.sh_link = struct.unpack('<I', data[40:44])[0]
            self.sh_info = struct.unpack('<I', data[44:48])[0]
            self.sh_addralign = struct.unpack('<Q', data[48:56])[0]
            self.sh_entsize = struct.unpack('<Q', data[56:64])[0]
        else:
            if len(data) < 40:
                raise ValueError("Invalid 32-bit section header size")
            self.sh_name = struct.unpack('<I', data[0:4])[0]
            self.sh_type = struct.unpack('<I', data[4:8])[0]
            self.sh_flags = struct.unpack('<I', data[8:12])[0]
            self.sh_addr = struct.unpack('<I', data[12:16])[0]
            self.sh_offset = struct.unpack('<I', data[16:20])[0]
            self.sh_size = struct.unpack('<I', data[20:24])[0]
            self.sh_link = struct.unpack('<I', data[24:28])[0]
            self.sh_info = struct.unpack('<I', data[28:32])[0]
            self.sh_addralign = struct.unpack('<I', data[32:36])[0]
            self.sh_entsize = struct.unpack('<I', data[36:40])[0]
    
    def is_executable(self) -> bool:
        """Check if section is executable"""
        return bool(self.sh_flags & 0x4)  # SHF_EXECINSTR flag
    
    def is_writable(self) -> bool:
        """Check if section is writable"""
        return bool(self.sh_flags & 0x1)  # SHF_WRITE flag

class ELFAnalyzer:
    """Complete ELF binary analyzer"""
    
    def __init__(self, binary_path: str):
        """Initialize ELF analyzer"""
        self.binary_path = binary_path
        self.data = b""
        self.elf_header = None
        self.program_headers = []
        self.section_headers = []
        self.string_table = b""
        self.symbols = []
        self.imports = []
        self.exports = []
        
        self._load_binary()
        self._parse_elf()
    
    def _load_binary(self):
        """Load binary file into memory"""
        try:
            with open(self.binary_path, 'rb') as f:
                self.data = f.read()
            print_success(f"Loaded binary: {self.binary_path} ({len(self.data)} bytes)")
        except Exception as e:
            print_error(f"Failed to load binary: {e}")
            raise
    
    def _parse_elf(self):
        """Parse ELF structure"""
        if len(self.data) < 52:
            raise ValueError("File too small to be a valid ELF")
        
        # Check ELF magic
        if self.data[:4] != b'\x7fELF':
            raise ValueError("Not a valid ELF file")
        
        # Parse ELF header
        self.elf_header = ELFHeader(self.data)
        print_info(f"Architecture: {self.elf_header.get_architecture()}")
        print_info(f"64-bit: {self.elf_header.is_64bit}")
        print_info(f"Entry point: 0x{self.elf_header.e_entry:x}")
        
        # Parse program headers
        self._parse_program_headers()
        
        # Parse section headers
        self._parse_section_headers()
        
        # Parse symbol table
        self._parse_symbols()
    
    def _parse_program_headers(self):
        """Parse program headers"""
        if self.elf_header.e_phnum == 0:
            return
        
        ph_size = 32 if not self.elf_header.is_64bit else 56
        ph_offset = self.elf_header.e_phoff
        
        for i in range(self.elf_header.e_phnum):
            start = ph_offset + (i * ph_size)
            end = start + ph_size
            if end > len(self.data):
                break
            
            ph_data = self.data[start:end]
            try:
                ph = ProgramHeader(ph_data, self.elf_header.is_64bit)
                self.program_headers.append(ph)
            except Exception as e:
                print_warning(f"Failed to parse program header {i}: {e}")
        
        print_success(f"Parsed {len(self.program_headers)} program headers")
    
    def _parse_section_headers(self):
        """Parse section headers"""
        if self.elf_header.e_shnum == 0:
            return
        
        sh_size = 40 if not self.elf_header.is_64bit else 64
        sh_offset = self.elf_header.e_shoff
        
        for i in range(self.elf_header.e_shnum):
            start = sh_offset + (i * sh_size)
            end = start + sh_size
            if end > len(self.data):
                break
            
            sh_data = self.data[start:end]
            try:
                sh = SectionHeader(sh_data, self.elf_header.is_64bit)
                self.section_headers.append(sh)
            except Exception as e:
                print_warning(f"Failed to parse section header {i}: {e}")
        
        # Parse string table
        self._parse_string_table()
        
        print_success(f"Parsed {len(self.section_headers)} section headers")
    
    def _parse_string_table(self):
        """Parse string table"""
        if self.elf_header.e_shstrndx >= len(self.section_headers):
            return
        
        strtab_sh = self.section_headers[self.elf_header.e_shstrndx]
        start = strtab_sh.sh_offset
        end = start + strtab_sh.sh_size
        
        if end <= len(self.data):
            self.string_table = self.data[start:end]
    
    def _parse_symbols(self):
        """Parse symbol table"""
        # Find symbol table sections
        symtab_sh = None
        strtab_sh = None
        
        for sh in self.section_headers:
            if sh.sh_type == 2:  # SHT_SYMTAB
                symtab_sh = sh
            elif sh.sh_type == 3:  # SHT_STRTAB
                strtab_sh = sh
        
        if not symtab_sh or not strtab_sh:
            return
        
        # Parse symbols
        sym_size = 16 if not self.elf_header.is_64bit else 24
        sym_count = symtab_sh.sh_size // sym_size
        
        for i in range(sym_count):
            start = symtab_sh.sh_offset + (i * sym_size)
            end = start + sym_size
            if end > len(self.data):
                break
            
            sym_data = self.data[start:end]
            symbol = self._parse_symbol(sym_data, strtab_sh)
            if symbol:
                self.symbols.append(symbol)
        
        print_success(f"Parsed {len(self.symbols)} symbols")
    
    def _parse_symbol(self, data: bytes, strtab_sh: SectionHeader) -> Optional[Dict[str, Any]]:
        """Parse a single symbol"""
        try:
            if self.elf_header.is_64bit:
                st_name = struct.unpack('<I', data[0:4])[0]
                st_info = data[4]
                st_other = data[5]
                st_shndx = struct.unpack('<H', data[6:8])[0]
                st_value = struct.unpack('<Q', data[8:16])[0]
                st_size = struct.unpack('<Q', data[16:24])[0]
            else:
                st_name = struct.unpack('<I', data[0:4])[0]
                st_value = struct.unpack('<I', data[4:8])[0]
                st_size = struct.unpack('<I', data[8:12])[0]
                st_info = data[12]
                st_other = data[13]
                st_shndx = struct.unpack('<H', data[14:16])[0]
            
            # Get symbol name
            name = ""
            if st_name > 0 and st_name < strtab_sh.sh_size:
                name_start = strtab_sh.sh_offset + st_name
                name_end = name_start
                while name_end < len(self.data) and self.data[name_end] != 0:
                    name_end += 1
                name = self.data[name_start:name_end].decode('utf-8', errors='ignore')
            
            return {
                'name': name,
                'value': st_value,
                'size': st_size,
                'info': st_info,
                'shndx': st_shndx
            }
        except Exception as e:
            print_warning(f"Failed to parse symbol: {e}")
            return None
    
    def get_executable_sections(self) -> List[SectionHeader]:
        """Get all executable sections"""
        return [sh for sh in self.section_headers if sh.is_executable()]
    
    def get_writable_sections(self) -> List[SectionHeader]:
        """Get all writable sections"""
        return [sh for sh in self.section_headers if sh.is_writable()]
    
    def get_executable_segments(self) -> List[ProgramHeader]:
        """Get all executable segments"""
        return [ph for ph in self.program_headers if ph.is_loadable() and ph.is_executable()]
    
    def get_writable_segments(self) -> List[ProgramHeader]:
        """Get all writable segments"""
        return [ph for ph in self.program_headers if ph.is_loadable() and ph.is_writable()]
    
    def get_section_by_name(self, name: str) -> Optional[SectionHeader]:
        """Get section by name"""
        for sh in self.section_headers:
            if self.get_section_name(sh) == name:
                return sh
        return None
    
    def get_section_name(self, sh: SectionHeader) -> str:
        """Get section name from string table"""
        if sh.sh_name >= len(self.string_table):
            return ""
        
        name_start = sh.sh_name
        name_end = name_start
        while name_end < len(self.string_table) and self.string_table[name_end] != 0:
            name_end += 1
        
        return self.string_table[name_start:name_end].decode('utf-8', errors='ignore')
    
    def get_symbol_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get symbol by name"""
        for symbol in self.symbols:
            if symbol['name'] == name:
                return symbol
        return None
    
    def get_imported_functions(self) -> List[Dict[str, Any]]:
        """Get imported functions"""
        imports = []
        for symbol in self.symbols:
            if symbol['shndx'] == 0:  # Undefined symbol
                imports.append(symbol)
        return imports
    
    def get_exported_functions(self) -> List[Dict[str, Any]]:
        """Get exported functions"""
        exports = []
        for symbol in self.symbols:
            if symbol['value'] > 0 and symbol['shndx'] > 0:
                exports.append(symbol)
        return exports
    
    def get_binary_info(self) -> Dict[str, Any]:
        """Get comprehensive binary information"""
        return {
            'path': self.binary_path,
            'size': len(self.data),
            'architecture': self.elf_header.get_architecture(),
            'is_64bit': self.elf_header.is_64bit,
            'entry_point': self.elf_header.e_entry,
            'is_executable': self.elf_header.is_executable(),
            'is_dynamic': self.elf_header.is_dynamic(),
            'program_headers': len(self.program_headers),
            'section_headers': len(self.section_headers),
            'symbols': len(self.symbols),
            'executable_sections': len(self.get_executable_sections()),
            'writable_sections': len(self.get_writable_sections()),
            'executable_segments': len(self.get_executable_segments()),
            'writable_segments': len(self.get_writable_segments())
        }
