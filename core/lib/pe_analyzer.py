#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PE Binary Analyzer for ROP Library
Basic PE file analysis functionality
"""

import struct
import os
from typing import List, Dict, Any, Optional, Tuple
from core.output_handler import print_info, print_success, print_error, print_warning

class PEHeader:
    """PE Header parser"""
    
    def __init__(self, data: bytes):
        """Parse PE header from binary data"""
        if len(data) < 64:  # Minimum PE header size
            raise ValueError("Invalid PE header size")
        
        # Check DOS signature
        if data[0:2] != b'MZ':
            raise ValueError("Invalid DOS signature")
        
        # Parse DOS header
        self.e_magic = data[0:2]
        self.e_lfanew = struct.unpack('<I', data[60:64])[0]
        
        # Check if we have enough data for PE header
        if self.e_lfanew >= len(data) or self.e_lfanew < 0:
            raise ValueError("Invalid PE header offset")
        
        # Parse PE signature
        pe_offset = self.e_lfanew
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            raise ValueError("Invalid PE signature")
        
        # Parse COFF header
        coff_offset = pe_offset + 4
        self.machine = struct.unpack('<H', data[coff_offset:coff_offset+2])[0]
        self.number_of_sections = struct.unpack('<H', data[coff_offset+2:coff_offset+4])[0]
        self.time_date_stamp = struct.unpack('<I', data[coff_offset+4:coff_offset+8])[0]
        self.pointer_to_symbol_table = struct.unpack('<I', data[coff_offset+8:coff_offset+12])[0]
        self.number_of_symbols = struct.unpack('<I', data[coff_offset+12:coff_offset+16])[0]
        self.size_of_optional_header = struct.unpack('<H', data[coff_offset+16:coff_offset+18])[0]
        self.characteristics = struct.unpack('<H', data[coff_offset+18:coff_offset+20])[0]
        
        # Determine if 64-bit
        self.is_64bit = self.machine == 0x8664  # IMAGE_FILE_MACHINE_AMD64
        
        # Parse optional header
        opt_header_offset = coff_offset + 20
        if self.size_of_optional_header > 0:
            self.magic = struct.unpack('<H', data[opt_header_offset:opt_header_offset+2])[0]
            self.is_pe32_plus = self.magic == 0x20b  # PE32+
            
            if self.is_pe32_plus:
                # PE32+ header
                self.address_of_entry_point = struct.unpack('<Q', data[opt_header_offset+16:opt_header_offset+24])[0]
                self.image_base = struct.unpack('<Q', data[opt_header_offset+24:opt_header_offset+32])[0]
                self.section_alignment = struct.unpack('<I', data[opt_header_offset+32:opt_header_offset+36])[0]
                self.file_alignment = struct.unpack('<I', data[opt_header_offset+36:opt_header_offset+40])[0]
            else:
                # PE32 header
                self.address_of_entry_point = struct.unpack('<I', data[opt_header_offset+16:opt_header_offset+20])[0]
                self.image_base = struct.unpack('<I', data[opt_header_offset+28:opt_header_offset+32])[0]
                self.section_alignment = struct.unpack('<I', data[opt_header_offset+32:opt_header_offset+36])[0]
                self.file_alignment = struct.unpack('<I', data[opt_header_offset+36:opt_header_offset+40])[0]

class PESection:
    """PE Section parser"""
    
    def __init__(self, data: bytes, offset: int):
        """Parse PE section from binary data"""
        if offset + 40 > len(data):
            raise ValueError("Invalid section offset")
        
        # Parse section header
        self.name = data[offset:offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
        self.virtual_size = struct.unpack('<I', data[offset+8:offset+12])[0]
        self.virtual_address = struct.unpack('<I', data[offset+12:offset+16])[0]
        self.size_of_raw_data = struct.unpack('<I', data[offset+16:offset+20])[0]
        self.pointer_to_raw_data = struct.unpack('<I', data[offset+20:offset+24])[0]
        self.pointer_to_relocations = struct.unpack('<I', data[offset+24:offset+28])[0]
        self.pointer_to_linenumbers = struct.unpack('<I', data[offset+28:offset+32])[0]
        self.number_of_relocations = struct.unpack('<H', data[offset+32:offset+34])[0]
        self.number_of_linenumbers = struct.unpack('<H', data[offset+34:offset+36])[0]
        self.characteristics = struct.unpack('<I', data[offset+36:offset+40])[0]
        
        # Determine section type
        self.is_executable = bool(self.characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
        self.is_readable = bool(self.characteristics & 0x40000000)    # IMAGE_SCN_MEM_READ
        self.is_writable = bool(self.characteristics & 0x80000000)    # IMAGE_SCN_MEM_WRITE

class PEAnalyzer:
    """PE Binary Analyzer"""
    
    @staticmethod
    def analyze(file_path: str) -> Dict[str, Any]:
        """
        Analyze a PE file and return analysis results
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            Dict containing analysis results
        """
        try:
            if not os.path.exists(file_path):
                print_error(f"File not found: {file_path}")
                return None
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if len(data) < 64:
                print_error("File too small to be a valid PE")
                return None
            
            # Parse PE header
            pe_header = PEHeader(data)
            
            # Parse sections
            sections = []
            section_offset = pe_header.e_lfanew + 4 + 20 + pe_header.size_of_optional_header
            
            for i in range(pe_header.number_of_sections):
                try:
                    section = PESection(data, section_offset + (i * 40))
                    sections.append(section)
                except Exception as e:
                    print_warning(f"Failed to parse section {i}: {e}")
                    continue
            
            # Analyze sections
            executable_sections = [s for s in sections if s.is_executable]
            writable_sections = [s for s in sections if s.is_writable]
            
            # Look for common sections
            text_section = next((s for s in sections if s.name == '.text'), None)
            data_section = next((s for s in sections if s.name == '.data'), None)
            rdata_section = next((s for s in sections if s.name == '.rdata'), None)
            
            # Build analysis result
            analysis = {
                'file_path': file_path,
                'file_size': len(data),
                'is_64bit': pe_header.is_64bit,
                'machine_type': pe_header.machine,
                'entry_point': pe_header.address_of_entry_point,
                'image_base': pe_header.image_base,
                'characteristics': pe_header.characteristics,
                'sections': {
                    'total': len(sections),
                    'executable': len(executable_sections),
                    'writable': len(writable_sections),
                    'list': [
                        {
                            'name': s.name,
                            'virtual_address': s.virtual_address,
                            'virtual_size': s.virtual_size,
                            'raw_size': s.size_of_raw_data,
                            'is_executable': s.is_executable,
                            'is_readable': s.is_readable,
                            'is_writable': s.is_writable,
                            'characteristics': s.characteristics
                        } for s in sections
                    ]
                },
                'special_sections': {
                    'text': {
                        'name': text_section.name if text_section else None,
                        'address': text_section.virtual_address if text_section else None,
                        'size': text_section.virtual_size if text_section else None
                    } if text_section else None,
                    'data': {
                        'name': data_section.name if data_section else None,
                        'address': data_section.virtual_address if data_section else None,
                        'size': data_section.virtual_size if data_section else None
                    } if data_section else None,
                    'rdata': {
                        'name': rdata_section.name if rdata_section else None,
                        'address': rdata_section.virtual_address if rdata_section else None,
                        'size': rdata_section.virtual_size if rdata_section else None
                    } if rdata_section else None
                }
            }
            
            print_success(f"PE analysis completed for {file_path}")
            print_info(f"Architecture: {'64-bit' if pe_header.is_64bit else '32-bit'}")
            print_info(f"Sections: {len(sections)} total, {len(executable_sections)} executable")
            print_info(f"Entry point: 0x{pe_header.address_of_entry_point:x}")
            
            return analysis
            
        except Exception as e:
            print_error(f"PE analysis failed: {e}")
            return None
    
    @staticmethod
    def find_gadgets(file_path: str, max_gadgets: int = 100) -> List[Dict[str, Any]]:
        """
        Find ROP gadgets in a PE file (placeholder implementation)
        
        Args:
            file_path: Path to the PE file
            max_gadgets: Maximum number of gadgets to return
            
        Returns:
            List of gadgets found
        """
        print_warning("ROP gadget finding for PE files not implemented yet")
        return []
    
    @staticmethod
    def find_imports(file_path: str) -> Dict[str, List[str]]:
        """
        Find imported functions in a PE file (placeholder implementation)
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            Dict mapping DLL names to imported functions
        """
        print_warning("Import analysis for PE files not implemented yet")
        return {}
