#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NOP (No Operation) manager for KittySploit framework
Integrated NOPs instead of separate modules for better performance
"""

import random
import struct

class NopManager:
    """Manager for NOP sleds and padding"""
    
    def __init__(self):
        self.nops = {
            'x86': {
                'opty2': self._x86_opty2,
                'single_byte': self._x86_single_byte,
                'random': self._x86_random,
                'alpha': self._x86_alpha
            },
            'x64': {
                'opty2': self._x64_opty2,
                'single_byte': self._x64_single_byte,
                'random': self._x64_random
            }
        }
    
    def generate(self, arch='x86', nop_type='opty2', size=100):
        """
        Generate NOP sled
        
        Args:
            arch: Architecture (x86, x64)
            nop_type: Type of NOP (opty2, single_byte, random, alpha)
            size: Size of the NOP sled
            
        Returns:
            bytes: NOP sled
        """
        if arch not in self.nops:
            raise ValueError(f"Unsupported architecture: {arch}")
        
        if nop_type not in self.nops[arch]:
            raise ValueError(f"Unsupported NOP type for {arch}: {nop_type}")
        
        return self.nops[arch][nop_type](size)
    
    def _x86_opty2(self, size):
        """Generate x86 opty2 NOP sled"""
        nops = [
            b'\x81\xc4\x54\xf2\xff\xff',  # add esp, -3500
            b'\x8d\x64\x24\x14',          # lea esp, [esp+0x14]
            b'\x8d\x40\x00',              # lea eax, [eax+0x00]
            b'\x8d\x44\x24\x00',          # lea eax, [esp+0x00]
            b'\x8b\xff',                  # mov edi, edi
            b'\x90',                      # nop
        ]
        
        result = b''
        while len(result) < size:
            result += random.choice(nops)
        
        return result[:size]
    
    def _x86_single_byte(self, size):
        """Generate x86 single byte NOP sled"""
        return b'\x90' * size
    
    def _x86_random(self, size):
        """Generate x86 random NOP sled"""
        nops = [
            b'\x90',                      # nop
            b'\x40',                      # inc eax
            b'\x41',                      # inc ecx
            b'\x42',                      # inc edx
            b'\x43',                      # inc ebx
            b'\x44',                      # inc esp
            b'\x45',                      # inc ebp
            b'\x46',                      # inc esi
            b'\x47',                      # inc edi
        ]
        
        result = b''
        while len(result) < size:
            result += random.choice(nops)
        
        return result[:size]
    
    def _x86_alpha(self, size):
        """Generate x86 alphanumeric NOP sled"""
        # Alphanumeric instructions that don't affect execution
        alpha_nops = [
            b'PPYA',  # push eax; push eax; push eax; push eax
            b'PPYB',  # push eax; push eax; push eax; push ebx
            b'PPYC',  # push eax; push eax; push eax; push ecx
            b'PPYD',  # push eax; push eax; push eax; push edx
        ]
        
        result = b''
        while len(result) < size:
            result += random.choice(alpha_nops)
        
        return result[:size]
    
    def _x64_opty2(self, size):
        """Generate x64 opty2 NOP sled"""
        nops = [
            b'\x48\x81\xc4\x54\xf2\xff\xff',  # add rsp, -3500
            b'\x48\x8d\x64\x24\x14',          # lea rsp, [rsp+0x14]
            b'\x48\x8d\x40\x00',              # lea rax, [rax+0x00]
            b'\x48\x8d\x44\x24\x00',          # lea rax, [rsp+0x00]
            b'\x48\x8b\xff',                  # mov rdi, rdi
            b'\x90',                          # nop
        ]
        
        result = b''
        while len(result) < size:
            result += random.choice(nops)
        
        return result[:size]
    
    def _x64_single_byte(self, size):
        """Generate x64 single byte NOP sled"""
        return b'\x90' * size
    
    def _x64_random(self, size):
        """Generate x64 random NOP sled"""
        nops = [
            b'\x90',                      # nop
            b'\x48\x40',                  # rex.w inc rax
            b'\x48\x41',                  # rex.w inc rcx
            b'\x48\x42',                  # rex.w inc rdx
            b'\x48\x43',                  # rex.w inc rbx
            b'\x48\x44',                  # rex.w inc rsp
            b'\x48\x45',                  # rex.w inc rbp
            b'\x48\x46',                  # rex.w inc rsi
            b'\x48\x47',                  # rex.w inc rdi
        ]
        
        result = b''
        while len(result) < size:
            result += random.choice(nops)
        
        return result[:size]
    
    def list_available(self):
        """List all available NOP types"""
        result = {}
        for arch, types in self.nops.items():
            result[arch] = list(types.keys())
        return result
    
    def get_info(self, arch, nop_type):
        """Get information about a specific NOP type"""
        info = {
            'x86': {
                'opty2': 'Optimized x86 NOP sled with various instructions',
                'single_byte': 'Simple x86 NOP sled using 0x90',
                'random': 'Random x86 NOP sled with various instructions',
                'alpha': 'Alphanumeric x86 NOP sled'
            },
            'x64': {
                'opty2': 'Optimized x64 NOP sled with various instructions',
                'single_byte': 'Simple x64 NOP sled using 0x90',
                'random': 'Random x64 NOP sled with various instructions'
            }
        }
        
        return info.get(arch, {}).get(nop_type, 'Unknown NOP type')
