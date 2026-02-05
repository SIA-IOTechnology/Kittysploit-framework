#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compilateur Python vers EXE - Python + Zig
Génère un exécutable standalone qui embeds le script Python et l'exécute via l'interpréteur local.
Utilise le ZigCompiler du framework (PATH + core/lib/compiler/zig_executable/).
"""

import os
import sys
import zlib
import base64
import tempfile

from typing import Optional
from core.output_handler import print_info, print_success, print_error, print_warning


# Template avec compression zlib (payload plus compact) - Zig 0.15 compatible
ZIG_STUB_TEMPLATE = '''
const std = @import("std");

const PAYLOAD_COMPRESSED = "{payload_b64}";

pub fn main() !void {{
    var gpa = std.heap.GeneralPurposeAllocator(.{{}}){{}};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const b64_decoder = std.base64.standard.Decoder;
    const compressed_len = try b64_decoder.calcSizeForSlice(PAYLOAD_COMPRESSED);
    const payload_compressed = try allocator.alloc(u8, compressed_len);
    defer allocator.free(payload_compressed);
    try b64_decoder.decode(payload_compressed, PAYLOAD_COMPRESSED);

    var stream = std.io.fixedBufferStream(payload_compressed);
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress = std.compress.flate.Decompress.init(stream.reader(), .zlib, &decompress_buf);
    var script_list = std.ArrayList(u8).empty;
    defer script_list.deinit(allocator);
    try decompress.reader.appendRemainingUnlimited(allocator, &script_list);

    const tmp_dir = std.fs.cwd();
    const temp_file = "~temp_script.py";
    const file = try tmp_dir.createFile(temp_file, .{{}});
    defer tmp_dir.deleteFile(temp_file) catch {{}};
    defer file.close();
    try file.writeAll(script_list.items);

    var argv_buf: [2][]const u8 = undefined;
    argv_buf[0] = "{python_binary}";
    argv_buf[1] = temp_file;
    var child = std.process.Child.init(&argv_buf, allocator);
    try child.spawn();
    const term = try child.wait();

    const exit_code: u8 = switch (term) {{
        .Exited => |code| @intCast(code),
        else => 1,
    }};
    std.process.exit(exit_code);
}}
'''

# Template simple (base64 sans compression) - Zig 0.15 compatible
ZIG_STUB_SIMPLE_TEMPLATE = '''
const std = @import("std");

const SCRIPT_B64 = "{script_b64}";

pub fn main() !void {{
    var gpa = std.heap.GeneralPurposeAllocator(.{{}}){{}};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const decoder = std.base64.standard.Decoder;
    const script_len = try decoder.calcSizeForSlice(SCRIPT_B64);
    const script_code = try allocator.alloc(u8, script_len);
    defer allocator.free(script_code);
    try decoder.decode(script_code, SCRIPT_B64);

    const tmp_dir = std.fs.cwd();
    const temp_file = "~temp_script.py";
    const file = try tmp_dir.createFile(temp_file, .{{}});
    defer tmp_dir.deleteFile(temp_file) catch {{}};
    defer file.close();
    try file.writeAll(script_code);

    var argv_buf: [2][]const u8 = undefined;
    argv_buf[0] = "{python_binary}";
    argv_buf[1] = temp_file;
    var child = std.process.Child.init(&argv_buf, allocator);
    try child.spawn();
    const term = try child.wait();

    const exit_code: u8 = switch (term) {{
        .Exited => |code| @intCast(code),
        else => 1,
    }};
    std.process.exit(exit_code);
}}
'''


class Py2ExeCompiler:
    """
    Compile Python scripts to executables using Zig.
    Uses the framework's ZigCompiler (PATH or core/lib/compiler/zig_executable/).
    """

    def __init__(self, zig_path: Optional[str] = None):
        from core.lib.compiler.zig_compiler import ZigCompiler
        self._zig_compiler = ZigCompiler(zig_path)

    def is_available(self) -> bool:
        """Check if Zig compiler is available."""
        return self._zig_compiler.is_available()

    def compile(
        self,
        script_code: str,
        output_path: str,
        target_platform: str = 'windows',
        target_arch: str = 'x64',
        python_binary: str = 'python',
        use_compression: bool = False,
        windows_subsystem: Optional[str] = 'windows',
    ) -> bool:
        """
        Compile Python script to executable.

        Args:
            script_code: Python source code
            output_path: Output executable path (.exe on Windows)
            target_platform: linux, windows, macos
            target_arch: x64, x86, arm64, etc.
            python_binary: Python interpreter name on target (python, python3, py)
            use_compression: Use zlib compression for smaller payload
            windows_subsystem: 'windows' to hide console, 'console' for default

        Returns:
            True if successful
        """
        if not self.is_available():
            print_error("Zig compiler not available")
            print_error("Install Zig and add to PATH, or place in core/lib/compiler/zig_executable/")
            return False

        # Escape for Zig string literal
        python_binary_escaped = (python_binary or "python").replace('\\', '\\\\').replace('"', '\\"')

        if use_compression:
            compressed = zlib.compress(script_code.encode('utf-8'), level=9)
            payload_b64 = base64.b64encode(compressed).decode('ascii')
            zig_code = ZIG_STUB_TEMPLATE.format(
                payload_b64=payload_b64,
                python_binary=python_binary_escaped,
            )
        else:
            script_b64 = base64.b64encode(script_code.encode('utf-8')).decode('ascii')
            zig_code = ZIG_STUB_SIMPLE_TEMPLATE.format(
                script_b64=script_b64,
                python_binary=python_binary_escaped,
            )

        print_info(f"Compiling Python to {target_platform}/{target_arch} executable")
        return self._zig_compiler.compile(
            source_code=zig_code,
            output_path=output_path,
            target_platform=target_platform,
            target_arch=target_arch,
            optimization='ReleaseSmall',
            strip=True,
            static=True,
            windows_subsystem=windows_subsystem if target_platform.lower() == 'windows' else None,
        )


def compile_python_to_exe(
    script_code: str,
    output_path: str,
    target_platform: str = 'windows',
    target_arch: str = 'x64',
    python_binary: str = 'python',
    use_compression: bool = False,
    zig_path: Optional[str] = None,
) -> bool:
    """
    Compile Python script to executable (standalone function).

    Args:
        script_code: Python source code
        output_path: Output path
        target_platform: windows, linux, macos
        target_arch: x64, x86, etc.
        python_binary: Interpreter on target
        use_compression: zlib compression
        zig_path: Override Zig executable path

    Returns:
        True if successful
    """
    compiler = Py2ExeCompiler(zig_path)
    return compiler.compile(
        script_code=script_code,
        output_path=output_path,
        target_platform=target_platform,
        target_arch=target_arch,
        python_binary=python_binary,
        use_compression=use_compression,
    )


def main():
    """CLI entry point."""
    print("=" * 70)
    print("  Python to EXE Compiler (Zig)")
    print("=" * 70)
    print()

    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} <script.py> [options]")
        print()
        print("Options:")
        print("  --output <nom>      Output executable path")
        print("  --target <triple>   e.g. x86_64-windows, x86_64-linux-gnu")
        print("  --platform <p>      windows|linux|macos")
        print("  --arch <a>          x64|x86|arm64")
        print("  --python <bin>      Python binary (python, python3)")
        print("  --compress          Use zlib compression")
        sys.exit(1)

    python_file = sys.argv[1]
    if not os.path.exists(python_file):
        print_error(f"File not found: {python_file}")
        sys.exit(1)

    with open(python_file, 'r', encoding='utf-8') as f:
        script_code = f.read()

    output_path = None
    if '--output' in sys.argv:
        idx = sys.argv.index('--output')
        if idx + 1 < len(sys.argv):
            output_path = sys.argv[idx + 1]

    target_platform = 'windows'
    target_arch = 'x64'
    if '--platform' in sys.argv:
        idx = sys.argv.index('--platform')
        if idx + 1 < len(sys.argv):
            target_platform = sys.argv[idx + 1]
    if '--arch' in sys.argv:
        idx = sys.argv.index('--arch')
        if idx + 1 < len(sys.argv):
            target_arch = sys.argv[idx + 1]

    if '--target' in sys.argv:
        idx = sys.argv.index('--target')
        if idx + 1 < len(sys.argv):
            triple = sys.argv[idx + 1]
            if 'windows' in triple:
                target_platform = 'windows'
            elif 'linux' in triple:
                target_platform = 'linux'
            elif 'macos' in triple:
                target_platform = 'macos'
            if 'x86_64' in triple or 'x64' in triple:
                target_arch = 'x64'
            elif 'i386' in triple or 'x86' in triple:
                target_arch = 'x86'
            elif 'aarch64' in triple or 'arm64' in triple:
                target_arch = 'arm64'

    python_binary = 'python'
    if '--python' in sys.argv:
        idx = sys.argv.index('--python')
        if idx + 1 < len(sys.argv):
            python_binary = sys.argv[idx + 1]

    use_compression = '--compress' in sys.argv

    if output_path is None:
        base_name = os.path.splitext(os.path.basename(python_file))[0]
        output_path = base_name + ('.exe' if target_platform == 'windows' else '')

    success = compile_python_to_exe(
        script_code=script_code,
        output_path=output_path,
        target_platform=target_platform,
        target_arch=target_arch,
        python_binary=python_binary,
        use_compression=use_compression,
    )

    if success:
        print_success("Compilation successful")
    else:
        print_error("Compilation failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
