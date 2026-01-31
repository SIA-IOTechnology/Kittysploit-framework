from core.framework.base_module import BaseModule
from core.framework.option import OptString, OptPort, OptInt, OptChoice, OptBool
from core.output_handler import print_success, print_status, print_error, print_info, print_warning
import base64
import os


class ExeCompiler(BaseModule):
    """
    Compiles source (Zig) or shellcode to executable/binary.
    Uses ZigCompiler for PE/ELF; does not rely on framework.payload.
    """

    def __init__(self, framework=None):
        super().__init__(framework)

    def _get_zig_compiler(self):
        """Lazy-init Zig compiler."""
        if getattr(self, "_zig_compiler", None) is None:
            from core.lib.compiler.zig_compiler import ZigCompiler
            self._zig_compiler = ZigCompiler()
        return self._zig_compiler

    def generate_pe(self, source_code: str, output_path: str, target_arch: str = "x86_64") -> bool:
        """Compile Zig source to Windows PE executable."""
        compiler = self._get_zig_compiler()
        if not compiler.is_available():
            print_error("Zig compiler not available; cannot generate PE.")
            return False
        return compiler.compile(
            source_code=source_code,
            output_path=output_path,
            target_platform="windows",
            target_arch=target_arch,
            optimization="ReleaseSmall",
            strip=True,
            static=True,
            windows_subsystem="windows",
        )

    def generate_elf(self, source_code: str, output_path: str, target_arch: str = "x86_64") -> bool:
        """Compile Zig source to Linux ELF executable."""
        compiler = self._get_zig_compiler()
        if not compiler.is_available():
            print_error("Zig compiler not available; cannot generate ELF.")
            return False
        return compiler.compile(
            source_code=source_code,
            output_path=output_path,
            target_platform="linux",
            target_arch=target_arch,
            optimization="ReleaseSmall",
            strip=True,
            static=True,
        )

    def generate_exe(self, source_code: str, output_path: str, target_arch: str = "x86_64"):
        """Generate executable: PE on Windows target, ELF on Linux. Defaults to PE."""
        out_lower = output_path.lower()
        if out_lower.endswith(".exe") or "windows" in out_lower:
            return self.generate_pe(source_code, output_path, target_arch=target_arch)
        return self.generate_elf(source_code, output_path, target_arch=target_arch)

    def generate_shellcode(self, source_code: str, output_path: str) -> bool:
        """
        Write shellcode to file. source_code can be:
        - Hex string (with or without \\x prefix)
        - Base64 string
        - Raw string (written as-is; use for small payloads)
        """
        try:
            data = self._decode_shellcode(source_code)
            os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(data)
            print_success(f"Shellcode written to {output_path} ({len(data)} bytes)")
            return True
        except Exception as e:
            print_error(f"Failed to write shellcode: {e}")
            return False

    def _decode_shellcode(self, source_code: str) -> bytes:
        """Decode shellcode from hex, base64, or return as utf-8 bytes."""
        s = source_code.strip()
        if not s:
            return b""
        # Base64 (only try if it looks like base64)
        try:
            if len(s) % 4 == 0 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in s):
                return base64.b64decode(s)
        except Exception:
            pass
        # Hex (with or without \x / 0x)
        hex_candidates = s.replace("\\x", "").replace(" ", "").replace("0x", "")
        if hex_candidates and all(c in "0123456789abcdefABCDEF" for c in hex_candidates):
            if len(hex_candidates) % 2:
                hex_candidates = "0" + hex_candidates
            return bytes.fromhex(hex_candidates)
        return s.encode("utf-8", errors="replace")

    def generate_payload(self, source_code: str, output_path: str, target_arch: str = "x86_64"):
        """
        Generate payload: compile Zig source to executable (PE/ELF by extension),
        or write as shellcode if output has no extension or .bin/.raw.
        """
        ext = os.path.splitext(output_path)[1].lower()
        if ext in (".exe",):
            return self.generate_pe(source_code, output_path, target_arch=target_arch)
        if ext in (".elf", ".bin", "") or "shellcode" in output_path.lower():
            return self.generate_shellcode(source_code, output_path)
        return self.generate_elf(source_code, output_path, target_arch=target_arch)