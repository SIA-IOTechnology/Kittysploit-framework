#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compilateur Python vers EXE standalone - Zig + Python embeddable
Génère un exécutable autonome qui intègre Python (python3X.dll + stdlib).
Aucune installation de Python requise sur la machine cible.
Utilise le package embeddable de python.org.
"""

import os
import sys
import zlib
import base64
import urllib.request
import urllib.error

from typing import Optional
from core.output_handler import print_info, print_success, print_error, print_warning

# Répertoire par défaut pour le package embeddable (core/lib/embed_python)
_here = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EMBED_DIR = os.path.normpath(os.path.join(_here, "..", "embed_python"))

# Template Zig Windows - charge python3X.dll et exécute le script via l'API C
# Nécessite: EMBEDDABLE_B64 (zip compressé en base64), SCRIPT_B64, PYTHON_DLL
ZIG_STANDALONE_TEMPLATE = '''
const std = @import("std");
const process = std.process;

const EMBEDDABLE_B64 = "{embeddable_b64}";
const SCRIPT_B64 = "{script_b64}";
const PYTHON_DLL = "{python_dll}";

const Py_InitializeEx = fn (initsigs: c_int) callconv(.c) void;
const PyRun_SimpleString = fn (command: [*:0]const u8) callconv(.c) c_int;
const Py_Finalize = fn () callconv(.c) void;

pub fn main() !void {{
    var gpa = std.heap.GeneralPurposeAllocator(.{{}}){{}};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const b64_dec = std.base64.standard.Decoder;

    // Decode base64 compressed embeddable
    const embed_len = try b64_dec.calcSizeForSlice(EMBEDDABLE_B64);
    const embed_compressed = try allocator.alloc(u8, embed_len);
    defer allocator.free(embed_compressed);
    try b64_dec.decode(embed_compressed, EMBEDDABLE_B64);

    // Decompress zlib data
    var input_reader = std.Io.Reader.fixed(embed_compressed);
    var decomp_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decomp = std.compress.flate.Decompress.init(&input_reader, .zlib, &decomp_buf);
    var zip_data: std.ArrayList(u8) = .empty;
    defer zip_data.deinit(allocator);
    try decomp.reader.appendRemainingUnlimited(allocator, &zip_data);

    // Decode base64 script
    const script_len = try b64_dec.calcSizeForSlice(SCRIPT_B64);
    const script_code = try allocator.alloc(u8, script_len + 1);
    defer allocator.free(script_code);
    try b64_dec.decode(script_code[0..script_len], SCRIPT_B64);
    script_code[script_len] = 0;

    // Create temp directory
    const tmp_base = process.getEnvVarOwned(allocator, "TEMP") catch process.getEnvVarOwned(allocator, "TMP") catch blk: {{
        break :blk try allocator.dupe(u8, ".");
    }};
    defer allocator.free(tmp_base);
    var prng = std.Random.DefaultPrng.init(@intCast(std.time.microTimestamp()));
    const rand_val = prng.random().int(u32);
    const tmp_dir_path = try std.fmt.allocPrint(allocator, "{{s}}\\\\kp_{{d:0>8}}", .{{ tmp_base, rand_val }});
    defer allocator.free(tmp_dir_path);
    try std.fs.cwd().makePath(tmp_dir_path);
    defer std.fs.cwd().deleteTree(tmp_dir_path) catch {{}};

    // Write zip to temp file
    const zip_tmp = try std.fmt.allocPrint(allocator, "{{s}}\\\\embed.zip", .{{tmp_dir_path}});
    defer allocator.free(zip_tmp);
    var zip_file = try std.fs.cwd().createFile(zip_tmp, .{{}});
    try zip_file.writeAll(zip_data.items);
    zip_file.close();

    // Extract zip
    var zip_f = try std.fs.cwd().openFile(zip_tmp, .{{}});
    defer zip_f.close();
    var read_buf: [8192]u8 = undefined;
    var zip_reader = zip_f.reader(&read_buf);
    var extract_dir = try std.fs.cwd().openDir(tmp_dir_path, .{{}});
    defer extract_dir.close();
    try std.zip.extract(extract_dir, &zip_reader, .{{ .allow_backslashes = true }});

    // Build DLL path
    var dll_path_buf: [1024]u16 = undefined;
    const dll_path_u8 = try std.fmt.allocPrint(allocator, "{{s}}\\\\{{s}}", .{{ tmp_dir_path, PYTHON_DLL }});
    defer allocator.free(dll_path_u8);
    const dll_path_len = try std.unicode.utf8ToUtf16Le(dll_path_buf[0..], dll_path_u8);
    dll_path_buf[dll_path_len] = 0;

    // Load Python DLL
    const kernel32 = std.os.windows.kernel32;
    const hmod = kernel32.LoadLibraryW(@as([*:0]const u16, @ptrCast(&dll_path_buf))) orelse return error.FailedToLoadPython;
    defer _ = kernel32.FreeLibrary(hmod);

    // Get Python C API functions
    const py_init_ptr = kernel32.GetProcAddress(hmod, "Py_InitializeEx") orelse return error.NoPyInit;
    const py_run_ptr = kernel32.GetProcAddress(hmod, "PyRun_SimpleString") orelse return error.NoPyRun;
    const py_final_ptr = kernel32.GetProcAddress(hmod, "Py_Finalize") orelse return error.NoPyFinal;

    const py_init: *const Py_InitializeEx = @ptrCast(py_init_ptr);
    const py_run: *const PyRun_SimpleString = @ptrCast(py_run_ptr);
    const py_final: *const Py_Finalize = @ptrCast(py_final_ptr);

    // Execute Python script
    py_init(0);
    _ = py_run(@ptrCast(script_code.ptr));
    py_final();
}}
'''


def _download_embeddable(dest_dir: str, python_version: tuple) -> Optional[str]:
    """Télécharge le package embeddable Python depuis python.org si absent."""
    major, minor = python_version[:2]
    patch = python_version[2] if len(python_version) > 2 else 0
    version = f"{major}.{minor}.{patch}"
    filename = f"python-{version}-embed-amd64.zip"
    url = f"https://www.python.org/ftp/python/{version}/{filename}"

    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, filename)
    if os.path.isfile(dest_path):
        return dest_path

    print_info(f"Downloading Python embeddable package: {filename}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Kittysploit/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
        with open(dest_path, "wb") as f:
            f.write(data)
        print_success(f"Downloaded to {dest_path}")
        return dest_path
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print_warning(f"Version {version} not found, trying major.minor...")
            version_short = f"{major}.{minor}"
            url_alt = f"https://www.python.org/ftp/python/{version_short}/{filename}"
            try:
                req = urllib.request.Request(url_alt, headers={"User-Agent": "Kittysploit/1.0"})
                with urllib.request.urlopen(req, timeout=120) as resp:
                    data = resp.read()
                with open(dest_path, "wb") as f:
                    f.write(data)
                print_success(f"Downloaded to {dest_path}")
                return dest_path
            except Exception as e2:
                print_error(f"Download failed: {e2}")
        else:
            print_error(f"Download failed: {e}")
    except Exception as e:
        print_error(f"Download failed: {e}")
    return None


def _find_embeddable(embed_path: Optional[str], python_version: tuple) -> Optional[str]:
    """Trouve le fichier zip embeddable Python (ou le télécharge si absent)."""
    if embed_path and os.path.isfile(embed_path):
        return embed_path
    major, minor = python_version[:2]
    search_dirs = [
        embed_path if embed_path and os.path.isdir(embed_path) else None,
        DEFAULT_EMBED_DIR,
        os.path.join(os.path.dirname(__file__), "embed_python"),
        os.path.expanduser("~/.kittysploit/embed_python"),
    ]
    exact_names = [
        f"python{major}{minor}-embed-amd64.zip",
        f"python-{major}.{minor}-embed-amd64.zip",
    ]
    if len(python_version) > 2:
        patch = python_version[2]
        exact_names.insert(0, f"python-{major}.{minor}.{patch}-embed-amd64.zip")

    for d in search_dirs:
        if not d or not os.path.isdir(d):
            continue
        for name in exact_names:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
        try:
            for f in os.listdir(d):
                if f.endswith("-embed-amd64.zip") and "python" in f.lower():
                    if f"python{major}{minor}" in f or f"python-{major}.{minor}" in f or f"python-{major}.{minor}." in f:
                        return os.path.join(d, f)
        except OSError:
            pass

    # Téléchargement automatique si non trouvé
    downloaded = _download_embeddable(DEFAULT_EMBED_DIR, python_version)
    if downloaded:
        return downloaded

    return None


def _get_python_dll_name() -> str:
    """Retourne le nom de la DLL Python (python311.dll, etc.)."""
    v = sys.version_info
    return f"python{v.major}{v.minor}.dll"


class Py2ExeStandaloneCompiler:
    """
    Compile Python scripts to standalone executables using Zig + Python embeddable.
    L'exe généré inclut Python (python3X.dll + stdlib). Aucune installation requise.
    """

    def __init__(self, zig_path: Optional[str] = None, embeddable_path: Optional[str] = None):
        from core.lib.compiler.zig_compiler import ZigCompiler
        self._zig_compiler = ZigCompiler(zig_path)
        self._embeddable_path = embeddable_path

    def is_available(self) -> bool:
        """Vérifie que Zig et le package embeddable sont disponibles."""
        if not self._zig_compiler.is_available():
            return False
        embed = _find_embeddable(self._embeddable_path, sys.version_info)
        return embed is not None

    def compile(
        self,
        script_code: str,
        output_path: str,
        embeddable_path: Optional[str] = None,
        python_version: Optional[tuple] = None,
        windows_subsystem: Optional[str] = 'windows',
    ) -> bool:
        """
        Compile un script Python en exe standalone (Windows uniquement pour l'instant).

        Args:
            script_code: Code Python source
            output_path: Chemin de l'exe de sortie
            embeddable_path: Chemin vers pythonX.Y-embed-amd64.zip (optionnel)
            python_version: (major, minor) pour la DLL (défaut: version courante)
            windows_subsystem: 'windows' ou 'console'

        Returns:
            True si succès
        """
        if not self._zig_compiler.is_available():
            print_error("Zig compiler not available")
            return False

        pv = python_version or (sys.version_info.major, sys.version_info.minor)
        embed_path = embeddable_path or self._embeddable_path
        embed_file = _find_embeddable(embed_path, pv)

        if not embed_file:
            print_error("Python embeddable package not found")
            print_error(f"Download from: https://www.python.org/downloads/windows/")
            print_error(f"Get 'Windows embeddable package (64-bit)' and place in:")
            print_error(f"  {DEFAULT_EMBED_DIR}")
            print_error(f"  Or set embeddable_path option")
            return False

        try:
            with open(embed_file, 'rb') as f:
                embed_data = f.read()
        except OSError as e:
            print_error(f"Cannot read embeddable: {e}")
            return False

        # Compress embeddable
        compressed = zlib.compress(embed_data, level=9)
        embed_b64 = base64.b64encode(compressed).decode('ascii')
        script_b64 = base64.b64encode(script_code.encode('utf-8')).decode('ascii')
        python_dll = f"python{pv[0]}{pv[1]}.dll"

        zig_code = ZIG_STANDALONE_TEMPLATE.format(
            embeddable_b64=embed_b64,
            script_b64=script_b64,
            python_dll=python_dll,
        )

        print_info("Compiling standalone Python executable (embeddable + Zig)")
        return self._zig_compiler.compile(
            source_code=zig_code,
            output_path=output_path,
            target_platform='windows',
            target_arch='x64',
            optimization='ReleaseSmall',
            strip=True,
            static=True,
            windows_subsystem=windows_subsystem,
        )


def compile_python_to_standalone_exe(
    script_code: str,
    output_path: str,
    embeddable_path: Optional[str] = None,
    zig_path: Optional[str] = None,
) -> bool:
    """
    Compile un script Python en exe standalone.

    Args:
        script_code: Code Python
        output_path: Chemin de sortie
        embeddable_path: Chemin vers pythonX.Y-embed-amd64.zip
        zig_path: Chemin vers zig (optionnel)

    Returns:
        True si succès
    """
    compiler = Py2ExeStandaloneCompiler(zig_path=zig_path, embeddable_path=embeddable_path)
    return compiler.compile(
        script_code=script_code,
        output_path=output_path,
        embeddable_path=embeddable_path,
    )


if __name__ == "__main__":
    """CLI: télécharge le package embeddable si absent."""
    print("Kittysploit - Download Python embeddable package")
    print(f"Target directory: {DEFAULT_EMBED_DIR}")
    found = _find_embeddable(None, sys.version_info)
    if found:
        print_success(f"Embeddable package ready: {found}")
    else:
        print_error("Download failed or package not found")
        sys.exit(1)
