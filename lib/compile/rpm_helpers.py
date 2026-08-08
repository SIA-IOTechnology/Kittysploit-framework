#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Cross-platform binary RPM generation (no rpmbuild/subprocess)."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import stat
import struct
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# RPM tag / type constants (subset of rpmtag.h)
RPM_STRING_TYPE = 6
RPM_INT16_TYPE = 3
RPM_INT32_TYPE = 4
RPM_STRING_ARRAY_TYPE = 8

RPMTAG_NAME = 1000
RPMTAG_VERSION = 1001
RPMTAG_RELEASE = 1002
RPMTAG_SUMMARY = 1004
RPMTAG_DESCRIPTION = 1005
RPMTAG_BUILDTIME = 1006
RPMTAG_LICENSE = 1014
RPMTAG_PREIN = 1023
RPMTAG_POSTIN = 1024
RPMTAG_PREUN = 1025
RPMTAG_POSTUN = 1026
RPMTAG_OS = 1021
RPMTAG_ARCH = 1022
RPMTAG_FILEMODES = 1030
RPMTAG_FILERDEVS = 1033
RPMTAG_FILEMTIMES = 1034
RPMTAG_FILEDIGESTS = 1035
RPMTAG_FILELINKTOS = 1036
RPMTAG_FILEFLAGS = 1037
RPMTAG_FILEUSERNAME = 1039
RPMTAG_FILEGROUPNAME = 1040
RPMTAG_SOURCERPM = 1044
RPMTAG_FILEINODES = 1096
RPMTAG_FILELANGS = 1097
RPMTAG_DIRINDEXES = 1116
RPMTAG_BASENAMES = 1117
RPMTAG_DIRNAMES = 1118
RPMTAG_FILESIZES = 1028
RPMTAG_PAYLOADFORMAT = 1124
RPMTAG_PAYLOADCOMPRESSOR = 1125
RPMTAG_FILEDIGESTALGO = 5011
RPMTAG_PAYLOADDIGEST = 5092
RPMTAG_PAYLOADDIGESTALGO = 5093

RPMSIGTAG_PAYLOADSIZE = 1007
PGPHASHALGO_SHA1 = 2

CPIO_CRC_MAGIC = b"070702"
CPIO_TRAILER = b"TRAILER!!!\0"


def _pad4(n: int) -> int:
    return (4 - (n % 4)) % 4


def _hex_field(value: int, width: int = 8) -> bytes:
    return f"{int(value):0{width}x}".encode("ascii")


def _cpio_crc_entry(name: bytes, mode: int, data: bytes, mtime: int, inode: int) -> bytes:
    namesize = len(name) + 1
    filesize = len(data)
    header = b"".join(
        [
            CPIO_CRC_MAGIC,
            _hex_field(inode),
            _hex_field(mode),
            _hex_field(0),  # uid
            _hex_field(0),  # gid
            _hex_field(1),  # nlink
            _hex_field(mtime),
            _hex_field(filesize),
            _hex_field(0),  # devmajor
            _hex_field(0),  # devminor
            _hex_field(0),  # rdevmajor
            _hex_field(0),  # rdevminor
            _hex_field(namesize),
            _hex_field(0),  # chksum (unused by RPM)
        ]
    )
    assert len(header) == 110
    out = bytearray(header)
    out.extend(name + b"\0")
    out.extend(b"\0" * _pad4(namesize))
    if data:
        out.extend(data)
        out.extend(b"\0" * _pad4(filesize))
    return bytes(out)


def build_cpio_crc_from_tree(root: Path) -> bytes:
    """Build SVR4 CRC cpio archive from a directory tree (paths relative to root)."""
    root = root.resolve()
    paths: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        base = Path(dirpath)
        for d in dirnames:
            paths.append(base / d)
        for f in filenames:
            paths.append(base / f)
    paths.sort(key=lambda p: str(p.relative_to(root)).replace("\\", "/"))

    buf = bytearray()
    inode = 1
    now = int(time.time())
    for path in paths:
        rel = path.relative_to(root).as_posix()
        st = path.lstat()
        if path.is_symlink():
            mode = stat.S_IFLNK | 0o777
            data = os.readlink(path).encode("utf-8", errors="surrogateescape")
        elif path.is_dir():
            mode = stat.S_IFDIR | 0o755
            data = b""
        else:
            mode = stat.S_IFREG | (st.st_mode & 0o777)
            data = path.read_bytes()
        mtime = int(st.st_mtime) if st.st_mtime else now
        buf.extend(_cpio_crc_entry(rel.encode("utf-8"), mode, data, mtime, inode))
        inode += 1

    buf.extend(_cpio_crc_entry(CPIO_TRAILER, 0, b"", now, inode))
    return bytes(buf)


def _gzip_bytes(data: bytes) -> bytes:
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(data)
    return out.getvalue()


def _sha1_hex(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _sha1_file(path: Path) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class _RpmHeaderBuilder:
    def __init__(self) -> None:
        self._entries: List[Tuple[int, int, int, bytes, int]] = []

    def add(self, tag: int, typ: int, count: int, value: bytes, *, pad: int = 1) -> None:
        self._entries.append((tag, typ, count, value, pad))

    def add_string(self, tag: int, text: str) -> None:
        self.add(tag, RPM_STRING_TYPE, 1, (text + "\0").encode("utf-8"))

    def add_string_array(self, tag: int, strings: Sequence[str]) -> None:
        blob = "\0".join(strings).encode("utf-8") + b"\0"
        self.add(tag, RPM_STRING_ARRAY_TYPE, len(strings), blob)

    def add_uint32_array(self, tag: int, values: Sequence[int]) -> None:
        blob = b"".join(struct.pack(">I", int(v)) for v in values)
        self.add(tag, RPM_INT32_TYPE, len(values), blob, pad=4)

    def add_uint16_array(self, tag: int, values: Sequence[int]) -> None:
        blob = b"".join(struct.pack(">H", int(v)) for v in values)
        self.add(tag, RPM_INT16_TYPE, len(values), blob, pad=2)

    def build(self) -> bytes:
        index = bytearray()
        store = bytearray()
        for tag, typ, count, value, pad in self._entries:
            while len(store) % pad:
                store.append(0)
            index.extend(struct.pack(">IIII", tag, typ, len(store), count))
            store.extend(value)
        body = bytearray()
        body.extend(b"\x8e\xad\xe0\x11")
        body.extend(b"\x00" * 4)
        body.extend(struct.pack(">II", len(self._entries), len(store)))
        body.extend(index)
        body.extend(store)
        while len(body) % 8:
            body.append(0)
        return bytes(body)


def _rpm_lead(name: str, version: str, release: str) -> bytes:
    lead_name = f"{name}-{version}-{release}"[:65]
    lead_name = lead_name.ljust(66, "\0")
    parts = [
        b"\xed\xab\xee\xdb",  # magic
        b"\x03",  # major
        b"\x00",  # minor
        b"\x00\x00",  # type binary
        b"\xff\xff",  # noarch
        lead_name.encode("ascii", errors="replace"),
        b"\x00\x01",  # os linux
        b"\x00\x05",  # signature type
        b"\x00" * 16,
    ]
    return b"".join(parts)


def _rpm_signature(payload_size: int) -> bytes:
    sig = bytearray()
    sig.extend(b"\x8e\xad\xe0\x11")
    sig.extend(b"\x00" * 4)
    sig.extend(struct.pack(">II", 1, 4))
    sig.extend(struct.pack(">IIII", RPMSIGTAG_PAYLOADSIZE, RPM_INT32_TYPE, 0, 1))
    sig.extend(struct.pack(">I", int(payload_size)))
    while len(sig) % 8:
        sig.append(0)
    return bytes(sig)


def build_binary_rpm(
    output_path: Path,
    *,
    name: str,
    version: str,
    release: str,
    file_tree: Path,
    summary: str = "System package",
    description: str = "KittySploit package",
    license_text: str = "MIT",
    arch: str = "noarch",
    postin: Optional[str] = None,
    preun: Optional[str] = None,
) -> Path:
    """Write a noarch binary RPM from ``file_tree`` (pure Python, any OS)."""
    file_tree = file_tree.resolve()
    if not file_tree.is_dir():
        raise ValueError(f"file_tree is not a directory: {file_tree}")

    all_files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(file_tree):
        dirnames.sort()
        filenames.sort()
        base = Path(dirpath)
        for d in dirnames:
            all_files.append(base / d)
        for f in filenames:
            all_files.append(base / f)
    all_files.sort(key=lambda p: str(p.relative_to(file_tree)).replace("\\", "/"))

    dirs = sorted({str(p.parent.relative_to(file_tree)).replace("\\", "/") for p in all_files})
    dir_index: Dict[str, int] = {d: i for i, d in enumerate(dirs)}

    def rpm_dirname(rel_dir: str) -> str:
        if rel_dir in (".", ""):
            return "/"
        return f"/{rel_dir}/"

    dirnames = [rpm_dirname(d) for d in dirs]
    basenames: List[str] = []
    dirindexes: List[int] = []
    filesizes: List[int] = []
    filemodes: List[int] = []
    filemtimes: List[int] = []
    filelinktos: List[str] = []
    filedigests: List[str] = []
    fileflags: List[int] = []

    for path in all_files:
        rel_dir = str(path.parent.relative_to(file_tree)).replace("\\", "/")
        basenames.append(path.name)
        dirindexes.append(dir_index[rel_dir])
        st = path.lstat()
        if path.is_symlink():
            target = os.readlink(path)
            target_bytes = target.encode("utf-8", errors="surrogateescape")
            filesizes.append(len(target_bytes))
            filemodes.append(stat.S_IFLNK | 0o777)
            filelinktos.append(target)
            filedigests.append(_sha1_hex(target_bytes))
        elif path.is_dir():
            filesizes.append(0)
            filemodes.append(stat.S_IFDIR | 0o755)
            filelinktos.append("")
            filedigests.append(_sha1_hex(b""))
        else:
            filesizes.append(st.st_size)
            filemodes.append(stat.S_IFREG | (st.st_mode & 0o777))
            filelinktos.append("")
            filedigests.append(_sha1_file(path))
        filemtimes.append(int(st.st_mtime) if st.st_mtime else int(time.time()))
        fileflags.append(0)

    cpio = build_cpio_crc_from_tree(file_tree)
    payload = _gzip_bytes(cpio)

    hdr = _RpmHeaderBuilder()
    hdr.add_string(RPMTAG_NAME, name)
    hdr.add_string(RPMTAG_VERSION, version)
    hdr.add_string(RPMTAG_RELEASE, release)
    hdr.add_string(RPMTAG_SUMMARY, summary)
    hdr.add_string(RPMTAG_DESCRIPTION, description)
    hdr.add_string(RPMTAG_LICENSE, license_text)
    hdr.add_string(RPMTAG_OS, "linux")
    hdr.add_string(RPMTAG_ARCH, arch)
    hdr.add_string(RPMTAG_SOURCERPM, "")
    hdr.add_uint32_array(RPMTAG_BUILDTIME, [int(time.time())])
    hdr.add_string(RPMTAG_PAYLOADFORMAT, "cpio")
    hdr.add_string(RPMTAG_PAYLOADCOMPRESSOR, "gzip")

    if postin:
        hdr.add_string(RPMTAG_POSTIN, postin)
    if preun:
        hdr.add_string(RPMTAG_PREUN, preun)

    hdr.add_string_array(RPMTAG_DIRNAMES, dirnames)
    hdr.add_string_array(RPMTAG_BASENAMES, basenames)
    hdr.add_uint32_array(RPMTAG_DIRINDEXES, dirindexes)
    hdr.add_string_array(RPMTAG_FILEUSERNAME, ["root"] * len(basenames))
    hdr.add_string_array(RPMTAG_FILEGROUPNAME, ["root"] * len(basenames))
    hdr.add_uint32_array(RPMTAG_FILEFLAGS, fileflags)
    hdr.add_uint32_array(RPMTAG_FILESIZES, filesizes)
    hdr.add_string_array(RPMTAG_FILELINKTOS, filelinktos)
    hdr.add_uint32_array(RPMTAG_FILEMTIMES, filemtimes)
    hdr.add_uint16_array(RPMTAG_FILERDEVS, [0] * len(basenames))
    hdr.add_uint32_array(RPMTAG_FILEINODES, list(range(1, len(basenames) + 1)))
    hdr.add_string_array(RPMTAG_FILELANGS, [""] * len(basenames))
    hdr.add_uint16_array(RPMTAG_FILEMODES, filemodes)
    hdr.add_uint32_array(RPMTAG_FILEDIGESTALGO, [PGPHASHALGO_SHA1])
    hdr.add_string_array(RPMTAG_FILEDIGESTS, filedigests)
    hdr.add_uint32_array(RPMTAG_PAYLOADDIGESTALGO, [PGPHASHALGO_SHA1])
    hdr.add_string_array(RPMTAG_PAYLOADDIGEST, [_sha1_hex(payload)])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as out:
        out.write(_rpm_lead(name, version, release))
        out.write(_rpm_signature(len(cpio)))
        out.write(hdr.build())
        out.write(payload)
    return output_path
