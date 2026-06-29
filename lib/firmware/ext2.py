#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Lecteur ext2 minimal en lecture seule (parcours, lecture de fichiers, extraction).
"""

from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional, Tuple

EXT2_MAGIC = 0xEF53
SUPERBLOCK_OFFSET = 1024


class Ext2Reader:
    """Lecteur ext2 read-only pour images disque ou partitions brutes."""

    def __init__(self, data: bytes, partition_offset: int = 512) -> None:
        self.data = data
        self.partition_offset = partition_offset
        self._parse_superblock()
        self._load_group_descriptors()

    @classmethod
    def from_image(cls, data: bytes) -> "Ext2Reader":
        offset = cls.find_partition_offset(data)
        return cls(data, offset)

    @staticmethod
    def find_partition_offset(data: bytes, scan_limit: int = 256 * 1024) -> int:
        """Localise le début d'une partition ext2 dans un buffer."""
        candidates: List[int] = []

        for offset in (512, 0, 1024, 2048):
            if offset not in candidates:
                candidates.append(offset)

        limit = min(len(data), scan_limit)
        for offset in range(0, limit, 512):
            if offset not in candidates:
                candidates.append(offset)

        for offset in candidates:
            sb_off = offset + SUPERBLOCK_OFFSET
            if sb_off + 58 > len(data):
                continue
            magic = int.from_bytes(data[sb_off + 56 : sb_off + 58], "little")
            if magic != EXT2_MAGIC:
                continue
            try:
                Ext2Reader(data, offset)
                return offset
            except ValueError:
                continue

        raise ValueError("ext2 partition not found in image")

    def _parse_superblock(self) -> None:
        sb_off = self.partition_offset + SUPERBLOCK_OFFSET
        if sb_off + 1024 > len(self.data):
            raise ValueError("truncated ext2 superblock")

        sb = self.data[sb_off : sb_off + 1024]
        magic = int.from_bytes(sb[56:58], "little")
        if magic != EXT2_MAGIC:
            raise ValueError(f"invalid ext2 magic 0x{magic:04x}")

        self.block_size = 1024 << int.from_bytes(sb[24:28], "little")
        self.inode_size = int.from_bytes(sb[88:90], "little") or 128
        self.inodes_per_group = int.from_bytes(sb[40:44], "little")
        self.blocks_per_group = int.from_bytes(sb[32:36], "little")
        self.first_data_block = int.from_bytes(sb[20:24], "little")
        self.total_inodes = int.from_bytes(sb[0:4], "little")

        if self.block_size < 1024 or self.inodes_per_group == 0:
            raise ValueError("unsupported ext2 geometry")

    def _load_group_descriptors(self) -> None:
        if self.block_size == 1024:
            desc_block = self.first_data_block + 1
        else:
            desc_block = self.first_data_block
        desc_off = self.partition_offset + desc_block * self.block_size
        desc_size = 32
        num_groups = (
            self.total_inodes + self.inodes_per_group - 1
        ) // self.inodes_per_group
        self.group_descriptors: List[dict] = []

        for i in range(num_groups):
            off = desc_off + i * desc_size
            chunk = self.data[off : off + desc_size]
            if len(chunk) < desc_size:
                break
            self.group_descriptors.append(
                {"inode_table": int.from_bytes(chunk[8:12], "little")}
            )

    def _inode_offset(self, inode_num: int) -> int:
        if inode_num < 1:
            raise ValueError("invalid inode number")
        group = (inode_num - 1) // self.inodes_per_group
        index = (inode_num - 1) % self.inodes_per_group
        if group >= len(self.group_descriptors):
            raise ValueError(f"inode {inode_num} out of range")
        table_block = self.group_descriptors[group]["inode_table"]
        return (
            self.partition_offset
            + table_block * self.block_size
            + index * self.inode_size
        )

    def _read_inode(self, inode_num: int) -> dict:
        off = self._inode_offset(inode_num)
        raw = self.data[off : off + self.inode_size]
        if len(raw) < 128:
            raise ValueError(f"truncated inode {inode_num}")

        mode = int.from_bytes(raw[0:2], "little")
        size = int.from_bytes(raw[4:8], "little")
        blocks = [
            int.from_bytes(raw[40 + i * 4 : 44 + i * 4], "little") for i in range(12)
        ]
        indirect = int.from_bytes(raw[88:92], "little")
        double_indirect = int.from_bytes(raw[92:96], "little")
        triple_indirect = int.from_bytes(raw[96:100], "little")

        return {
            "mode": mode,
            "size": size,
            "blocks": blocks,
            "indirect": indirect,
            "double_indirect": double_indirect,
            "triple_indirect": triple_indirect,
        }

    def _block_offset(self, block_num: int) -> int:
        return self.partition_offset + block_num * self.block_size

    def _read_block(self, block_num: int) -> bytes:
        if block_num == 0:
            return b""
        off = self._block_offset(block_num)
        return self.data[off : off + self.block_size]

    def _collect_block_numbers(self, inode: dict) -> List[int]:
        out: List[int] = [b for b in inode["blocks"] if b]

        def read_ptr_block(block_num: int) -> List[int]:
            raw = self._read_block(block_num)
            nums = []
            for i in range(0, len(raw), 4):
                val = int.from_bytes(raw[i : i + 4], "little")
                if val:
                    nums.append(val)
            return nums

        if inode["indirect"]:
            out.extend(read_ptr_block(inode["indirect"]))

        if inode["double_indirect"]:
            for ptr in read_ptr_block(inode["double_indirect"]):
                out.extend(read_ptr_block(ptr))

        if inode["triple_indirect"]:
            for ptr1 in read_ptr_block(inode["triple_indirect"]):
                for ptr2 in read_ptr_block(ptr1):
                    out.extend(read_ptr_block(ptr2))

        return out

    def read_file(self, inode_num: int) -> bytes:
        inode = self._read_inode(inode_num)
        if (inode["mode"] & 0xF000) == 0x4000:
            raise IsADirectoryError(inode_num)

        chunks: List[bytes] = []
        remaining = inode["size"]
        for block_num in self._collect_block_numbers(inode):
            if remaining <= 0:
                break
            block = self._read_block(block_num)
            take = min(remaining, len(block))
            chunks.append(block[:take])
            remaining -= take
        return b"".join(chunks)

    def list_dir(self, inode_num: int = 2) -> Dict[str, int]:
        inode = self._read_inode(inode_num)
        if (inode["mode"] & 0xF000) != 0x4000:
            raise NotADirectoryError(inode_num)

        entries: Dict[str, int] = {}
        for block_num in self._collect_block_numbers(inode):
            block = self._read_block(block_num)
            offset = 0
            while offset + 8 <= len(block):
                entry_inode = int.from_bytes(block[offset : offset + 4], "little")
                rec_len = int.from_bytes(block[offset + 4 : offset + 6], "little")
                if rec_len < 8:
                    break
                name_len = block[offset + 6]
                name = block[offset + 8 : offset + 8 + name_len].decode(
                    "utf-8", errors="replace"
                )
                if entry_inode and name not in (".", ".."):
                    entries[name] = entry_inode
                offset += rec_len
        return entries

    def find_path(self, path: str) -> Optional[int]:
        parts = [p for p in path.strip("/").split("/") if p]
        inode_num = 2
        for part in parts:
            entries = self.list_dir(inode_num)
            if part not in entries:
                return None
            inode_num = entries[part]
        return inode_num

    def read_file_by_name(self, name: str) -> Optional[bytes]:
        inode = self.find_path(name)
        if inode is not None:
            try:
                return self.read_file(inode)
            except (IsADirectoryError, ValueError):
                return None

        queue: List[Tuple[int, str]] = [(2, "")]
        while queue:
            inode_num, prefix = queue.pop(0)
            try:
                entries = self.list_dir(inode_num)
            except (NotADirectoryError, ValueError):
                continue
            for entry_name, child_inode in entries.items():
                full = f"{prefix}/{entry_name}" if prefix else entry_name
                if entry_name == name:
                    try:
                        return self.read_file(child_inode)
                    except (IsADirectoryError, ValueError):
                        return None
                child = self._read_inode(child_inode)
                if (child["mode"] & 0xF000) == 0x4000:
                    queue.append((child_inode, full))
        return None

    def extract_files(
        self,
        output_dir: str,
        filenames: Iterable[str],
        *,
        missing_ok: bool = False,
    ) -> Dict[str, str]:
        """
        Extrait des fichiers nommés vers ``output_dir``.

        Retourne un mapping ``nom -> chemin local``. Lève ``FileNotFoundError``
        si un fichier est absent et ``missing_ok`` est False.
        """
        os.makedirs(output_dir, exist_ok=True)
        extracted: Dict[str, str] = {}
        missing: List[str] = []

        for name in filenames:
            content = self.read_file_by_name(name)
            if content is None:
                missing.append(name)
                continue
            dest = os.path.join(output_dir, name)
            parent = os.path.dirname(dest)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(dest, "wb") as f:
                f.write(content)
            extracted[name] = dest

        if missing and not missing_ok:
            raise FileNotFoundError(
                "files not found in ext2 image: " + ", ".join(missing)
            )
        return extracted

    @staticmethod
    def verify_files(directory: str, filenames: Iterable[str]) -> bool:
        return all(os.path.isfile(os.path.join(directory, name)) for name in filenames)
