#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Ed25519 implant identity helpers for backdoor modules."""

from __future__ import annotations

from typing import Any, Optional

from lib.implant.identity import (
    ImplantIdentity,
    generate_implant_identity,
    load_implant_identity,
    save_implant_identity,
)


def _opt_bool(module: Any, name: str, default: bool = True) -> bool:
    attr = getattr(module, name, default)
    if hasattr(attr, "value"):
        return bool(attr.value)
    return bool(attr) if attr is not None else default


def _opt_str(module: Any, name: str, default: str = "") -> str:
    attr = getattr(module, name, default)
    if hasattr(attr, "value"):
        return str(attr.value or default)
    return str(attr or default)


def apply_implant_identity(module: Any, *, default_enabled: bool = True) -> Optional[ImplantIdentity]:
    """Resolve or generate Ed25519 identity; set client_id and public key on module."""
    if not _opt_bool(module, "implant_identity", default_enabled):
        return None

    existing = _opt_str(module, "implant_id", "").strip()
    keys_dir = "output/implant_keys"
    if existing:
        path = __import__("pathlib").Path(keys_dir) / f"{existing}.json"
        if path.is_file():
            identity = load_implant_identity(path)
        else:
            identity = generate_implant_identity()
            save_implant_identity(identity, keys_dir)
    else:
        identity = generate_implant_identity()
        path = save_implant_identity(identity, keys_dir)
        from core.output_handler import print_success

        print_success(f"Implant identity {identity.implant_id} saved to {path}")

    for opt_name in ("client_id", "implant_id"):
        if hasattr(module, opt_name):
            opt = getattr(module, opt_name)
            if hasattr(opt, "value"):
                opt.value = identity.implant_id
            else:
                setattr(module, opt_name, identity.implant_id)

    module._implant_identity_obj = identity
    module._implant_public_key_pem = identity.public_key_pem
    return identity
