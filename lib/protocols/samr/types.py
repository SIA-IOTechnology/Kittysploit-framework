# -*- coding: utf-8 -*-
"""Types partagés pour l'énumération SAMR / NetAPI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SamAccountRecord:
    """Compte SAM avec attributs comportementaux (oracle lastLogon)."""

    name: str
    last_logon: int = 0
    logon_count: int = 0
    password_last_set: int = 0
    description: str = ""
    admin_comment: str = ""
    rid: int = 0
    user_account_control: int = 0
    source: str = "samr"

    @property
    def is_computer(self) -> bool:
        return self.name.endswith("$")


@dataclass
class SamAliasRecord:
    """Alias / groupe local exposé via SAMR."""

    name: str
    rid: int
    domain_sid: bytes = b""


@dataclass
class SamGroupMembership:
    """Membres d'un alias SAMR."""

    group_name: str
    group_rid: int
    members: List[str]
