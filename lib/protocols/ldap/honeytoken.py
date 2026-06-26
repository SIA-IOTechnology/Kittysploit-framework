# -*- coding: utf-8 -*-
"""Analyse comportementale des honeytokens AD (oracle lastLogon, historique vide)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from lib.protocols.ldap.ad_helpers import attr_raw, ldap_ts_to_dt

try:
    from lib.protocols.samr.types import SamAccountRecord
except ImportError:
    SamAccountRecord = None  # type: ignore

# Noms suggestifs souvent utilisés pour les leurres (svc_backup_adm, sql_da, …)
_ATTRACTIVE_NAME = re.compile(
    r"(?:^|[._-])(?:svc|sql|backup|adm|admin|da|root|oracle|postgres|exchange|"
    r"sharepoint|vmware|vsphere|krb|krbtgt|sap|jenkins|gitlab)(?:[._-]|$)",
    re.IGNORECASE,
)

PROBABLE_THRESHOLD = 75.0
SUSPICIOUS_THRESHOLD = 50.0


def is_never_logged_on(raw: Any) -> bool:
    """
    Indique si lastLogon (ou pwdLastSet) n'a jamais été écrit.

    lastLogon=0 reste à zéro tant qu'aucune auth réussie n'a eu lieu.
    Les outils affichent souvent 1601-01-01 ou 1600-12-31 (décalage TZ) : même signal.
    """
    if raw is None:
        return True
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="ignore")
    try:
        return int(raw) <= 0
    except (TypeError, ValueError):
        return ldap_ts_to_dt(raw) is None


def is_machine_account(sam: str) -> bool:
    return bool(sam) and sam.endswith("$")


def looks_attractive(sam: str, description: str = "") -> bool:
    haystack = f"{sam} {description}".strip()
    return bool(_ATTRACTIVE_NAME.search(haystack))


@dataclass
class HoneytokenAssessment:
    sam_account: str
    score: float
    verdict: str
    signals: List[str] = field(default_factory=list)
    is_computer: bool = False
    never_logged_on: bool = False
    logon_count: int = 0
    admin_count: int = 0

    @property
    def identity_key(self) -> str:
        return self.sam_account.lower()


def assess_account(
    sam: str,
    *,
    last_logon: Any = None,
    logon_count: int = 0,
    admin_count: int = 0,
    pwd_last_set: Any = None,
    description: str = "",
    is_computer: Optional[bool] = None,
) -> HoneytokenAssessment:
    """Score un compte AD à partir d'attributs comportementaux (pas d'auth requise)."""
    if is_computer is None:
        is_computer = is_machine_account(sam)

    signals: List[str] = []
    score = 0.0
    never_logged = is_never_logged_on(last_logon)
    pwd_never_set = is_never_logged_on(pwd_last_set)

    if is_computer:
        if never_logged:
            signals.append(
                "machine account never authenticated (domain join impossible without logon)"
            )
            score += 85.0
        if logon_count == 0 and never_logged:
            signals.append("logonCount=0 on computer account")
            score += 10.0
    else:
        if never_logged:
            signals.append("lastLogon never set (no successful authentication recorded)")
            score += 35.0
        if logon_count == 0:
            signals.append("logonCount=0")
            score += 15.0

    if admin_count == 1:
        signals.append("adminCount=1 (privileged/protected object marker)")
        score += 20.0

    if looks_attractive(sam, description):
        signals.append("attractive naming pattern (common honeytoken convention)")
        score += 15.0

    if never_logged and pwd_never_set:
        signals.append("pwdLastSet unset alongside empty authentication history")
        score += 10.0

    # Identité convaincante + historique vide = écart typique des decoys
    if never_logged and (admin_count == 1 or looks_attractive(sam, description)):
        signals.append("high-value identity with no behavioural history")
        score += 15.0

    score = min(100.0, score)
    if score >= PROBABLE_THRESHOLD:
        verdict = "PROBABLE_HONEYTOKEN"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return HoneytokenAssessment(
        sam_account=sam,
        score=score,
        verdict=verdict,
        signals=signals,
        is_computer=is_computer,
        never_logged_on=never_logged,
        logon_count=logon_count,
        admin_count=admin_count,
    )


def assess_ldap_entry(entry: Any) -> Optional[HoneytokenAssessment]:
    """Évalue une entrée ldap3 (user ou computer)."""
    sam = str(attr_raw(entry, "sAMAccountName") or "").strip()
    if not sam:
        return None

    logon_raw = attr_raw(entry, "logonCount")
    try:
        logon_count = int(logon_raw or 0)
    except (TypeError, ValueError):
        logon_count = 0

    admin_raw = attr_raw(entry, "adminCount")
    try:
        admin_count = int(admin_raw or 0)
    except (TypeError, ValueError):
        admin_count = 0

    description = str(attr_raw(entry, "description") or "")

    return assess_account(
        sam,
        last_logon=attr_raw(entry, "lastLogon"),
        logon_count=logon_count,
        admin_count=admin_count,
        pwd_last_set=attr_raw(entry, "pwdLastSet"),
        description=description,
    )


def assess_sam_record(record: "SamAccountRecord") -> Optional[HoneytokenAssessment]:
    """Évalue un compte issu de SAMR / NetUserEnum."""
    if not record or not record.name:
        return None
    description = record.description or record.admin_comment or ""
    return assess_account(
        record.name,
        last_logon=record.last_logon,
        logon_count=record.logon_count,
        admin_count=0,
        pwd_last_set=record.password_last_set,
        description=description,
        is_computer=record.is_computer,
    )


def assessments_to_guardian_payload(
    domain: str,
    assessments: List[HoneytokenAssessment],
    source: str = "ldap",
) -> List[Dict[str, Any]]:
    """Convertit des évaluations pour enregistrement Guardian."""
    rows: List[Dict[str, Any]] = []
    for item in assessments:
        rows.append(
            {
                "sam_account": item.sam_account,
                "domain": domain,
                "account_type": "computer" if item.is_computer else "user",
                "score": item.score,
                "verdict": item.verdict,
                "signals": list(item.signals),
                "never_logged_on": item.never_logged_on,
                "logon_count": item.logon_count,
                "admin_count": item.admin_count,
                "source": source,
            }
        )
    return rows
