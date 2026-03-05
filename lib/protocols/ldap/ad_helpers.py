# -*- coding: utf-8 -*-
"""Helpers partagés pour les checks AD (dates, UAC, SID, etc.)."""

import datetime
from typing import Any, Optional

NOW = datetime.datetime.now(datetime.timezone.utc)

# UAC flags
UAC_DISABLED = 0x0002
UAC_PASSWD_NOTREQD = 0x0020
UAC_DONT_EXPIRE_PASSWD = 0x10000
UAC_NO_PREAUTH = 0x400000

# Well-known RIDs
_DA_RID, _EA_RID, _DC_RID, _RODC_RID, _EDC_RID, _SA_RID = "512", "519", "516", "521", "498", "518"
_ADMINS = "S-1-5-32-544"
_SYSTEM = "S-1-5-18"
_ENTERPRISE_DCS = "S-1-5-9"


def attr_raw(entry: Any, name: str) -> Any:
    """Extraire la valeur brute d'un attribut LDAP (ldap3 Entry ou dict)."""
    raw = getattr(entry, name, None)
    if raw is None and isinstance(entry, dict):
        raw = entry.get(name)
    if raw is None:
        return None
    if hasattr(raw, "value"):
        return raw.value
    if hasattr(raw, "raw_values") and raw.raw_values:
        return raw.raw_values[0]
    if isinstance(raw, (list, tuple)) and raw:
        return raw[0]
    return raw


def ldap_ts_to_dt(raw: Any) -> Optional[datetime.datetime]:
    """Convertir un timestamp LDAP (Windows filetime ou string) en datetime."""
    if raw is None:
        return None
    if isinstance(raw, datetime.datetime):
        return raw.replace(tzinfo=datetime.timezone.utc) if raw.tzinfo is None else raw
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="ignore")
    if isinstance(raw, str) and len(raw) >= 14 and not raw.lstrip("-").isdigit():
        try:
            clean = raw.split(".")[0].replace("Z", "")
            return datetime.datetime.strptime(clean, "%Y%m%d%H%M%S").replace(tzinfo=datetime.timezone.utc)
        except (ValueError, IndexError):
            pass
    try:
        v = int(raw)
        if v <= 0:
            return None
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return epoch + datetime.timedelta(microseconds=v // 10)
    except (ValueError, TypeError, OverflowError):
        return None


def days_since(dt: Optional[datetime.datetime]) -> Optional[int]:
    """Nombre de jours depuis dt jusqu'à maintenant."""
    if dt is None:
        return None
    return (NOW - dt).days


def filetime_100ns_to_days(val: int) -> int:
    """Convertir un filetime (100ns, négatif pour âge) en jours."""
    if val >= 0:
        return 0
    return abs(val) // 864_000_000_000


def get_domain_sid(ad: Any) -> str:
    """Récupérer le SID du domaine depuis l'objet domain."""
    dom = ad.get_domain_object()
    if not dom:
        return ""
    raw = attr_raw(dom, "objectSid")
    if not raw:
        return ""
    s = str(raw)
    parts = s.split("-")
    if len(parts) == 8:
        return "-".join(parts[:7])
    return s


def sid_is_privileged(sid: str, domain_sid: str) -> bool:
    """Indique si le SID est un compte privilégié connu."""
    if sid in (_ADMINS, _ENTERPRISE_DCS, _SYSTEM, "S-1-5-9", "S-1-5-32-548", "S-1-5-32-569", "S-1-5-11"):
        return True
    if not domain_sid:
        return False
    for rid in (_DA_RID, _EA_RID, _DC_RID, _SA_RID, _RODC_RID, _EDC_RID, "517"):
        if sid == f"{domain_sid}-{rid}":
            return True
    return False
