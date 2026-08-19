from __future__ import annotations

from typing import Any, Type

_KrbRelayxConfigCls: Type[Any] | None = None


def get_krb_relayx_config_class() -> Type[Any]:
    """Return KrbRelayxConfig, importing impacket only when needed."""
    global _KrbRelayxConfigCls
    if _KrbRelayxConfigCls is not None:
        return _KrbRelayxConfigCls

    from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

    class KrbRelayxConfig(NTLMRelayxConfig):
        def __init__(self):
            super().__init__()
            self.dcip = None
            self.aeskey = None
            self.hashes = None
            self.password = None
            self.israwpassword = False
            self.salt = None
            self.format = "ccache"
            self.dumpdomain = True
            self.addda = True
            self.aclattack = True
            self.validateprivs = True
            self.escalateuser = None
            self.addcomputer = False
            self.delegateaccess = False
            self.queries = []
            self.interactive = False
            self.victim = None

        def setLDAPOptions(self, dumpdomain, addda, aclattack, validateprivs, escalateuser, addcomputer, delegateaccess, dumplaps, dumpgmsa, dumpadcs, sid):
            self.dumpdomain = dumpdomain
            self.addda = addda
            self.aclattack = aclattack
            self.validateprivs = validateprivs
            self.escalateuser = escalateuser
            self.addcomputer = addcomputer
            self.delegateaccess = delegateaccess
            self.dumplaps = dumplaps
            self.dumpgmsa = dumpgmsa
            self.dumpadcs = dumpadcs
            self.sid = sid

        def setMSSQLOptions(self, queries):
            self.queries = queries or []

        def setInteractive(self, interactive):
            self.interactive = interactive

        def setAuthOptions(self, aeskey, hashes, dcip, password, salt, israwpassword=False):
            self.dcip = dcip
            self.aeskey = aeskey
            self.hashes = hashes
            self.password = password
            self.salt = salt
            self.israwpassword = israwpassword

        def setKrbOptions(self, outformat, victim):
            self.format = outformat
            self.victim = victim

    _KrbRelayxConfigCls = KrbRelayxConfig
    return _KrbRelayxConfigCls


class KrbRelayxConfig:
    """Lazy proxy so modules can import this package without impacket installed."""

    def __new__(cls, *args, **kwargs):
        return get_krb_relayx_config_class()(*args, **kwargs)
