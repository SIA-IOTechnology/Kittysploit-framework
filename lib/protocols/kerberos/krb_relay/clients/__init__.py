from lib.protocols.kerberos.krb_relay.clients.base import ProtocolClient
from lib.protocols.kerberos.krb_relay.clients.httprelayclient import HTTPRelayClient, HTTPSRelayClient
from lib.protocols.kerberos.krb_relay.clients.mssqlrelayclient import MSSQLRelayClient

PROTOCOL_CLIENTS = {
    HTTPRelayClient.PLUGIN_NAME: HTTPRelayClient,
    HTTPSRelayClient.PLUGIN_NAME: HTTPSRelayClient,
    MSSQLRelayClient.PLUGIN_NAME: MSSQLRelayClient,
}

__all__ = ["ProtocolClient", "PROTOCOL_CLIENTS", "HTTPRelayClient", "HTTPSRelayClient", "MSSQLRelayClient"]
