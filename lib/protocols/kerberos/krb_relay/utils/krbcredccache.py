from impacket.krb5 import types
from impacket.krb5.ccache import CCache, Header, Credential, Times, CountedOctetString, Principal, Ticket
from pyasn1.codec.der import encoder

try:
    from impacket.krb5.ccache import KeyBlockV4 as KeyBlock
except ImportError:
    from impacket.krb5.ccache import KeyBlock


class KrbCredCCache(CCache):
    def fromKrbCredTicket(self, ticket, ticketdata):
        self.headers = []
        header = Header()
        header["tag"] = 1
        header["taglen"] = 8
        header["tagdata"] = b"\xff\xff\xff\xff\x00\x00\x00\x00"
        self.headers.append(header)

        tmp_principal = types.Principal()
        tmp_principal.from_asn1(ticketdata, "prealm", "pname")
        self.principal = Principal()
        self.principal.fromPrincipal(tmp_principal)

        credential = Credential()
        server = types.Principal()
        server.from_asn1(ticketdata, "srealm", "sname")
        tmp_server = Principal()
        tmp_server.fromPrincipal(server)

        credential["client"] = self.principal
        credential["server"] = tmp_server
        credential["is_skey"] = 0
        credential["key"] = KeyBlock()
        credential["key"]["keytype"] = int(ticketdata["key"]["keytype"])
        credential["key"]["keyvalue"] = bytes(ticketdata["key"]["keyvalue"])
        credential["key"]["keylen"] = len(credential["key"]["keyvalue"])

        credential["time"] = Times()
        credential["time"]["authtime"] = self.toTimeStamp(types.KerberosTime.from_asn1(ticketdata["starttime"]))
        credential["time"]["starttime"] = self.toTimeStamp(types.KerberosTime.from_asn1(ticketdata["starttime"]))
        credential["time"]["endtime"] = self.toTimeStamp(types.KerberosTime.from_asn1(ticketdata["endtime"]))
        credential["time"]["renew_till"] = self.toTimeStamp(types.KerberosTime.from_asn1(ticketdata["renew-till"]))

        credential["tktflags"] = self.reverseFlags(ticketdata["flags"])
        credential["num_address"] = 0
        credential.ticket = CountedOctetString()
        credential.ticket["data"] = encoder.encode(ticket.clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
        credential.ticket["length"] = len(credential.ticket["data"])
        credential.secondTicket = CountedOctetString()
        credential.secondTicket["data"] = b""
        credential.secondTicket["length"] = 0
        self.credentials.append(credential)
