#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal Kerberos ASN.1 message types (pyasn1 only, no Impacket)."""

from __future__ import annotations

from pyasn1.type import char, namedtype, tag, univ, useful


def _ctx(name: str, num: int, asn1_type):
    return namedtype.NamedType(
        name,
        asn1_type.subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, num)
        ),
    )


def _opt(name: str, num: int, asn1_type):
    return namedtype.OptionalNamedType(
        name,
        asn1_type.subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, num)
        ),
    )


class KerberosString(char.GeneralString):
    pass


class Realm(KerberosString):
    pass


class PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _ctx("name-type", 0, univ.Integer()),
        namedtype.NamedType(
            "name-string",
            univ.SequenceOf(componentType=KerberosString()).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
    )


class HostAddress(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _ctx("addr-type", 0, univ.Integer()),
        _ctx("address", 1, univ.OctetString()),
    )


class HostAddresses(univ.SequenceOf):
    componentType = HostAddress()


class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _ctx("etype", 0, univ.Integer()),
        _opt("kvno", 1, univ.Integer()),
        _ctx("cipher", 2, univ.OctetString()),
    )


class Ticket(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1)
    )
    componentType = namedtype.NamedTypes(
        _ctx("tkt-vno", 0, univ.Integer()),
        _ctx("realm", 1, Realm()),
        _ctx("sname", 2, PrincipalName()),
        _ctx("enc-part", 3, EncryptedData()),
    )


class PA_DATA(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _ctx("padata-type", 1, univ.Integer()),
        _ctx("padata-value", 2, univ.OctetString()),
    )


class METHOD_DATA(univ.SequenceOf):
    componentType = PA_DATA()


class KDCOptions(univ.BitString):
    pass


class KDC_REQ_BODY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _ctx("kdc-options", 0, KDCOptions()),
        _opt("cname", 1, PrincipalName()),
        _ctx("realm", 2, Realm()),
        _opt("sname", 3, PrincipalName()),
        _opt("from", 4, useful.GeneralizedTime()),
        _ctx("till", 5, useful.GeneralizedTime()),
        _opt("rtime", 6, useful.GeneralizedTime()),
        _ctx("nonce", 7, univ.Integer()),
        namedtype.NamedType(
            "etype",
            univ.SequenceOf(componentType=univ.Integer()).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8)
            ),
        ),
        _opt("addresses", 9, HostAddresses()),
        _opt("enc-authorization-data", 10, EncryptedData()),
        namedtype.OptionalNamedType(
            "additional-tickets",
            univ.SequenceOf(componentType=Ticket()).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11)
            ),
        ),
    )


class KDC_REQ(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _ctx("pvno", 1, univ.Integer()),
        _ctx("msg-type", 2, univ.Integer()),
        namedtype.OptionalNamedType(
            "padata",
            METHOD_DATA().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            ),
        ),
        _ctx("req-body", 4, KDC_REQ_BODY()),
    )


class AS_REQ(KDC_REQ):
    tagSet = KDC_REQ.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 10)
    )


class TGS_REQ(KDC_REQ):
    tagSet = KDC_REQ.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 12)
    )


class KDC_REP(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _ctx("pvno", 0, univ.Integer()),
        _ctx("msg-type", 1, univ.Integer()),
        namedtype.OptionalNamedType(
            "padata",
            METHOD_DATA().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            ),
        ),
        _ctx("crealm", 3, Realm()),
        _ctx("cname", 4, PrincipalName()),
        _ctx("ticket", 5, Ticket()),
        _ctx("enc-part", 6, EncryptedData()),
    )


class AS_REP(KDC_REP):
    tagSet = KDC_REP.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 11)
    )


class TGS_REP(KDC_REP):
    tagSet = KDC_REP.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 13)
    )


class KRB_ERROR(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 30)
    )
    componentType = namedtype.NamedTypes(
        _ctx("pvno", 0, univ.Integer()),
        _ctx("msg-type", 1, univ.Integer()),
        _opt("ctime", 2, useful.GeneralizedTime()),
        _opt("cusec", 3, univ.Integer()),
        _ctx("stime", 4, useful.GeneralizedTime()),
        _ctx("susec", 5, univ.Integer()),
        _ctx("error-code", 6, univ.Integer()),
        _opt("crealm", 7, Realm()),
        _opt("cname", 8, PrincipalName()),
        _ctx("realm", 9, Realm()),
        _ctx("sname", 10, PrincipalName()),
        _opt("e-text", 11, KerberosString()),
        _opt("e-data", 12, univ.OctetString()),
    )


class KERB_PA_PAC_REQUEST(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _ctx("include-pac", 0, univ.Boolean()),
    )


class PA_ENC_TS_ENC(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _ctx("patimestamp", 0, useful.GeneralizedTime()),
        _opt("pausec", 1, univ.Integer()),
    )


class Authenticator(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 2)
    )
    componentType = namedtype.NamedTypes(
        _ctx("authenticator-vno", 0, univ.Integer()),
        _ctx("crealm", 1, Realm()),
        _ctx("cname", 2, PrincipalName()),
        _opt("cksum", 3, univ.Sequence()),
        _ctx("cusec", 4, univ.Integer()),
        _ctx("ctime", 5, useful.GeneralizedTime()),
        _opt("subkey", 6, univ.Sequence()),
        _opt("seq-number", 7, univ.Integer()),
        _opt("authorization-data", 8, univ.SequenceOf()),
    )


class AP_REQ(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 14)
    )
    componentType = namedtype.NamedTypes(
        _ctx("pvno", 0, univ.Integer()),
        _ctx("msg-type", 1, univ.Integer()),
        _ctx("ap-options", 2, univ.BitString()),
        _ctx("ticket", 3, Ticket()),
        _ctx("authenticator", 4, EncryptedData()),
    )


class EncryptionKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _ctx("keytype", 0, univ.Integer()),
        _ctx("keyvalue", 1, univ.OctetString()),
    )


class LastReq(univ.SequenceOf):
    componentType = univ.Sequence()


class EncKDCRepPart(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _ctx("key", 0, EncryptionKey()),
        _ctx("last-req", 1, LastReq()),
        _ctx("nonce", 2, univ.Integer()),
        _opt("key-expiration", 3, useful.GeneralizedTime()),
        _ctx("flags", 4, univ.BitString()),
        _ctx("authtime", 5, useful.GeneralizedTime()),
        _opt("starttime", 6, useful.GeneralizedTime()),
        _ctx("endtime", 7, useful.GeneralizedTime()),
        _opt("renew-till", 8, useful.GeneralizedTime()),
        _ctx("srealm", 9, Realm()),
        _ctx("sname", 10, PrincipalName()),
        _opt("caddr", 11, HostAddresses()),
    )


class EncASRepPart(EncKDCRepPart):
    tagSet = EncKDCRepPart.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 25)
    )


class EncTGSRepPart(EncKDCRepPart):
    tagSet = EncKDCRepPart.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 26)
    )


# Constants
NT_PRINCIPAL = 1
NT_SRV_INST = 2
NT_SRV_HST = 3

ETYPE_AES128 = 17
ETYPE_AES256 = 18
ETYPE_RC4 = 23

PA_TGS_REQ = 1
PA_ENC_TIMESTAMP = 2
PA_PAC_REQUEST = 128

AS_REQ_MSG = 10
AS_REP_MSG = 11
TGS_REQ_MSG = 12
TGS_REP_MSG = 13
KRB_ERROR_MSG = 30

KU_AS_REQ_PA_ENC_TS = 1
KU_TGS_REQ_AUTH = 7
KU_AS_REP_ENC_PART = 3
KU_TGS_REP_ENC_PART = 8

KDC_ERR_PREAUTH_REQUIRED = 25
KDC_ERR_ETYPE_NOSUPP = 14
