from pyasn1.type import univ, char, namedtype, namedval, tag

from lib.protocols.kerberos.krb_relay.utils.krb5_asn1 import AP_REQ


def _sequence_component(name, tag_num, asn1_type):
    return namedtype.NamedType(
        name,
        asn1_type.subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tag_num),
        ),
    )


def _sequence_optional_component(name, tag_num, asn1_type):
    return namedtype.OptionalNamedType(
        name,
        asn1_type.subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tag_num),
        ),
    )


MechTypes = {
    "1.3.6.1.4.1.311.2.2.10": "NTLMSSP - Microsoft NTLM Security Support Provider",
    "1.2.840.48018.1.2.2": "MS KRB5 - Microsoft Kerberos 5",
    "1.2.840.113554.1.2.2": "KRB5 - Kerberos 5",
    "1.2.840.113554.1.2.2.3": "KRB5 - Kerberos 5 - User to User",
    "1.3.6.1.4.1.311.2.2.30": "NEGOEX - SPNEGO Extended Negotiation Security Mechanism",
}

TypesMech = {value: key for key, value in MechTypes.items()}


class ContextFlags(univ.BitString):
    namedValues = namedval.NamedValues(
        ("delegFlag", 0),
        ("mutualFlag", 1),
        ("replayFlag", 2),
        ("sequenceFlag", 3),
        ("anonFlag", 4),
        ("confFlag", 5),
        ("integFlag", 6),
    )


class NegResult(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ("accept_completed", 0),
        ("accept_incomplete", 1),
        ("reject", 2),
        ("request_mic", 3),
    )


class MechType(univ.ObjectIdentifier):
    pass


class MechTypeList(univ.SequenceOf):
    componentType = MechType()


class NegHints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_optional_component("hintName", 0, char.GeneralString()),
        _sequence_optional_component("hintAddress", 1, univ.OctetString()),
    )


class NegTokenInit(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("mechTypes", 0, MechTypeList()),
        _sequence_optional_component("reqFlags", 1, ContextFlags()),
        _sequence_optional_component("mechToken", 2, univ.OctetString()),
        _sequence_optional_component("mechListMIC", 3, univ.OctetString()),
    )


class NegTokenInit2(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("mechTypes", 0, MechTypeList()),
        _sequence_optional_component("reqFlags", 1, ContextFlags()),
        _sequence_optional_component("mechToken", 2, univ.OctetString()),
        _sequence_optional_component("negHints", 3, NegHints()),
        _sequence_optional_component("mechListMIC", 4, univ.OctetString()),
    )


class NegTokenResp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_optional_component("negResult", 0, NegResult()),
        _sequence_optional_component("supportedMech", 1, MechType()),
        _sequence_optional_component("responseToken", 2, univ.OctetString()),
        _sequence_optional_component("mechListMIC", 3, univ.OctetString()),
    )


class NegotiationToken(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "negTokenInit",
            NegTokenInit().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)),
        ),
        namedtype.NamedType(
            "negTokenResp",
            NegTokenResp().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)),
        ),
    )


class GSSAPIHeader_SPNEGO_Init(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tokenOid", univ.ObjectIdentifier()),
        namedtype.NamedType("innerContextToken", NegotiationToken()),
    )


class GSSAPIHeader_SPNEGO_Init2(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tokenOid", univ.ObjectIdentifier()),
        _sequence_component("innerContextToken", 0, NegTokenInit2()),
    )


class GSSAPIHeader_KRB5_AP_REQ(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tokenOid", univ.ObjectIdentifier()),
        namedtype.NamedType("krb5_ap_req", univ.Boolean()),
        namedtype.NamedType("apReq", AP_REQ()),
    )


class GSSAPIHeader_KRB5_AP_REP(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 15))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tokenOid", univ.ObjectIdentifier()),
        namedtype.NamedType("krb5_ap_rep", univ.Integer()),
        namedtype.NamedType("apRep", univ.OctetString()),
    )
