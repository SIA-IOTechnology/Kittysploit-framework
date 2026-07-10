# -*- coding: utf-8 -*-
"""Minimal Kerberos ASN.1 definitions (pyasn1 only, no impacket)."""

from pyasn1.type import namedtype, tag, univ


def _seq_component(name, tag_num, asn1_type):
    return namedtype.NamedType(
        name,
        asn1_type.subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tag_num),
        ),
    )


class KerberosString(univ.SequenceOf):
    componentType = univ.GeneralString()


class PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _seq_component("name-type", 0, univ.Integer()),
        _seq_component("name-string", 1, KerberosString()),
    )


class Ticket(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _seq_component("tkt-vno", 0, univ.Integer()),
        _seq_component("realm", 1, univ.GeneralString()),
        _seq_component("sname", 2, PrincipalName()),
        _seq_component("enc-part", 3, univ.Sequence()),
    )


class AP_REQ(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 14),
    )
    componentType = namedtype.NamedTypes(
        _seq_component("pvno", 0, univ.Integer()),
        _seq_component("msg-type", 1, univ.Integer()),
        _seq_component("ap-options", 2, univ.BitString()),
        _seq_component("ticket", 3, Ticket()),
        _seq_component("authenticator", 4, univ.Sequence()),
    )
