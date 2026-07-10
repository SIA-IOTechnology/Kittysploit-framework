#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive S7comm / ISO-on-TCP header detection."""

from __future__ import annotations

from lib.protocols.ics.constants import S7_DANGEROUS_JOBS


def parse_s7comm(payload: bytes) -> dict | None:
    """
    Best-effort S7comm detection from a TCP payload on port 102.

    Validates TPKT (RFC 1006) framing before reading COTP/S7 fields.
    """
    if len(payload) < 17:
        return None

    if payload[0] != 0x03:  # TPKT version
        return None

    tpkt_len = int.from_bytes(payload[2:4], "big")
    if tpkt_len < 7 or tpkt_len > len(payload):
        return None

    cotp_len = payload[4]
    if cotp_len < 2 or 4 + cotp_len > len(payload):
        return None

    cotp_pdu_type = payload[5]
    if cotp_pdu_type not in (0xE0, 0xD0, 0xF0):
        return None

    # ISO-on-TCP data transfer: COTP 0x02 0xF0, then S7 header 0x32
    s7_offset = 4 + cotp_len
    if s7_offset >= len(payload) or payload[s7_offset] != 0x32:
        return None

    rosctr = payload[s7_offset + 1] if s7_offset + 1 < len(payload) else None
    job_type = None
    is_program_transfer = False

    if rosctr == 0x01 and s7_offset + 17 < len(payload):
        job_type = payload[s7_offset + 17]
        is_program_transfer = job_type in S7_DANGEROUS_JOBS

    return {
        "protocol": "s7comm",
        "tpkt_length": tpkt_len,
        "cotp_pdu_type": cotp_pdu_type,
        "rosctr": rosctr,
        "job_type": job_type,
        "is_program_transfer": is_program_transfer,
    }
