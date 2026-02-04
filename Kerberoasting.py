#!/usr/bin/env python3
"""
find_kerberoastable.py

Small helper: one function that connects to an Active Directory LDAP server,
looks up one-or-more usernames (from a text file, one username per line) and
returns which accounts have servicePrincipalName values (i.e. are kerberoastable).

Dependencies:
    pip install ldap3

Function:
    find_kerberoastable_users(ldap_server, bind_user, bind_password, usernames_file,
                              base_dn=None, use_ssl=False, port=None, timeout=10)

Returns:
    dict: { 'username1': { 'dn': 'CN=...', 'spns': [...], 'enabled': True }, ... }

Example:
    result = find_kerberoastable_users(
        ldap_server="dc01.example.com",
        bind_user="EXAMPLE\\svc-ldap",
        bind_password="P@ssw0rd",
        usernames_file="targets.txt",
    )
    for user, info in result.items():
        print(user, info)
"""
from typing import Dict, List, Optional
from ldap3 import Server, Connection, ALL, SUBTREE, NTLM
import os


def _is_account_enabled(uac_value: Optional[str]) -> bool:
    """
    Return True if the account is enabled (USER_ACCOUNT_DISABLED bit not set).
    userAccountControl bit 2 (0x2) indicates ACCOUNTDISABLE.
    """
    if uac_value is None:
        return True
    try:
        uac = int(uac_value)
        return (uac & 0x2) == 0
    except Exception:
        return True


def find_kerberoastable_users(
    ldap_server: str,
    bind_user: str,
    bind_password: str,
    usernames_file: str,
    base_dn: Optional[str] = None,
    use_ssl: bool = False,
    port: Optional[int] = None,
    timeout: int = 10,
) -> Dict[str, dict]:
    """
    Connect to LDAP and find kerberoastable accounts for usernames listed in `usernames_file`.

    Parameters
    ----------
    ldap_server : str
        FQDN or IP of LDAP server (e.g. "dc01.example.com"). If you need a URL scheme,
        do NOT include it; pass hostname only.
    bind_user : str
        Bind account. Can be "DOMAIN\\user" or "user@domain".
    bind_password : str
        Password for bind_user.
    usernames_file : str
        Path to a text file containing one username per line (sAMAccountName typically).
    base_dn : Optional[str]
        Optional base DN to search under (e.g. "DC=example,DC=com"). If not provided,
        the function attempts to read defaultNamingContext from rootDSE.
    use_ssl : bool
        If True, connect using LDAPS (port 636 by default).
    port : Optional[int]
        Explicit port. If omitted, defaults to 636 when use_ssl is True, else 389.
    timeout : int
        Socket/connect timeout in seconds.

    Returns
    -------
    Dict[str, dict]
        Map of provided input username -> dict with keys:
            - dn: distinguishedName (or None if not found)
            - spns: list of servicePrincipalName values (empty if none)
            - enabled: bool (True if account not disabled)
            - found: bool (True if directory entry was found)
    """
    if not os.path.isfile(usernames_file):
        raise FileNotFoundError(f"usernames_file not found: {usernames_file}")

    # determine port
    if port is None:
        port = 636 if use_ssl else 389

    server = Server(ldap_server, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=timeout)
    # Choose NTLM auth if DOMAIN\username supplied, otherwise simple bind (assume UPN).
    auth = NTLM if "\\" in bind_user else None

    conn = Connection(server, user=bind_user, password=bind_password, authentication=auth, receive_timeout=timeout)
    if not conn.bind():
        raise ConnectionError(f"LDAP bind failed: {conn.result}")

    # determine base DN from server info if not provided
    if not base_dn:
        try:
            # server.info.other is a dict of lists; defaultNamingContext usually present
            default_ctx = None
            if conn.server and conn.server.info and conn.server.info.other:
                default_ctx = conn.server.info.other.get("defaultNamingContext", None)
                if default_ctx:
                    base_dn = default_ctx[0]
            if not base_dn:
                # fallback: root DSE query
                conn.search(search_base="", search_filter="(objectClass=*)", search_scope="BASE", attributes=["defaultNamingContext"])
                if conn.entries and "defaultNamingContext" in conn.entries[0]:
                    base_dn = str(conn.entries[0]["defaultNamingContext"].value)
        except Exception:
            base_dn = None

    if not base_dn:
        raise ValueError("Could not determine base DN; please pass base_dn explicitly.")

    results = {}
    attributes = ["distinguishedName", "servicePrincipalName", "userAccountControl", "sAMAccountName"]

    # Read usernames
    with open(usernames_file, "r", encoding="utf-8") as fh:
        input_usernames = [line.strip() for line in fh if line.strip()]

    for user in input_usernames:
        # Search for the account by sAMAccountName
        search_filter = f"(&(objectCategory=person)(sAMAccountName={user}))"
        try:
            conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes, size_limit=1)
        except Exception as e:
            results[user] = {"found": False, "dn": None, "spns": [], "enabled": False, "error": str(e)}
            continue

        if not conn.entries:
            results[user] = {"found": False, "dn": None, "spns": [], "enabled": False}
            continue

        entry = conn.entries[0]
        dn = str(entry.distinguishedName.value) if "distinguishedName" in entry else None
        spn_attr = entry.servicePrincipalName.values if "servicePrincipalName" in entry and entry.servicePrincipalName.values is not None else []
        uac_val = entry.userAccountControl.value if "userAccountControl" in entry else None
        enabled = _is_account_enabled(uac_val)

        results[user] = {
            "found": True,
            "dn": dn,
            "spns": list(spn_attr),
            "enabled": enabled,
        }

    conn.unbind()
    return results


if __name__ == "__main__":
    # quick CLI test
    import argparse
    parser = argparse.ArgumentParser(description="Find kerberoastable accounts from a username list.")
    parser.add_argument("ldap_server", help="LDAP host (FQDN or IP)")
    parser.add_argument("bind_user", help="Bind user (DOMAIN\\user or user@domain)")
    parser.add_argument("bind_pass", help="Bind password")
    parser.add_argument("usernames_file", help="Path to file with one username per line")
    parser.add_argument("--base-dn", help="Search base DN (e.g. DC=example,DC=com)", default=None)
    parser.add_argument("--ldaps", action="store_true", help="Use LDAPS (port 636)")
    parser.add_argument("--port", type=int, help="LDAP port (overrides default)", default=None)
    args = parser.parse_args()

    out = find_kerberoastable_users(
        ldap_server=args.ldap_server,
        bind_user=args.bind_user,
        bind_password=args.bind_pass,
        usernames_file=args.usernames_file,
        base_dn=args.base_dn,
        use_ssl=args.ldaps,
        port=args.port,
    )
    for username, info in out.items():
        print(f"{username}: found={info['found']} enabled={info['enabled']} spns={info['spns']} dn={info['dn']}")
