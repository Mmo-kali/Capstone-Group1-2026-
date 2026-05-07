#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime, timezone

from ldap3 import Server, Connection, NTLM, SUBTREE
from ldap3.utils.conv import escape_filter_chars


DANGEROUS_GROUP_KEYWORDS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "DnsAdmins",
    "Group Policy Creator Owners",
    "Print Operators",
]


UAC_FLAGS = {
    0x0002: "ACCOUNT_DISABLED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}


def domain_to_dn(domain):
    return ",".join(f"DC={part}" for part in domain.split("."))


def filetime_to_datetime(value):
    try:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        value = int(value)
        if value == 0:
            return "Never"

        unix_time = (value - 116444736000000000) / 10000000
        return datetime.fromtimestamp(unix_time, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


def clean_dn_name(dn):
    try:
        first = dn.split(",")[0]
        return first.replace("CN=", "").replace("OU=", "")
    except Exception:
        return dn


def parse_uac(value):
    try:
        value = int(value)
    except Exception:
        return []

    flags = []

    for bit, name in UAC_FLAGS.items():
        if value & bit:
            flags.append(name)

    return flags


def find_dangerous_groups(groups):
    dangerous = []

    for group_dn in groups:
        group_name = clean_dn_name(group_dn)

        for keyword in DANGEROUS_GROUP_KEYWORDS:
            if keyword.lower() == group_name.lower():
                dangerous.append(group_name)

    return sorted(set(dangerous))


def analyze_privileges(entry):
    findings = []

    username = str(entry.sAMAccountName) if "sAMAccountName" in entry else ""

    groups = []
    if "memberOf" in entry and entry.memberOf:
        groups = [str(g) for g in entry.memberOf.values]

    dangerous_groups = find_dangerous_groups(groups)

    for group in dangerous_groups:
        findings.append(f"High-risk group: {group}")

    admin_count = str(entry.adminCount) if "adminCount" in entry and entry.adminCount else ""

    if admin_count == "1":
        findings.append("adminCount=1 / protected or previously privileged account")

    uac_value = str(entry.userAccountControl) if "userAccountControl" in entry else "0"
    uac_flags = parse_uac(uac_value)

    if "DONT_REQ_PREAUTH" in uac_flags:
        findings.append("AS-REP roastable: Kerberos pre-auth not required")

    if "TRUSTED_FOR_DELEGATION" in uac_flags:
        findings.append("Unconstrained delegation enabled")

    if "TRUSTED_TO_AUTH_FOR_DELEGATION" in uac_flags:
        findings.append("Protocol transition / constrained delegation flag enabled")

    if "DONT_EXPIRE_PASSWORD" in uac_flags:
        findings.append("Password never expires")

    if "PASSWD_NOTREQD" in uac_flags:
        findings.append("Password not required flag set")

    if "ACCOUNT_DISABLED" in uac_flags:
        findings.append("Account disabled")

    if "servicePrincipalName" in entry and entry.servicePrincipalName:
        findings.append("SPN present / kerberoastable account")

    if "msDS-AllowedToDelegateTo" in entry and entry["msDS-AllowedToDelegateTo"]:
        findings.append("Constrained delegation target configured")

    return sorted(set(findings)), uac_flags


def get_user_info(conn, domain_dn, username):
    safe_user = escape_filter_chars(username)

    attributes = [
        "sAMAccountName",
        "displayName",
        "description",
        "pwdLastSet",
        "memberOf",
        "userAccountControl",
        "adminCount",
        "servicePrincipalName",
        "msDS-AllowedToDelegateTo",
        "lastLogonTimestamp",
    ]

    conn.search(
        search_base=domain_dn,
        search_filter=f"(&(objectClass=user)(sAMAccountName={safe_user}))",
        search_scope=SUBTREE,
        attributes=attributes,
    )

    if not conn.entries:
        return None

    return conn.entries[0]


def main():
    parser = argparse.ArgumentParser(description="Audit AD users without BloodHound")
    parser.add_argument("-dc", required=True, help="Domain controller hostname or IP")
    parser.add_argument("-d", required=True, help="Domain name, example: gikyon.local")
    parser.add_argument("-u", required=True, help="LDAP username")
    parser.add_argument("-p", required=True, help="LDAP password")
    parser.add_argument("-users", required=True, help="File with usernames, one per line")
    parser.add_argument("-o", default="user_audit_report.json", help="Output JSON file")

    args = parser.parse_args()

    domain_dn = domain_to_dn(args.d)

    server = Server(args.dc, port=389, use_ssl=False)

    conn = Connection(
        server,
        user=f"{args.d}\\{args.u}",
        password=args.p,
        authentication=NTLM,
        auto_bind=True,
    )

    with open(args.users, "r", encoding="utf-8") as f:
        users = [line.strip() for line in f if line.strip()]

    rows = []

    print("", file=sys.stderr)

    for username in users:
        entry = get_user_info(conn, domain_dn, username)

        if not entry:
            print(f"[-] {username}: NOT FOUND", file=sys.stderr)
            rows.append({
                "Username": username,
                "Display Name": "",
                "Description": "",
                "Password Last Set": "",
                "Last Logon Timestamp": "",
                "Groups": "",
                "UAC Flags": "",
                "Special / Dangerous Privileges": "USER NOT FOUND",
            })
            continue

        groups = []
        if "memberOf" in entry and entry.memberOf:
            groups = [clean_dn_name(g) for g in entry.memberOf.values]

        findings, uac_flags = analyze_privileges(entry)

        pwd_last_set = ""
        if "pwdLastSet" in entry and entry.pwdLastSet:
            pwd_last_set = filetime_to_datetime(entry.pwdLastSet.value)
            if not pwd_last_set and entry.pwdLastSet.raw_values:
                raw_value = entry.pwdLastSet.raw_values[0]
                raw_text = raw_value.decode("utf-8", errors="ignore") if isinstance(raw_value, bytes) else raw_value
                pwd_last_set = filetime_to_datetime(raw_text)

        last_logon = ""
        if "lastLogonTimestamp" in entry and entry.lastLogonTimestamp:
            last_logon = filetime_to_datetime(entry.lastLogonTimestamp.value)

        description = ""
        if "description" in entry and entry.description:
            description = str(entry.description)

        display_name = ""
        if "displayName" in entry and entry.displayName:
            display_name = str(entry.displayName)

        rows.append({
            "Username": username,
            "Display Name": display_name,
            "Description": description,
            "Password Last Set": pwd_last_set,
            "Last Logon Timestamp": last_logon,
            "Groups": "; ".join(groups),
            "UAC Flags": "; ".join(uac_flags),
            "Special / Dangerous Privileges": "; ".join(findings) if findings else "None detected",
        })

    with open(args.o, "w", encoding="utf-8") as jsonfile:
        json.dump(rows, jsonfile, indent=2)

    json.dump(rows, sys.stdout, indent=2)
    sys.stdout.write("\n")

if __name__ == "__main__":
    main()