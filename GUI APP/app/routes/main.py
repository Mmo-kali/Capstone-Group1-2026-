"""Main routes for the Flask application."""

import re
import subprocess

from flask import render_template, request

from . import main_bp
from ..forms.user_form import UserForm
from ..db.database import (
    fetch_profiles,
    fetch_user_info,
    fetch_vault_users,
    get_active_profile,
    get_profile,
    set_active_profile,
    clear_vault,
    clear_profiles,
    update_user_password,
    upsert_profile,
    upsert_user_info,
)
from ..utils.helpers import process_user_input
from ..utils.userRetrieval import filetime_to_datetime, find_dangerous_groups_from_text
from ..utils.asreproast import check_asreproast, run_asreproast
from ..utils.dcsync import check_dcsync, run_dcsync
from ..utils.kerberoast import (
    HashcatRunnerError,
    crack_hash_value,
    check_kerberoast,
    run_kerberoast,
)

REQUIRED_CRED_KEYS = ("username", "password", "domain", "dc_ip")

DANGEROUS_GROUP_DETAILS = {
    "Domain Admins": {
        "sid_rid": "S-1-5-21-<domain>-512",
        "scope": "Global",
        "tier": "Tier Zero",
        "description": (
            "Administrators with full control over the domain; members are in the "
            "domain's built-in Administrators group and local Administrators on all "
            "domain-joined systems by default."
        ),
        "danger_reason": (
            "Compromise grants full domain control and administrative access on all "
            "domain-joined machines."
        ),
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-au/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory",
            "specterops": "https://bloodhound.specterops.io/get-started/security-boundaries/tier-zero-members",
        },
    },
    "Enterprise Admins": {
        "sid_rid": "S-1-5-21-<root-domain>-519",
        "scope": "Universal",
        "tier": "Tier Zero",
        "description": (
            "Forest-wide administrators; membership grants control across all domains "
            "in the forest and inherits rights through membership in Administrators groups."
        ),
        "danger_reason": "Compromise grants forest-wide administrative control.",
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-au/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory",
            "specterops": "https://bloodhound.specterops.io/get-started/security-boundaries/tier-zero-members",
        },
    },
    "Administrators": {
        "sid_rid": "S-1-5-32-544",
        "scope": "Builtin Local (Domain Local)",
        "tier": "Tier Zero",
        "description": (
            "Built-in Administrators group with direct rights over directory objects "
            "and domain controllers."
        ),
        "danger_reason": "Members have powerful rights in AD and on domain controllers.",
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-au/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory",
            "specterops": "https://bloodhound.specterops.io/get-started/security-boundaries/tier-zero-members",
        },
    },
    "Schema Admins": {
        "sid_rid": "S-1-5-21-<root-domain>-518",
        "scope": "Universal",
        "tier": "Tier Zero",
        "description": "Can modify the AD schema, affecting the entire forest.",
        "danger_reason": (
            "Schema changes can impact all domains and enable persistence or wide-scale "
            "compromise."
        ),
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-au/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory",
            "specterops": "https://bloodhound.specterops.io/get-started/security-boundaries/tier-zero-members",
        },
    },
    "Domain Controllers": {
        "sid_rid": "S-1-5-21-<domain>-516",
        "scope": "Global",
        "tier": "Tier Zero",
        "description": "Group containing all domain controllers in the domain.",
        "danger_reason": "Any compromise of a DC equals domain compromise.",
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups",
            "specterops": "https://bloodhound.specterops.io/get-started/security-boundaries/tier-zero-members",
        },
    },
    "Enterprise Domain Controllers": {
        "sid_rid": "S-1-5-9",
        "scope": "Global",
        "tier": "Tier Zero",
        "description": "Includes all domain controllers in the forest.",
        "danger_reason": (
            "Represents forest-wide DC trust; compromise implies forest-level impact."
        ),
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups",
            "specterops": "https://bloodhound.specterops.io/get-started/security-boundaries/tier-zero-members",
        },
    },
    "Key Admins": {
        "sid_rid": "S-1-5-21-<domain>-526",
        "scope": "Global",
        "tier": "Tier Zero",
        "description": "Can manage key credentials for AD objects in the domain.",
        "danger_reason": (
            "Can enable shadow credentials and take over accounts using key credential "
            "manipulation."
        ),
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups",
            "specterops": "https://bloodhound.specterops.io/get-started/security-boundaries/tier-zero-members",
        },
    },
    "Enterprise Key Admins": {
        "sid_rid": "S-1-5-21-<root-domain>-527",
        "scope": "Universal",
        "tier": "Tier Zero",
        "description": "Can manage key credentials for AD objects across the forest.",
        "danger_reason": (
            "Forest-wide ability to manipulate key credentials can lead to pervasive "
            "compromise."
        ),
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups",
            "specterops": "https://bloodhound.specterops.io/get-started/security-boundaries/tier-zero-members",
        },
    },
    "Account Operators": {
        "sid_rid": "S-1-5-32-548",
        "scope": "Builtin Local (Domain Local)",
        "tier": "Privileged",
        "description": "Can create/modify/delete many user accounts and groups.",
        "danger_reason": (
            "Can manipulate accounts and groups, enabling privilege escalation and "
            "persistence."
        ),
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups",
        },
    },
    "Server Operators": {
        "sid_rid": "S-1-5-32-549",
        "scope": "Builtin Local (Domain Local)",
        "tier": "Privileged",
        "description": (
            "Has elevated rights on domain controllers (service/logon/maintenance tasks)."
        ),
        "danger_reason": "Operator privileges on DCs can be abused to gain higher privileges.",
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups",
        },
    },
    "Backup Operators": {
        "sid_rid": "S-1-5-32-551",
        "scope": "Builtin Local (Domain Local)",
        "tier": "Privileged",
        "description": "Can back up and restore files and directories on domain controllers.",
        "danger_reason": "Backup/restore rights can bypass file ACLs and enable credential theft.",
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups",
        },
    },
    "Print Operators": {
        "sid_rid": "S-1-5-32-550",
        "scope": "Builtin Local (Domain Local)",
        "tier": "Privileged",
        "description": "Can manage printers and print queues on domain controllers.",
        "danger_reason": "Printer management rights can be abused for privilege escalation.",
        "docs": {
            "microsoft": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups",
        },
    },
}


def _get_creds():
    active_profile = get_active_profile()
    if not active_profile:
        return {}
    return get_profile(active_profile) or {}


def _missing_creds(creds):
    return [key for key in REQUIRED_CRED_KEYS if not creds.get(key)]


def _render_exploit(template, creds, results, error, status_message, action):
    return render_template(
        template,
        creds=creds,
        results=results,
        error=error,
        status_message=status_message,
        action=action,
    )


def _parse_bloodyad_output(output):
    if not output:
        return {}

    attr_map = {
        "samaccountname": "sAMAccountName",
        "pwdlastset": "pwdLastSet",
        "description": "description",
    }
    parsed = {}

    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key not in attr_map:
            continue
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            value = value[1:-1].strip()
        value = value.strip().strip("\"").strip("'")
        parsed[attr_map[key]] = value

    return parsed


def _parse_bloodyad_membership_output(output):
    if not output:
        return []

    matches = []
    for line in output.splitlines():
        match = re.search(r"samaccountname\s*[:=]\s*(.+)", line, re.IGNORECASE)
        if not match:
            continue
        value = match.group(1).strip()
        if value.startswith("[") and value.endswith("]"):
            value = value[1:-1].strip()
        value = value.strip().strip("\"").strip("'")
        if value:
            matches.append(value)

    return matches

# Index
@main_bp.route("/", methods=["GET", "POST"])
def index():
    """Render the main form and handle submissions."""
    form = UserForm()
    profiles = fetch_profiles()
    active_profile = get_active_profile()
    status_message = None
    error = None

    form.profile_select.choices = [("", "Select a profile")] + [
        (name, name) for name in sorted(profiles.keys())
    ]

    def apply_profile(profile_name, profile_data):
        set_active_profile(profile_name)
        form.username.data = profile_data.get("username", "")
        form.password.data = profile_data.get("password", "")
        form.domain.data = profile_data.get("domain", "")
        form.dc_ip.data = profile_data.get("dc_ip", "")
        form.dc_fqdn.data = profile_data.get("dc_fqdn", "")
        form.profile_select.data = profile_name

    if request.method == "GET" and active_profile in profiles:
        apply_profile(active_profile, profiles[active_profile])

    if form.validate_on_submit():
        if form.activate_profile.data:
            selected = form.profile_select.data
            if selected and selected in profiles:
                apply_profile(selected, profiles[selected])
                status_message = f"Using profile: {selected}"
            else:
                error = "Please select a saved profile to use."
        elif form.flush_profiles.data:
            clear_profiles()
            profiles = {}
            form.profile_select.choices = [("", "Select a profile")]
            form.profile_select.data = ""
            form.username.data = ""
            form.password.data = ""
            form.domain.data = ""
            form.dc_ip.data = ""
            form.dc_fqdn.data = ""
            form.profile_name.data = ""
            status_message = "All profiles cleared."
        elif form.save_profile.data:
            profile_description = (form.profile_name.data or "").strip()
            username = (form.username.data or "").strip()
            profile_name = username

            if not profile_name:
                error = "Username is required to save a profile."
            else:
                profile_data = {
                    "username": form.username.data or "",
                    "password": form.password.data or "",
                    "domain": form.domain.data or "",
                    "dc_ip": form.dc_ip.data or "",
                    "dc_fqdn": form.dc_fqdn.data or "",
                    "profile_description": profile_description,
                }
                upsert_profile(profile_name, profile_data)
                profiles = fetch_profiles()
                apply_profile(profile_name, profile_data)

                result = process_user_input(
                    username=form.username.data,
                    password=form.password.data,
                    domain=form.domain.data,
                    dc_ip=form.dc_ip.data,
                    dc_fqdn=form.dc_fqdn.data,
                )

                return render_template("output.html", result=result)

    # Additional logic (e.g., analytics, prefill) can be added here
    return render_template(
        "index.html",
        form=form,
        error=error,
        status_message=status_message,
        active_profile=active_profile,
        profiles=profiles,
    )

############################### Exploits ###############################
@main_bp.route("/kerberoast", methods=["GET", "POST"])
def kerberoast():
    """Render the exploitation actions and handle kerberoast execution."""
    creds = _get_creds()
    results = []
    error = None
    status_message = None
    action = None

    if request.method == "POST":
        action = request.form.get("action")
        missing = _missing_creds(creds)
        if missing:
            error = "Please submit credentials and domain settings first."
        else:
            if action == "crack":
                target_user = request.form.get("target_user") or "Unknown"
                status_message = f"Cracking is disabled in this build. ({target_user})"
            elif action == "exploit":
                results = run_kerberoast(
                    creds["domain"],
                    creds["username"],
                    creds["password"],
                    creds["dc_ip"]
                )
            else:
                results = check_kerberoast(
                    creds["domain"],
                    creds["username"],
                    creds["password"],
                    creds["dc_ip"]
                )
            
    return _render_exploit(
        "kerberoast.html",
        creds,
        results,
        error,
        status_message,
        action,
    )


@main_bp.route("/asreproast", methods=["GET", "POST"])
def asreproast():
    """Render the AS-REP Roasting page and handle execution."""
    creds = _get_creds()
    results = []
    error = None
    status_message = None
    action = None

    if request.method == "POST":
        action = request.form.get("action")
        missing = _missing_creds(creds)
        if missing:
            error = "Please submit credentials and domain settings first."
        else:
            if action == "exploit":
                results = run_asreproast(
                    creds["domain"],
                    creds["username"],
                    creds["password"],
                    creds["dc_ip"]
                )
            else:
                results = check_asreproast(
                    creds["domain"],
                    creds["username"],
                    creds["password"],
                    creds["dc_ip"]
                )

    return _render_exploit(
        "asreproast.html",
        creds,
        results,
        error,
        status_message,
        action,
    )

@main_bp.route("/dcsync", methods=["GET", "POST"])
def dcsync():
    creds = _get_creds()
    results = []
    error = None
    status_message = None
    action = None

    if request.method == "POST":
        action = request.form.get("action")

        missing = _missing_creds(creds)

        if missing:
            error = "Please submit credentials and domain settings first."

        else:
            if action == "exploit":
                results = run_dcsync(
                    creds["domain"],
                    creds["username"],
                    creds["password"],
                    creds["dc_ip"]
                )
            else:
                results = check_dcsync(
                    creds["domain"],
                    creds["username"],
                    creds["password"],
                    creds["dc_ip"]
                )
                if results:
                    status_message = "DCSync attack successful."
                elif not error:
                    status_message = "DCSync executed but no Administrator credential found."
            
    return _render_exploit(
        "dcsync.html",
        creds,
        results,
        error,
        status_message,
        action,
    )

# Others
@main_bp.route("/health")
def health():
    """Simple health check endpoint."""
    return {"status": "ok"}


@main_bp.route("/user-info", methods=["GET", "POST"])
def user_info():
    """Display stored user information."""
    creds = _get_creds()
    profiles = fetch_profiles()
    active_profile = get_active_profile()
    status_message = None
    error = None

    loaded_user = creds.get("username") if creds else None

    if request.method == "POST":
        action = request.form.get("action")
        if action == "collect":
            missing = [
                key
                for key in ("username", "domain", "password")
                if not creds.get(key)
            ]
            dc_host = creds.get("dc_fqdn") or creds.get("dc_ip")
            if missing or not dc_host:
                error = "Please submit credentials and domain settings first."
                return render_template(
                    "user_info.html",
                    creds=creds,
                    profiles=profiles,
                    active_profile=active_profile,
                    status_message=status_message,
                    error=error,
                    user_info=None,
                )
            if not loaded_user:
                error = "No active user loaded."
                return render_template(
                    "user_info.html",
                    creds=creds,
                    profiles=profiles,
                    active_profile=active_profile,
                    status_message=status_message,
                    error=error,
                    user_info=None,
                )
            command = [
                "bloodyAD",
                "-H",
                dc_host,
                "-d",
                creds.get("domain", ""),
                "-u",
                creds.get("username", ""),
                "-p",
                creds.get("password", ""),
                "get",
                "object",
                loaded_user or "",
                "--attr",
                "sAMAccountName,pwdLastSet,description",
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode != 0:
                message = result.stderr.strip() or "Unknown error"
                error = f"bloodyAD failed: {message}"
            else:
                raw_output = result.stdout or result.stderr
                parsed = _parse_bloodyad_output(raw_output)
                if not parsed:
                    error = "No user attributes returned from bloodyAD."
                else:
                    membership_command = [
                        "bloodyAD",
                        "-H",
                        dc_host,
                        "-d",
                        creds.get("domain", ""),
                        "-u",
                        creds.get("username", ""),
                        "-p",
                        creds.get("password", ""),
                        "get",
                        "membership",
                        loaded_user or "",
                    ]
                    membership_result = subprocess.run(
                        membership_command,
                        capture_output=True,
                        text=True,
                    )
                    if membership_result.returncode != 0:
                        message = membership_result.stderr.strip() or "Unknown error"
                        error = f"bloodyAD membership failed: {message}"
                    else:
                        membership_output = (
                            membership_result.stdout or membership_result.stderr
                        )
                        group_names = _parse_bloodyad_membership_output(membership_output)
                        groups_text = ", ".join(sorted(set(group_names)))
                        upsert_user_info(
                            parsed.get("sAMAccountName") or loaded_user,
                            parsed.get("pwdLastSet"),
                            parsed.get("description"),
                            groups_text,
                        )
                        status_message = "User information collected."

    user_info = fetch_user_info(loaded_user) if loaded_user else None
    dangerous_groups = []
    dangerous_group_details = {}
    if user_info and user_info.get("groups"):
        dangerous_groups = find_dangerous_groups_from_text(user_info.get("groups"))
        dangerous_group_details = {
            name: DANGEROUS_GROUP_DETAILS.get(name)
            for name in dangerous_groups
            if DANGEROUS_GROUP_DETAILS.get(name)
        }
    if user_info and user_info.get("pwdLastSet"):
        formatted = filetime_to_datetime(user_info.get("pwdLastSet"))
        if formatted:
            user_info["pwdLastSetDisplay"] = formatted
    return render_template(
        "user_info.html",
        creds=creds,
        profiles=profiles,
        active_profile=active_profile,
        status_message=status_message,
        error=error,
        user_info=user_info,
        dangerous_groups=dangerous_groups,
        dangerous_group_details=dangerous_group_details,
    )


@main_bp.route("/vault", methods=["GET", "POST"])
def vault():
    """Display stored hashes and crack status."""
    users = fetch_vault_users()
    selected_username = request.args.get("username")
    if not selected_username and users:
        selected_username = users[0]["username"]
    status_message = None
    error = None
    cracked_lines = []

    if request.method == "POST":
        action = request.form.get("action")
        hash_type = request.form.get("hash_type")
        username = request.form.get("username")
        if username:
            selected_username = username

        if action == "crack":
            if not hash_type or not username:
                error = "Missing hash metadata for cracking request."
            else:
                hash_fields = {
                    "kerberoast": "kerberos_hash",
                    "asrep": "asrep_hash",
                    "dcsync": "ntlm_hash",
                }
                hash_field = hash_fields.get(hash_type)
                target = next((user for user in users if user["username"] == username), None)
                hash_value = target.get(hash_field) if target and hash_field else None

                if not hash_value:
                    error = f"No {hash_type} hash available for {username}."
                else:
                    try:
                        result = crack_hash_value(
                            hash_value,
                            hash_type,
                            timeout_seconds=60,
                        )
                        cracked_lines = result.cracked
                        if cracked_lines:
                            password = None
                            for line in cracked_lines:
                                if ":" not in line:
                                    continue
                                _, password = line.rsplit(":", 1)
                                if password:
                                    break
                            if password:
                                update_user_password(username, password)
                                users = fetch_vault_users()
                            status_message = f"Cracked {len(cracked_lines)} hash(es) for {username}."
                        else:
                            status_message = f"No hashes cracked for {username}."
                    except (HashcatRunnerError, subprocess.TimeoutExpired) as exc:
                        error = f"Cracking failed: {exc}"
        elif action == "flush":
            clear_vault()
            users = []
            status_message = "Password Vault cleared."

    selected_user = next(
        (user for user in users if user["username"] == selected_username),
        None,
    )

    return render_template(
        "vault.html",
        users=users,
        selected_user=selected_user,
        selected_username=selected_username,
        status_message=status_message,
        error=error,
        cracked_lines=cracked_lines,
    )
