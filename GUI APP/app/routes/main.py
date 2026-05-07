"""Main routes for the Flask application."""

from flask import render_template, request, session

from . import main_bp
from ..forms.user_form import UserForm
from ..utils.helpers import process_user_input
from ..utils.asreproast import check_asreproast, run_asreproast
from ..utils.dcsync import check_dcsync, run_dcsync
from ..utils.kerberoast import check_kerberoast, run_kerberoast

REQUIRED_CRED_KEYS = ("username", "password", "domain", "dc_ip")


def _get_creds():
    return session.get("creds") or {}


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

# Index
@main_bp.route("/", methods=["GET", "POST"])
def index():
    """Render the main form and handle submissions."""
    form = UserForm()
    profiles = session.get("profiles") or {}
    active_profile = session.get("active_profile")
    status_message = None
    error = None

    form.profile_select.choices = [("", "Select a profile")] + [
        (name, name) for name in sorted(profiles.keys())
    ]

    def apply_profile(profile_name, profile_data):
        session["active_profile"] = profile_name
        session["creds"] = profile_data
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
        elif form.save_profile.data:
            profile_name = (form.profile_name.data or "").strip()
            if not profile_name:
                username = (form.username.data or "").strip()
                domain = (form.domain.data or "").strip()
                if username and domain:
                    profile_name = f"{username}@{domain}"
                else:
                    profile_name = username

            if not profile_name:
                error = "Profile name is required to save."
            else:
                profile_data = {
                    "username": form.username.data or "",
                    "password": form.password.data or "",
                    "domain": form.domain.data or "",
                    "dc_ip": form.dc_ip.data or "",
                    "dc_fqdn": form.dc_fqdn.data or "",
                }
                profiles[profile_name] = profile_data
                session["profiles"] = profiles
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

# Exploits
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
            if action == "exploit":
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


@main_bp.route("/user-info")
def user_info():
    """Display stored user information."""
    creds = _get_creds()
    profiles = session.get("profiles") or {}
    active_profile = session.get("active_profile")
    return render_template(
        "user_info.html",
        creds=creds,
        profiles=profiles,
        active_profile=active_profile,
    )
