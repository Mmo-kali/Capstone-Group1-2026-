"""Main routes for the Flask application."""

from flask import render_template, request, session

from . import main_bp
from ..forms.user_form import UserForm
from ..utils.helpers import process_user_input
from ..utils.kerberoast import run_kerberoast, check_kerberoast
from ..utils.asreproast import run_asreproast
from ..utils.dcsync import run_dcsync

# Index
@main_bp.route("/", methods=["GET", "POST"])
def index():
    """Render the main form and handle submissions."""
    form = UserForm()

    if form.validate_on_submit():
        # Process the submitted form data
        result = process_user_input(
            username=form.username.data,
            password=form.password.data,
            domain=form.domain.data,
            dc_ip=form.dc_ip.data,
            dc_fqdn=form.dc_fqdn.data,
        )

        session["creds"] = {
            "username": form.username.data or "",
            "password": form.password.data or "",
            "domain": form.domain.data or "",
            "dc_ip": form.dc_ip.data or "",
            "dc_fqdn": form.dc_fqdn.data or "",
        }

        # Render the output page with processed result
        return render_template("output.html", result=result)

    # Additional logic (e.g., analytics, prefill) can be added here
    return render_template("index.html", form=form)

# Exploits
@main_bp.route("/kerberoast", methods=["GET", "POST"])
def kerberoast():
    """Render the exploitation actions and handle kerberoast execution."""
    creds = session.get("creds") or {}
    results = []
    error = None
    status_message = None
    action = None

    if request.method == "POST":
        action = request.form.get("action")
        missing = [
            key
            for key in ("username", "password", "domain", "dc_ip")
            if not creds.get(key)
        ]
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
            
    return render_template(
        "kerberoast.html",
        creds=creds,
        results=results,
        error=error,
        status_message=status_message,
        action=action,
    )


@main_bp.route("/asreproast", methods=["GET", "POST"])
def asreproast():
    """Render the AS-REP Roasting page and handle execution."""
    creds = session.get("creds") or {}
    results = []
    error = None
    status_message = None
    action = None

    if request.method == "POST":
        action = request.form.get("action")
        missing = [
            key
            for key in ("username", "password", "domain", "dc_ip")
            if not creds.get(key)
        ]
        if missing:
            error = "Please submit credentials and domain settings first."
        else:
            request_hash = action == "exploit"
            results, error = run_asreproast(
                domain=creds["domain"],
                username=creds["username"],
                password=creds["password"],
                dc_ip=creds["dc_ip"],
                request_hash=request_hash,
            )
            if not results and not error:
                status_message = "No AS-REP Roastable accounts found."

    return render_template(
        "asreproast.html",
        creds=creds,
        results=results,
        error=error,
        status_message=status_message,
        action=action,
    )

@main_bp.route("/dcsync", methods=["GET", "POST"])
def dcsync():
    creds = session.get("creds") or {}
    results = []
    error = None
    status_message = None
    action = None

    if request.method == "POST":
        action = request.form.get("action")

        missing = [
            key
            for key in ("username", "password", "domain", "dc_ip")
            if not creds.get(key)
        ]

        if missing:
            error = "Please submit credentials and domain settings first."

        else:
            
            # do exploit
            if action == "exploit":
                results = run_dcsync(
                    creds["domain"],
                    creds["username"],
                    creds["password"],
                    creds["dc_ip"]
                )

                if results:
                    status_message = "DCSync attack successful."
                elif not error:
                    status_message = "DCSync executed but no Administrator credential found."
            
    return render_template(
        "dcsync.html",
        creds=creds,
        results=results,
        error=error,
        status_message=status_message,
        action=action,
    )

# Others
@main_bp.route("/health")
def health():
    """Simple health check endpoint."""
    return {"status": "ok"}


@main_bp.route("/user-info")
def user_info():
    """Display stored user information."""
    creds = session.get("creds") or {}
    return render_template("user_info.html", creds=creds)
