"""WTForms definitions for user input."""

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import Optional


class UserForm(FlaskForm):
    """Primary form for collecting user information."""

    username = StringField(
        "Username",
        validators=[Optional()],
        render_kw={"placeholder": "Enter username"},
    )
    password = PasswordField(
        "Password",
        validators=[Optional()],
        render_kw={"placeholder": "Enter password"},
    )
    domain = StringField(
        "Domain",
        validators=[Optional()],
        render_kw={"placeholder": "example.com"},
    )
    dc_ip = StringField(
        "DC IP",
        validators=[Optional()],
        render_kw={"placeholder": "192.168.1.10"},
    )
    dc_fqdn = StringField(
        "DC FQDN",
        validators=[Optional()],
        render_kw={"placeholder": "dc01.example.com"},
    )
    submit = SubmitField("Submit")

    # Additional fields and validation logic can be added here
