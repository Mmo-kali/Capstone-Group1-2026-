"""Routes package for the application."""

from flask import Blueprint

# Blueprint configuration
main_bp = Blueprint("main", __name__)

# Import routes to register them with the blueprint
from . import main  # noqa: E402,F401
