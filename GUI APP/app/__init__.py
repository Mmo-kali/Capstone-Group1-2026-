"""Application factory and initialization."""

from flask import Flask

# Future extension imports go here (e.g., CSRFProtect, LoginManager)
# from flask_wtf import CSRFProtect


def create_app() -> Flask:
    """Create and configure the Flask application.

    Returns:
        Flask: Configured Flask application instance.
    """
    app = Flask(__name__)

    # Configuration placeholders
    app.config["SECRET_KEY"] = "change-me"  # TODO: Replace with secure key

    # Initialize extensions here
    # csrf = CSRFProtect(app)

    # Register blueprints
    from .routes import main_bp

    app.register_blueprint(main_bp)

    # Additional setup logic can be added here

    return app
