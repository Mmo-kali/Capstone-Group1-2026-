"""Application entry point."""

from app import create_app

# Create app instance
app = create_app()

# Additional startup logic can be added here

if __name__ == "__main__":
    app.run(debug=True)
