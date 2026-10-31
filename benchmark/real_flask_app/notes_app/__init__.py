import os

from flask import Flask

from .crypto import NoteCipher
from .export import export_notes
from .settings import read_settings
from .views import USERS, web


def create_app(config_path=None):
    app = Flask(__name__)
    settings = read_settings(config_path or os.environ.get("NOTES_CONFIG", "config.yaml"))
    app.config.update(
        SECRET_KEY=settings["secret_key"],
        UPLOAD_DIR=settings["upload_dir"],
        HOME_CITY=settings.get("home_city"),
        MAX_CONTENT_LENGTH=4 * 1024 * 1024,
    )
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)
    app.extensions["note_cipher"] = NoteCipher(settings["notes_key"].encode("ascii"))
    app.register_blueprint(web)

    @app.cli.command("export-notes")
    def export_command():
        path = export_notes(USERS, settings["export_path"])
        print(f"exported note counts to {path}")

    return app
