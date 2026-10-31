from functools import wraps

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .avatars import allowed_file, save_avatar
from .weather import fetch_forecast

web = Blueprint("web", __name__)
USERS = {}  # username -> {"password": hash, "notes": [token, ...]}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("web.login"))
        return view(*args, **kwargs)

    return wrapped


@web.route("/")
@login_required
def index():
    record = USERS[session["username"]]
    cipher = current_app.extensions["note_cipher"]
    notes = [cipher.unseal(token) for token in record["notes"]]
    forecast = None
    city = current_app.config.get("HOME_CITY")
    if city:
        try:
            forecast = fetch_forecast(city["lat"], city["lon"])
        except Exception:
            forecast = None  # the widget is optional
    return render_template("index.html", notes=notes, forecast=forecast, username=session["username"])


@web.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or len(password) < 8:
            flash("Pick a username and a password of at least 8 characters.")
        elif username in USERS:
            flash("That username is taken.")
        else:
            USERS[username] = {"password": generate_password_hash(password), "notes": []}
            return redirect(url_for("web.login"))
    return render_template("login.html", action="register")


@web.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        record = USERS.get(username)
        if record and check_password_hash(record["password"], request.form.get("password", "")):
            session.permanent = True
            session["username"] = username
            return redirect(url_for("web.index"))
        flash("Wrong username or password.")
    return render_template("login.html", action="login")


@web.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("web.login"))


@web.route("/notes", methods=["POST"])
@login_required
def add_note():
    text = request.form.get("text", "").strip()
    if text:
        cipher = current_app.extensions["note_cipher"]
        USERS[session["username"]]["notes"].append(cipher.seal(text))
    return redirect(url_for("web.index"))


@web.route("/avatar", methods=["POST"])
@login_required
def upload_avatar():
    upload = request.files.get("avatar")
    if upload is None or not allowed_file(upload.filename):
        flash("Upload a PNG, JPEG, GIF or WebP image.")
    else:
        save_avatar(upload, current_app.config["UPLOAD_DIR"], session["username"])
        flash("Avatar updated.")
    return redirect(url_for("web.index"))
