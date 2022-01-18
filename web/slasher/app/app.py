import os
from flask import Flask, flash, request, redirect, render_template, send_file, session
from werkzeug.exceptions import RequestEntityTooLarge
from db import UserService, FileService
from dotenv import load_dotenv
from functools import wraps
import base64
import bcrypt

load_dotenv()

app = Flask(__name__)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")
MAX_CONTENT_LENGTH_KB = int(os.getenv("MAX_CONTENT_LENGTH_KB"))

app.secret_key = os.getenv("SECRET_KEY")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH_KB * 1024
app.config["DEBUG"] = os.getenv("FLASK_ENV") == "development"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Helpers

def hashpw(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def checkpw(password, hashed):
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except:
        return False

def login_user(username):
    user = UserService.get_by_name(username)
    if user:
        session["uid"] = user["id"]

def logout_user():
    session.pop("uid", None)

def logged_in():
    uid = session.get("uid")
    user = UserService.get(uid)
    return user is not None

# Decorators

def login_required(route):
    @wraps(route)
    def ret():
        if logged_in():
            return route()
        else:
            return redirect("/login")

    return ret

def logout_required(route):
    @wraps(route)
    def ret():
        if logged_in():
            return redirect("/")
        else:
            return route()

    return ret

# Routes

@app.route("/login", methods=["GET", "POST"])
@logout_required
def login():
    if request.method == "GET":
        return render_template("login.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        user = UserService.get_by_name(username)
        if user and password and checkpw(password, user["password"]):
            login_user(username)
            return redirect("/")
        else:
            flash("Username and password don't match", "danger")
            return render_template("login.html"), 401

@app.route("/register", methods=["GET", "POST"])
@logout_required
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Username or password not specified", "danger")
            return render_template("register.html")
        elif UserService.add(username, hashpw(password).decode()):
            login_user(username)
            return redirect("/")
        else:
            flash("Username already taken", "danger")
            return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect("/login")

@app.route("/")
@login_required
def index():
    enc_filename = request.args.get("filename")
    if enc_filename:
        file = FileService.get(session["uid"], enc_filename)
        if file:
            path = os.path.join(APP_ROOT, UPLOAD_FOLDER, enc_filename)
            return send_file(path)
        else:
            flash("File not found", "danger")
            return redirect("/")
    else:
        files = FileService.get_by_uid(session["uid"])
        return render_template("index.html", files=files)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    success = False
    filename = request.form.get("filename")
    if not filename or "file" not in request.files or not request.files["file"].filename:
        flash("No file or filename specified", "danger")
    else:
        flash(f"Filename: {filename}", "info")
        file = request.files["file"]
        try:
            enc_filename = base64.b64encode(filename.encode("latin-1")).decode()
            if FileService.add(session["uid"], filename, enc_filename):
                path = os.path.join(APP_ROOT, UPLOAD_FOLDER, enc_filename)
                file.save(path)
                success = True
            else:
                flash("File already exists", "danger")
        except UnicodeEncodeError as e:
            flash(f"Error: {str(e)}", 'danger')

    return render_template("upload.html", success=success)

# Error handling

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500

@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def file_size_limit(e):
    return render_template("413.html", limit=MAX_CONTENT_LENGTH_KB), 413
