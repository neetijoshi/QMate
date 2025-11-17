# app/routes.py

from flask import Blueprint, render_template, request, redirect, url_for, session
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash

main = Blueprint("main", __name__)


# ---------------------- INDEX ---------------------- #
@main.route("/")
def index():
    return render_template("login_register.html", show_register=False)


# ---------------------- REGISTER ---------------------- #
@main.route("/register", methods=["POST"])
def register():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")

    # Validation
    if not name or not email or not password or not confirm:
        return render_template(
            "login_register.html",
            error="All fields are required!",
            show_register=True,
            name=name,
            email=email
        )

    if password != confirm:
        return render_template(
            "login_register.html",
            error="Passwords do not match!",
            show_register=True,
            name=name,
            email=email
        )

    existing = User.query.filter_by(email=email).first()
    if existing:
        return render_template(
            "login_register.html",
            error="Email already exists!",
            show_register=True,
            name=name,
            email=email
        )

    # Create new user
    hashed_pw = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
    new_user = User(name=name, email=email, password=hashed_pw)

    db.session.add(new_user)
    db.session.commit()

    # Return to login form with success message
    return render_template(
        "login_register.html",
        success="Account created! Please login.",
        show_register=False
    )


# ---------------------- LOGIN ---------------------- #
@main.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        return render_template(
            "login_register.html",
            error="All fields are required!",
            show_register=False,
            email=email
        )

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return render_template(
            "login_register.html",
            error="Invalid email or password!",
            show_register=False,
            email=email
        )

    # Login OK
    session["user_id"] = user.id
    session["role"] = user.role
    session["user_name"] = user.name

    if user.role == "admin":
        return redirect(url_for("main.admin_dashboard"))

    return redirect(url_for("main.user_dashboard"))


# ---------------------- USER DASHBOARD ---------------------- #
@main.route("/user_dashboard")
def user_dashboard():
    if session.get("user_id") is None:
        # No login => enter as guest
        return redirect(url_for("main.guest_dashboard"))
    return render_template("user_dashboard.html", guest=False)


# ---------------------- ADMIN DASHBOARD ---------------------- #
@main.route("/admin_dashboard")
def admin_dashboard():
    if session.get("user_id") is None or session.get("role") != "admin":
        return redirect(url_for("main.index"))
    return render_template("admin_dashboard.html")


# ---------------------- LOGOUT ---------------------- #
@main.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.index"))


# ---------------------- GUEST ---------------------- #
@main.route("/guest_dashboard")
def guest_dashboard():
    # Guests have no session
    return render_template("user_dashboard.html", guest=True)


# ---------------------- TOKEN (Restricted) ---------------------- #
@main.route("/get_token")
def get_token():
    if session.get("user_id") is None:
        return render_template(
            "login_register.html",
            error="Please log in to get tokens.",
            show_register=False
        )

    return "<h2>Your Token Page (You are logged in)</h2>"
