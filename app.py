import os
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


# Load environment configuration before importing modules that read it.
load_dotenv()

from utils.database import (
    DatabaseError,
    UserAlreadyExistsError,
    clear_history,
    create_user,
    delete_scan,
    get_dashboard_stats,
    get_history,
    get_scan_by_id,
    get_user_by_email,
    get_user_by_id,
    init_db,
    record_failed_login,
    reset_failed_logins,
    save_scan,
)
from utils.message_detector import analyze_message, detect_language
from utils.url_detector import analyze_url


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = any(
    os.getenv(setting, "").lower() in ("1", "true", "yes", "production")
    for setting in ("FLASK_ENV", "ENVIRONMENT", "VERCEL", "RENDER")
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

GENERIC_ERROR = "Something went wrong. Please try again."
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)
COMMON_PASSWORDS = {"password", "12345678", "qwerty123"}


def login_required(view):
    """Require an authenticated user, returning JSON errors for API requests."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def password_strength(password, email):
    """Return Weak for invalid passwords, otherwise rate by password length."""
    if not isinstance(password, str):
        return "Weak"
    email_name = email.split("@", 1)[0].casefold() if "@" in email else ""
    valid = (
        len(password) >= 8
        and any(character.isupper() for character in password)
        and any(character.islower() for character in password)
        and any(character in "0123456789" for character in password)
        and any(
            not character.isalnum() and not character.isspace()
            for character in password
        )
        and password.casefold() not in COMMON_PASSWORDS
        and not (email_name and email_name in password.casefold())
    )
    if not valid:
        return "Weak"
    if len(password) >= 16:
        return "Strong"
    if len(password) >= 12:
        return "Good"
    return "Fair"


def _auth_data():
    if request.is_json:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}
    return request.form


def _request_language(data):
    language = data.get("lang") if isinstance(data, dict) else None
    return language if language in ("en", "hi") else "en"


def _wants_json():
    return request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest"


def _auth_failure(message, template, **context):
    if _wants_json():
        return jsonify({"error": message, **context}), 400
    return render_template(template, error=message, **context), 400


def _login_session(user, remember_me):
    session.clear()
    session["user_id"] = str(user["id"])
    session["user_name"] = user["name"]
    session.permanent = remember_me


def _now_utc():
    return datetime.now(timezone.utc)


def _is_locked(user):
    locked_until = user.get("locked_until")
    if not locked_until:
        return False
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > _now_utc()


def stringify_scan_id(record):
    """Keep scan IDs JSON-compatible and consistent across database backends."""
    formatted_record = dict(record)
    if "id" in formatted_record and formatted_record["id"] is not None:
        formatted_record["id"] = str(formatted_record["id"])
    return formatted_record


def json_database_error(error):
    """Log the internal database failure and return a generic API response."""
    app.logger.error("Database request failed: %s", error)
    return jsonify({"error": GENERIC_ERROR}), 500


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/message-scanner")
@login_required
def message_scanner():
    return render_template("message_scanner.html")


@app.route("/url-scanner")
@app.route("/urlscanner")
@login_required
def url_scanner():
    return render_template("url_scanner.html")


@app.route("/history")
@login_required
def history_page():
    return render_template("history.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/scam-awareness")
def scam_awareness():
    return render_template("scam_awareness.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "GET":
        return render_template(
            "register.html", error=None, password_strength="Weak"
        )

    data = _auth_data()
    name_value = data.get("name", "")
    email_value = data.get("email", "")
    name = name_value.strip() if isinstance(name_value, str) else ""
    email = email_value.strip().lower() if isinstance(email_value, str) else ""
    password = data.get("password", "")
    confirm_password = data.get("confirm_password", "")
    strength = password_strength(password, email)
    context = {
        "name": name,
        "email": email,
        "password_strength": strength,
    }

    if not 2 <= len(name) <= 50:
        return _auth_failure("Name must be between 2 and 50 characters.", "register.html", **context)
    if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
        return _auth_failure("Enter a valid email address.", "register.html", **context)
    if strength == "Weak":
        return _auth_failure(
            "Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character. It cannot be common or contain your email name.",
            "register.html",
            **context,
        )
    if password != confirm_password:
        return _auth_failure("Passwords do not match.", "register.html", **context)

    try:
        create_user(name, email, generate_password_hash(password))
        if _wants_json():
            return jsonify({"success": True, "password_strength": strength}), 201
        return redirect(url_for("login"))
    except UserAlreadyExistsError:
        return _auth_failure(
            "An account with this email already exists. Please log in.",
            "register.html",
            **context,
        )
    except DatabaseError as error:
        return json_database_error(error)


def _remember_me(data):
    value = data.get("remember_me", False)
    return value is True or str(value).lower() in ("1", "true", "on", "yes")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "GET":
        return render_template("login.html", error=None, email="")

    data = _auth_data()
    email_value = data.get("email", "")
    email = email_value.strip().lower() if isinstance(email_value, str) else ""
    password = data.get("password", "")
    try:
        user = get_user_by_email(email) if EMAIL_PATTERN.fullmatch(email) else None
        if not user:
            return _auth_failure(
                "Incorrect email or password", "login.html", email=email
            )
        if _is_locked(user):
            return _auth_failure(
                "Incorrect email or password",
                "login.html",
                email=email,
                account_locked=True,
                lock_message="Too many failed attempts. Try again in five minutes.",
            )
        if not isinstance(password, str) or not check_password_hash(
            user["password_hash"], password
        ):
            account_locked = record_failed_login(user["id"]) >= 5
            return _auth_failure(
                "Incorrect email or password",
                "login.html",
                email=email,
                account_locked=account_locked,
                lock_message=(
                    "Too many failed attempts. Try again in five minutes."
                    if account_locked
                    else ""
                ),
            )
        reset_failed_logins(user["id"])
        _login_session(user, _remember_me(data))
        if _wants_json():
            return jsonify({"success": True})
        return redirect(url_for("dashboard"))
    except DatabaseError as error:
        return json_database_error(error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/api/me")
@login_required
def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Authentication required."}), 401
    try:
        user = get_user_by_id(user_id)
        if user is None:
            session.clear()
            return jsonify({"error": "Authentication required."}), 401
        return jsonify({"id": str(user["id"]), "name": user["name"], "email": user["email"]})
    except DatabaseError as error:
        return json_database_error(error)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user_name=session.get("user_name", "User"))


@app.route("/api/analyze-message", methods=["POST"])
@app.route("/api/analyze/message", methods=["POST"])
@login_required
def analyze_message_route():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Please send a valid JSON request."}), 400
    language = _request_language(data)

    message = data.get("message")
    if not isinstance(message, str) or not message.strip():
        return jsonify({"error": "Enter a message to analyze."}), 400
    if len(message) > 5000:
        return jsonify({"error": "Messages can contain up to 5000 characters."}), 400
    source = data.get("source", "Other")
    if source not in ("SMS", "WhatsApp", "Email", "Telegram", "Instagram", "Other"):
        return jsonify({"error": "Choose a valid message source."}), 400

    try:
        result = analyze_message(message, lang=language)
        prediction = result["classification"].upper()
        scan_id = save_scan(
            session["user_id"],
            "message",
            message,
            source,
            prediction,
            result["confidence"],
            result["explanation"],
            result["suspicious_keywords"],
            categories=result["categories"],
            keywords=result["suspicious_keywords"],
            language=result["language"],
        )
        result["id"] = str(scan_id)
        return jsonify(result)
    except DatabaseError as error:
        return json_database_error(error)
    except Exception:
        app.logger.exception("Message analysis failed")
        return jsonify({"error": GENERIC_ERROR}), 500


@app.route("/api/analyze-url", methods=["POST"])
@app.route("/api/analyze/url", methods=["POST"])
@login_required
def analyze_url_route():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Please send a valid JSON request."}), 400
    language = _request_language(data)

    url = data.get("url")
    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "Enter a URL to analyze."}), 400
    if len(url) > 2000:
        return jsonify({"error": "URLs can contain up to 2000 characters."}), 400

    try:
        result = analyze_url(url, lang=language)
    except ValueError:
        return jsonify({"error": "Enter a valid URL to analyze."}), 400
    except Exception:
        app.logger.exception("URL analysis failed")
        return jsonify({"error": GENERIC_ERROR}), 500

    try:
        prediction = result["classification"].upper()
        scan_language = detect_language(url)
        scan_id = save_scan(
            session["user_id"],
            "url",
            url,
            "manual",
            prediction,
            result["risk_score"],
            result["reasons"],
            result["reasons"],
            categories=["phishing"] if prediction != "SAFE" else [],
            keywords=result["suspicious_keywords"],
            language=scan_language,
        )
        result["id"] = str(scan_id)
        result["language"] = scan_language
        return jsonify(result)
    except DatabaseError as error:
        return json_database_error(error)
    except Exception:
        app.logger.exception("URL analysis failed")
        return jsonify({"error": GENERIC_ERROR}), 500


@app.route("/api/history", methods=["GET", "DELETE"])
@login_required
def history_list():
    try:
        if request.method == "DELETE":
            clear_history(session["user_id"])
            return jsonify({"success": True})

        scan_type = request.args.get("scan_type")
        prediction = request.args.get("prediction")
        if scan_type not in (None, "", "message", "url"):
            return jsonify({"error": "Choose a valid scan type filter."}), 400
        if prediction:
            prediction = prediction.upper()
            if prediction not in ("SAFE", "SPAM", "SUSPICIOUS", "HIGH RISK"):
                return jsonify({"error": "Choose a valid classification filter."}), 400

        history = get_history(
            session["user_id"],
            search=request.args.get("search"),
            scan_type=scan_type,
            prediction=prediction,
        )
        return jsonify({"history": [stringify_scan_id(scan) for scan in history]})
    except DatabaseError as error:
        return json_database_error(error)
    except Exception:
        app.logger.exception("History request failed")
        return jsonify({"error": GENERIC_ERROR}), 500


@app.route("/api/history/<scan_id>", methods=["GET", "DELETE"])
@login_required
def history_item(scan_id):
    try:
        if request.method == "DELETE":
            deleted = delete_scan(session["user_id"], scan_id)
            if not deleted:
                return jsonify({"error": "Scan not found."}), 404
            return jsonify({"success": True})

        scan = get_scan_by_id(session["user_id"], scan_id)
        if scan is None:
            return jsonify({"error": "Scan not found."}), 404
        return jsonify(stringify_scan_id(scan))
    except DatabaseError as error:
        return json_database_error(error)
    except Exception:
        app.logger.exception("History item request failed")
        return jsonify({"error": GENERIC_ERROR}), 500


@app.route("/api/report/<scan_id>", methods=["GET"])
@login_required
def report(scan_id):
    try:
        scan = get_scan_by_id(session["user_id"], scan_id)
        if scan is None:
            return jsonify({"error": "Scan not found."}), 404
        return jsonify({"report": stringify_scan_id(scan)})
    except DatabaseError as error:
        return json_database_error(error)
    except Exception:
        app.logger.exception("Report request failed")
        return jsonify({"error": GENERIC_ERROR}), 500


@app.route("/api/dashboard", methods=["GET"])
@app.route("/api/dashboard-stats", methods=["GET"])
@login_required
def dashboard_stats():
    try:
        range_name = request.args.get("range", "7d")
        if range_name not in ("7d", "30d", "all"):
            return jsonify({"error": "Choose a valid dashboard range."}), 400
        stats = get_dashboard_stats(session["user_id"], range_name)
        stats["recent_scans"] = [
            stringify_scan_id(scan) for scan in stats["recent_scans"]
        ]
        return jsonify(stats)
    except DatabaseError as error:
        return json_database_error(error)
    except Exception:
        app.logger.exception("Dashboard stats request failed")
        return jsonify({"error": GENERIC_ERROR}), 500


if __name__ == "__main__":
    try:
        init_db()
    except DatabaseError:
        app.logger.exception("Database initialization failed")
    app.run(debug=False)
