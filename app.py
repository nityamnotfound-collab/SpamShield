import os
import json

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request


# Load environment configuration before importing modules that read it.
load_dotenv()

from utils.database import (
    DatabaseError,
    clear_history,
    delete_scan,
    get_dashboard_stats,
    get_history,
    get_scan_by_id,
    init_db,
    save_scan,
)
from utils.message_detector import analyze_message
from utils.url_detector import analyze_url


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

GENERIC_ERROR = "Something went wrong. Please try again."


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
def message_scanner():
    return render_template("message_scanner.html")


@app.route("/url-scanner")
def url_scanner():
    return render_template("url_scanner.html")


@app.route("/history")
def history_page():
    return render_template("history.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/model-performance")
def model_performance():
    metrics_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "models",
        "metrics.json",
    )
    try:
        with open(metrics_path, "r", encoding="utf-8") as metrics_file:
            metrics = json.load(metrics_file)
        required_metrics = (
            "accuracy",
            "precision",
            "recall",
            "f1",
            "confusion_matrix",
            "dataset_size",
            "training_date",
        )
        if not isinstance(metrics, dict) or any(
            metric_name not in metrics for metric_name in required_metrics
        ):
            metrics = None
    except FileNotFoundError:
        metrics = None
    except (OSError, json.JSONDecodeError):
        app.logger.exception("Model metrics could not be loaded")
        metrics = None
    return render_template("model_performance.html", metrics=metrics)


@app.route("/dashboard")
def dashboard():
    try:
        stats = get_dashboard_stats()
        stats["last_five"] = [
            stringify_scan_id(scan) for scan in stats["last_five"]
        ]
        return render_template("dashboard.html", stats=stats)
    except DatabaseError as error:
        return json_database_error(error)


@app.route("/api/analyze-message", methods=["POST"])
@app.route("/api/analyze/message", methods=["POST"])
def analyze_message_route():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Please send a valid JSON request."}), 400

    message = data.get("message")
    if not isinstance(message, str) or not message.strip():
        return jsonify({"error": "Enter a message to analyze."}), 400
    if len(message) > 5000:
        return jsonify({"error": "Messages can contain up to 5000 characters."}), 400
    source = data.get("source", "Other")
    if source not in ("SMS", "WhatsApp", "Email", "Telegram", "Instagram", "Other"):
        return jsonify({"error": "Choose a valid message source."}), 400

    try:
        result = analyze_message(message)
        prediction = result["classification"].upper()
        scan_id = save_scan(
            "message",
            message,
            source,
            prediction,
            result["confidence"],
            result["explanation"],
            result["suspicious_keywords"],
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
def analyze_url_route():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Please send a valid JSON request."}), 400

    url = data.get("url")
    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "Enter a URL to analyze."}), 400
    if len(url) > 2000:
        return jsonify({"error": "URLs can contain up to 2000 characters."}), 400

    try:
        result = analyze_url(url)
    except ValueError:
        return jsonify({"error": "Enter a valid URL to analyze."}), 400
    except Exception:
        app.logger.exception("URL analysis failed")
        return jsonify({"error": GENERIC_ERROR}), 500

    try:
        prediction = result["classification"].upper()
        scan_id = save_scan(
            "url",
            url,
            "manual",
            prediction,
            result["risk_score"],
            result["reasons"],
            result["reasons"],
        )
        result["id"] = str(scan_id)
        return jsonify(result)
    except DatabaseError as error:
        return json_database_error(error)
    except Exception:
        app.logger.exception("URL analysis failed")
        return jsonify({"error": GENERIC_ERROR}), 500


@app.route("/api/history", methods=["GET", "DELETE"])
def history_list():
    try:
        if request.method == "DELETE":
            clear_history()
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
def history_item(scan_id):
    try:
        if request.method == "DELETE":
            deleted = delete_scan(scan_id)
            if not deleted:
                return jsonify({"error": "Scan not found."}), 404
            return jsonify({"success": True})

        scan = get_scan_by_id(scan_id)
        if scan is None:
            return jsonify({"error": "Scan not found."}), 404
        return jsonify(stringify_scan_id(scan))
    except DatabaseError as error:
        return json_database_error(error)
    except Exception:
        app.logger.exception("History item request failed")
        return jsonify({"error": GENERIC_ERROR}), 500


@app.route("/api/report/<scan_id>", methods=["GET"])
def report(scan_id):
    try:
        scan = get_scan_by_id(scan_id)
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
def dashboard_stats():
    try:
        stats = get_dashboard_stats()
        stats["last_five"] = [
            stringify_scan_id(scan) for scan in stats["last_five"]
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
