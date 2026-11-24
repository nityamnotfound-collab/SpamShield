import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from bson.errors import InvalidId
from bson.objectid import ObjectId
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

from utils.scam_categories import SCAM_CATEGORIES


# Load local configuration before checking which database to use.
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "spamshield")
USE_MONGODB = bool(MONGODB_URI)
logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Raised when a database operation fails."""


class UserAlreadyExistsError(Exception):
    """Raised when an account email is already registered."""


if USE_MONGODB:
    # Create one client for this module; MongoDB performs connection checks on use.
    mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    mongo_database = mongo_client[MONGODB_DB_NAME]
    scans_collection = mongo_database["scans"]
    users_collection = mongo_database["users"]
    print("Using MongoDB database:", MONGODB_DB_NAME)
else:
    mongo_client = None
    mongo_database = None
    scans_collection = None
    users_collection = None
    print("Using SQLite database.")


# Build the database path relative to this file, not the current working directory.
BASE_DIRECTORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.getenv("VERCEL"):
    DATABASE_DIRECTORY = "/tmp"
else:
    DATABASE_DIRECTORY = os.path.join(BASE_DIRECTORY, "database")
DATABASE_PATH = os.path.join(DATABASE_DIRECTORY, "spamshield.db")

if os.getenv("VERCEL") and not USE_MONGODB:
    logger.warning(
        "MONGODB_URI is not configured; using temporary SQLite storage on Vercel. "
        "Scan history will not be persistent."
    )


def get_connection():
    """Open a SQLite connection and enable foreign key enforcement."""
    os.makedirs(DATABASE_DIRECTORY, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _sqlite_init_db():
    """Create the database tables when they do not already exist."""
    connection = get_connection()
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                scan_type TEXT NOT NULL CHECK (scan_type IN ('message', 'url')),
                content TEXT NOT NULL,
                source TEXT NOT NULL,
                prediction TEXT NOT NULL,
                score REAL NOT NULL,
                created_at TEXT NOT NULL,
                categories TEXT NOT NULL DEFAULT '[]',
                keywords TEXT NOT NULL DEFAULT '[]',
                language TEXT NOT NULL DEFAULT 'en'
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                explanation TEXT NOT NULL,
                flags TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            """
        )
        scan_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(scans)")
        }
        if "user_id" not in scan_columns:
            connection.execute(
                "ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)"
            )
        for column in ("categories", "keywords"):
            if column not in scan_columns:
                connection.execute(
                    "ALTER TABLE scans ADD COLUMN {} TEXT NOT NULL DEFAULT '[]'".format(
                        column
                    )
                )
        if "language" not in scan_columns:
            connection.execute(
                "ALTER TABLE scans ADD COLUMN language TEXT NOT NULL DEFAULT 'en'"
            )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_user_created_at "
            "ON scans(user_id, created_at)"
        )
        connection.commit()
    finally:
        connection.close()


def _sqlite_save_scan(
    user_id,
    scan_type,
    content,
    source,
    prediction,
    score,
    explanation,
    flags,
    categories,
    keywords,
    language,
):
    """Save a scan and its JSON flags in one transaction."""
    connection = get_connection()
    try:
        cursor = connection.execute(
            """
            INSERT INTO scans
                (user_id, scan_type, content, source, prediction, score, created_at,
                 categories, keywords, language)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?, ?, ?)
            """,
            (
                int(user_id),
                scan_type,
                content,
                source,
                prediction,
                float(score),
                json.dumps(categories),
                json.dumps(keywords),
                language,
            ),
        )
        scan_id = cursor.lastrowid
        connection.execute(
            """
            INSERT INTO scan_details (scan_id, explanation, flags)
            VALUES (?, ?, ?)
            """,
            (scan_id, explanation, json.dumps(flags)),
        )
        connection.commit()
        return scan_id
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _sqlite_get_history(user_id, search=None, scan_type=None, prediction=None):
    """Return filtered scan history, optionally matching content or source text."""
    connection = get_connection()
    try:
        where_parts = ["s.user_id = ?"]
        parameters = [int(user_id)]

        if search:
            where_parts.append("(s.content LIKE ? OR s.source LIKE ?)")
            search_pattern = "%" + search + "%"
            parameters.extend([search_pattern, search_pattern])
        if scan_type:
            where_parts.append("s.scan_type = ?")
            parameters.append(scan_type)
        if prediction:
            where_parts.append("s.prediction = ?")
            parameters.append(prediction)

        where_sql = ""
        if where_parts:
            where_sql = "WHERE " + " AND ".join(where_parts)

        rows = connection.execute(
            """
            SELECT s.id, s.scan_type, s.content, s.source, s.prediction,
                   s.score, s.created_at,
                   d.explanation, d.flags, s.categories, s.keywords, s.language
            FROM scans AS s
            LEFT JOIN scan_details AS d ON d.scan_id = s.id
            """
            + where_sql
            + " ORDER BY s.id DESC LIMIT 200",
            parameters,
        ).fetchall()

        history = []
        for row in rows:
            history.append(
                {
                    "id": row["id"],
                    "scan_type": row["scan_type"],
                    "content": row["content"],
                    "source": row["source"],
                    "prediction": row["prediction"],
                    "score": row["score"],
                    "created_at": row["created_at"],
                    "explanation": row["explanation"],
                    "flags": json.loads(row["flags"]) if row["flags"] else [],
                    "categories": _decode_json_list(row["categories"]),
                    "keywords": _decode_json_list(row["keywords"]),
                    "language": row["language"],
                }
            )
        return history
    finally:
        connection.close()


def _sqlite_get_scan_by_id(user_id, scan_id):
    """Return one scan and its details by scan ID."""
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT s.id, s.scan_type, s.content, s.source, s.prediction,
                   s.score, s.created_at,
                   d.explanation, d.flags, s.categories, s.keywords, s.language
            FROM scans AS s
            LEFT JOIN scan_details AS d ON d.scan_id = s.id
            WHERE s.id = ? AND s.user_id = ?
            """,
            (scan_id, int(user_id)),
        ).fetchone()

        if row is None:
            return None

        return {
            "id": row["id"],
            "scan_type": row["scan_type"],
            "content": row["content"],
            "source": row["source"],
            "prediction": row["prediction"],
            "score": row["score"],
            "created_at": row["created_at"],
            "explanation": row["explanation"],
            "flags": json.loads(row["flags"]) if row["flags"] else [],
            "categories": _decode_json_list(row["categories"]),
            "keywords": _decode_json_list(row["keywords"]),
            "language": row["language"],
        }
    finally:
        connection.close()


def _sqlite_delete_scan(user_id, scan_id):
    """Delete a scan; cascading removes its scan details."""
    connection = get_connection()
    try:
        cursor = connection.execute(
            "DELETE FROM scans WHERE id = ? AND user_id = ?",
            (scan_id, int(user_id)),
        )
        connection.commit()
        return cursor.rowcount > 0
    finally:
        connection.close()


def _sqlite_clear_history(user_id):
    """Delete one user's scans and their dependent details."""
    connection = get_connection()
    try:
        connection.execute("DELETE FROM scans WHERE user_id = ?", (int(user_id),))
        connection.commit()
    finally:
        connection.close()


def _dashboard_period(range_name):
    """Return UTC date boundaries for the selected and previous periods."""
    today = datetime.now(timezone.utc).date()
    if range_name == "all":
        return None, today + timedelta(days=1), None, None, today
    if range_name not in ("7d", "30d"):
        raise ValueError("Dashboard range must be '7d', '30d', or 'all'.")

    days = 7 if range_name == "7d" else 30
    current_start = today - timedelta(days=days - 1)
    return (
        current_start,
        today + timedelta(days=1),
        today - timedelta(days=(days * 2) - 1),
        current_start,
        today,
    )


def _dashboard_summary_values(rows):
    counts = {}
    for row in rows:
        scan_type = str(row["scan_type"]).lower()
        prediction = str(row["prediction"]).upper()
        counts[(scan_type, prediction)] = int(row["count"])
    return counts


def _dashboard_change(current, previous, range_name):
    if range_name == "all":
        percent = None
    elif previous == 0:
        percent = 0 if current == 0 else None
    else:
        percent = round(((current - previous) / previous) * 100, 1)
    return {"percent": percent, "previous": previous}


def _assemble_dashboard_stats(
    range_name,
    current_rows,
    previous_rows,
    daily_rows,
    source_rows,
    category_rows,
    keyword_rows,
    recent_scans,
    lifetime_total,
    current_start,
    today,
):
    current = _dashboard_summary_values(current_rows)
    previous = _dashboard_summary_values(previous_rows)

    def count(summary, scan_type, prediction=None):
        return sum(
            value
            for (record_type, record_prediction), value in summary.items()
            if record_type == scan_type
            and (prediction is None or record_prediction == prediction)
        )

    messages = count(current, "message")
    urls = count(current, "url")
    message_counts = {
        prediction: count(current, "message", prediction)
        for prediction in ("SAFE", "SUSPICIOUS", "SPAM")
    }
    url_risk_counts = {
        prediction: count(current, "url", prediction)
        for prediction in ("SAFE", "SUSPICIOUS", "SPAM", "HIGH RISK")
    }
    previous_values = {
        "messages": count(previous, "message"),
        "safe": count(previous, "message", "SAFE"),
        "suspicious": count(previous, "message", "SUSPICIOUS"),
        "spam": count(previous, "message", "SPAM"),
        "urls": count(previous, "url"),
    }
    current_values = {
        "messages": messages,
        "safe": message_counts["SAFE"],
        "suspicious": message_counts["SUSPICIOUS"],
        "spam": message_counts["SPAM"],
        "urls": urls,
    }

    daily_counts = {}
    for row in daily_rows:
        day = row["day"]
        record_type = str(row["scan_type"]).lower()
        daily_counts.setdefault(day, {"messages": 0, "urls": 0})
        if record_type == "message":
            daily_counts[day]["messages"] = int(row["count"])
        elif record_type == "url":
            daily_counts[day]["urls"] = int(row["count"])

    if range_name == "all":
        first_day = min(daily_counts) if daily_counts else None
    else:
        first_day = current_start.isoformat()
    scans_per_day = []
    if first_day:
        day = datetime.strptime(first_day, "%Y-%m-%d").date()
        while day <= today:
            day_string = day.isoformat()
            day_counts = daily_counts.get(day_string, {"messages": 0, "urls": 0})
            scans_per_day.append(
                {
                    "date": day_string,
                    "messages": day_counts["messages"],
                    "urls": day_counts["urls"],
                    "total": day_counts["messages"] + day_counts["urls"],
                }
            )
            day += timedelta(days=1)

    source_counts = [
        {"source": str(row["source"]), "count": int(row["count"])}
        for row in source_rows
    ]
    category_counts_by_name = {
        str(row["category"]): int(row["count"]) for row in category_rows
    }
    categories = [
        {"category": category, "count": category_counts_by_name.get(category, 0)}
        for category in SCAM_CATEGORIES
    ]

    return {
        "range": range_name,
        "total_scans": sum(current.values()),
        "lifetime_total": int(lifetime_total),
        "messages": messages,
        "safe": message_counts["SAFE"],
        "spam": message_counts["SPAM"],
        "suspicious": message_counts["SUSPICIOUS"],
        "urls": urls,
        "url_risk_counts": url_risk_counts,
        "scans_per_day": scans_per_day,
        "sources": source_counts,
        "categories": categories,
        "top_keywords": [
            {"keyword": str(row["keyword"]), "count": int(row["count"])}
            for row in keyword_rows[:8]
        ],
        "recent_scans": recent_scans[:8],
        "changes": {
            key: _dashboard_change(current_values[key], previous_values[key], range_name)
            for key in current_values
        },
    }


def _sqlite_period_filter(start, end, column="created_at"):
    clauses = []
    parameters = []
    if start is not None:
        clauses.append("date({}) >= ?".format(column))
        parameters.append(start.isoformat())
    if end is not None:
        clauses.append("date({}) < ?".format(column))
        parameters.append(end.isoformat())
    return (" AND ".join(clauses), parameters)


def _sqlite_dashboard_summary(connection, user_id, start, end):
    date_filter, date_parameters = _sqlite_period_filter(start, end, "created_at")
    where_sql = "user_id = ?"
    if date_filter:
        where_sql += " AND " + date_filter
    return connection.execute(
        """
        SELECT scan_type, UPPER(prediction) AS prediction, COUNT(*) AS count
        FROM scans
        WHERE {}
        GROUP BY scan_type, UPPER(prediction)
        ORDER BY scan_type, prediction
        """.format(where_sql),
        [int(user_id)] + date_parameters,
    ).fetchall()


def _sqlite_get_dashboard_stats(user_id, range_name):
    """Aggregate user-scoped dashboard data with SQLite GROUP BY queries."""
    current_start, current_end, previous_start, previous_end, today = (
        _dashboard_period(range_name)
    )
    connection = get_connection()
    try:
        current_rows = _sqlite_dashboard_summary(
            connection, user_id, current_start, current_end
        )
        previous_rows = (
            _sqlite_dashboard_summary(
                connection, user_id, previous_start, previous_end
            )
            if previous_start is not None
            else []
        )

        current_filter, current_parameters = _sqlite_period_filter(
            current_start, current_end
        )
        current_where = "user_id = ?"
        if current_filter:
            current_where += " AND " + current_filter
        daily_rows = connection.execute(
            """
            SELECT date(created_at) AS day, scan_type, COUNT(*) AS count
            FROM scans
            WHERE {}
            GROUP BY date(created_at), scan_type
            ORDER BY day, scan_type
            """.format(current_where),
            [int(user_id)] + current_parameters,
        ).fetchall()
        source_rows = connection.execute(
            """
            SELECT COALESCE(NULLIF(source, ''), 'Other') AS source,
                   COUNT(*) AS count
            FROM scans
            WHERE {}
            GROUP BY COALESCE(NULLIF(source, ''), 'Other')
            ORDER BY count DESC, source
            """.format(current_where),
            [int(user_id)] + current_parameters,
        ).fetchall()
        category_rows = connection.execute(
            """
            SELECT category_item.value AS category, COUNT(*) AS count
            FROM scans
            JOIN json_each(scans.categories) AS category_item
            WHERE {}
            GROUP BY category_item.value
            ORDER BY count DESC, category
            """.format(current_where),
            [int(user_id)] + current_parameters,
        ).fetchall()
        keyword_rows = connection.execute(
            """
            SELECT LOWER(keyword_item.value) AS keyword, COUNT(*) AS count
            FROM scans
            JOIN json_each(scans.keywords) AS keyword_item
            WHERE {}
            GROUP BY LOWER(keyword_item.value)
            ORDER BY count DESC, keyword
            LIMIT 8
            """.format(current_where),
            [int(user_id)] + current_parameters,
        ).fetchall()
        lifetime_total = connection.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE user_id = ?",
            (int(user_id),),
        ).fetchone()["count"]
        recent_rows = connection.execute(
            """
            SELECT s.id, s.scan_type, s.content, s.source, s.prediction,
                   s.score, s.created_at, d.explanation, d.flags,
                   s.categories, s.keywords, s.language
            FROM scans AS s
            LEFT JOIN scan_details AS d ON d.scan_id = s.id
            WHERE s.user_id = ?
            ORDER BY s.created_at DESC, s.id DESC
            LIMIT 8
            """,
            (int(user_id),),
        ).fetchall()
        recent_scans = []
        for row in recent_rows:
            record = dict(row)
            record["flags"] = _decode_json_list(record["flags"])
            record["categories"] = _decode_json_list(record["categories"])
            record["keywords"] = _decode_json_list(record["keywords"])
            record["explanation"] = record["explanation"] or ""
            recent_scans.append(record)

        return _assemble_dashboard_stats(
            range_name,
            current_rows,
            previous_rows,
            daily_rows,
            source_rows,
            category_rows,
            keyword_rows,
            recent_scans,
            lifetime_total,
            current_start,
            today,
        )
    finally:
        connection.close()


def _format_created_at(created_at):
    """Format datetimes consistently for JSON-compatible return values."""
    if isinstance(created_at, datetime):
        return created_at.strftime("%Y-%m-%d %H:%M:%S")
    return str(created_at) if created_at is not None else ""


def _decode_json_list(value):
    """Return a stored JSON list, using an empty list for legacy rows."""
    if not value:
        return []
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return []
    return decoded if isinstance(decoded, list) else []


def _format_mongo_document(document):
    """Convert MongoDB-specific values into the shared history record format."""
    return {
        "id": str(document["_id"]),
        "scan_type": document["scan_type"],
        "content": document["content"],
        "source": document["source"],
        "prediction": document["prediction"],
        "score": document["score"],
        "created_at": _format_created_at(document["created_at"]),
        "explanation": document.get("explanation", []),
        "flags": document.get("flags", []),
        "categories": document.get("categories", []),
        "keywords": document.get("keywords", []),
        "language": document.get("language", "en"),
    }


def _normalize_prediction(prediction):
    """Store supported model labels in their required uppercase form."""
    normalized_prediction = str(prediction).strip().upper()
    if normalized_prediction not in ("SAFE", "SPAM", "SUSPICIOUS", "HIGH RISK"):
        raise ValueError("Prediction must be SAFE, SPAM, SUSPICIOUS, or HIGH RISK.")
    return normalized_prediction


def _run_database_operation(operation_name, operation):
    """Log the internal database error and expose only a generic custom error."""
    try:
        return operation()
    except DatabaseError:
        raise
    except Exception as error:
        logger.exception("Database operation failed: %s", operation_name)
        raise DatabaseError("Database operation failed.") from error


def _mongo_init_db():
    """Test MongoDB and create the account and per-user scan indexes."""
    mongo_database.command("ping")
    scans_collection.create_index("created_at")
    scans_collection.create_index("user_id")
    scans_collection.create_index([("user_id", 1), ("created_at", -1)])
    users_collection.create_index("email", unique=True)


def _sqlite_get_user(row):
    """Convert a SQLite user row to the shared account shape."""
    if row is None:
        return None
    locked_until = (
        datetime.fromisoformat(row["locked_until"])
        if row["locked_until"]
        else None
    )
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "password_hash": row["password_hash"],
        "created_at": row["created_at"],
        "failed_attempts": row["failed_attempts"],
        "locked_until": locked_until,
    }


def _mongo_get_user(document):
    """Convert a MongoDB user document to the shared account shape."""
    if document is None:
        return None
    locked_until = document.get("locked_until")
    if locked_until and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return {
        "id": str(document["_id"]),
        "name": document["name"],
        "email": document["email"],
        "password_hash": document["password_hash"],
        "created_at": _format_created_at(document["created_at"]),
        "failed_attempts": document.get("failed_attempts", 0),
        "locked_until": locked_until,
    }


def _sqlite_create_user(name, email, password_hash):
    connection = get_connection()
    try:
        cursor = connection.execute(
            """
            INSERT INTO users (name, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                name,
                email,
                password_hash,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()
        return str(cursor.lastrowid)
    finally:
        connection.close()


def _mongo_create_user(name, email, password_hash):
    result = users_collection.insert_one(
        {
            "name": name,
            "email": email,
            "password_hash": password_hash,
            "created_at": datetime.now(timezone.utc),
            "failed_attempts": 0,
            "locked_until": None,
        }
    )
    return str(result.inserted_id)


def _mongo_user_id(user_id):
    try:
        return ObjectId(str(user_id))
    except (InvalidId, TypeError):
        return None


def _sqlite_user_id(user_id):
    try:
        return int(user_id)
    except (TypeError, ValueError):
        return None


def _sqlite_get_user_by_email(email):
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        return _sqlite_get_user(row)
    finally:
        connection.close()


def _mongo_get_user_by_email(email):
    return _mongo_get_user(users_collection.find_one({"email": email}))


def _sqlite_get_user_by_id(user_id):
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return _sqlite_get_user(row)
    finally:
        connection.close()


def _mongo_get_user_by_id(user_id):
    object_id = _mongo_user_id(user_id)
    if object_id is None:
        return None
    return _mongo_get_user(users_collection.find_one({"_id": object_id}))


def _sqlite_record_failed_login(user_id):
    connection = get_connection()
    try:
        connection.execute("BEGIN")
        connection.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
            (user_id,),
        )
        row = connection.execute(
            "SELECT failed_attempts FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None:
            connection.rollback()
            return 0
        attempts = row["failed_attempts"]
        if attempts >= 5:
            lock_until = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            connection.execute(
                "UPDATE users SET locked_until = ? WHERE id = ?",
                (lock_until, user_id),
            )
        connection.commit()
        return attempts
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _mongo_record_failed_login(user_id):
    object_id = _mongo_user_id(user_id)
    if object_id is None:
        return 0
    users_collection.update_one({"_id": object_id}, {"$inc": {"failed_attempts": 1}})
    user = users_collection.find_one({"_id": object_id}, {"failed_attempts": 1})
    if user is None:
        return 0
    attempts = user["failed_attempts"]
    if attempts >= 5:
        users_collection.update_one(
            {"_id": object_id},
            {
                "$set": {
                    "locked_until": datetime.now(timezone.utc) + timedelta(minutes=5)
                }
            },
        )
    return attempts


def _sqlite_reset_failed_logins(user_id):
    connection = get_connection()
    try:
        connection.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,),
        )
        connection.commit()
    finally:
        connection.close()


def _mongo_reset_failed_logins(user_id):
    object_id = _mongo_user_id(user_id)
    if object_id is not None:
        users_collection.update_one(
            {"_id": object_id},
            {"$set": {"failed_attempts": 0, "locked_until": None}},
        )


def _mongo_save_scan(
    user_id,
    scan_type,
    content,
    source,
    prediction,
    score,
    explanation,
    flags,
    categories,
    keywords,
    language,
):
    """Insert one scan record in MongoDB."""
    if scan_type not in ("message", "url"):
        raise ValueError("Scan type must be 'message' or 'url'.")

    explanation_list = explanation if isinstance(explanation, list) else [str(explanation)]
    flag_list = flags if isinstance(flags, list) else list(flags or [])
    object_id = _mongo_user_id(user_id)
    if object_id is None:
        raise ValueError("A valid user ID is required.")

    result = scans_collection.insert_one(
        {
            "user_id": object_id,
            "scan_type": scan_type,
            "content": content,
            "source": source,
            "prediction": _normalize_prediction(prediction),
            "score": float(score),
            "explanation": explanation_list,
            "flags": flag_list,
            "categories": categories,
            "keywords": keywords,
            "language": language,
            "created_at": datetime.now(timezone.utc),
        }
    )
    return str(result.inserted_id)


def _mongo_get_history(user_id, search=None, scan_type=None, prediction=None):
    """Return at most 200 matching MongoDB scans, newest first."""
    object_id = _mongo_user_id(user_id)
    if object_id is None:
        return []
    filters = [{"user_id": object_id}]

    if search:
        safe_search = re.compile(re.escape(search), re.IGNORECASE)
        filters.append({"$or": [{"content": safe_search}, {"source": safe_search}]})
    if scan_type:
        filters.append({"scan_type": scan_type})
    if prediction:
        filters.append({"prediction": _normalize_prediction(prediction)})

    if len(filters) == 1:
        query = filters[0]
    elif filters:
        query = {"$and": filters}

    documents = scans_collection.find(query).sort("created_at", -1).limit(200)
    return [_format_mongo_document(document) for document in documents]


def _mongo_get_scan_by_id(user_id, scan_id):
    """Find a MongoDB scan safely using its string ObjectId."""
    try:
        object_id = ObjectId(str(scan_id))
    except (InvalidId, TypeError):
        return None

    user_object_id = _mongo_user_id(user_id)
    if user_object_id is None:
        return None
    document = scans_collection.find_one(
        {"_id": object_id, "user_id": user_object_id}
    )
    if document is None:
        return None
    return _format_mongo_document(document)


def _mongo_delete_scan(user_id, scan_id):
    """Delete one MongoDB scan, returning False for malformed IDs."""
    try:
        object_id = ObjectId(str(scan_id))
    except (InvalidId, TypeError):
        return False

    user_object_id = _mongo_user_id(user_id)
    if user_object_id is None:
        return False
    result = scans_collection.delete_one(
        {"_id": object_id, "user_id": user_object_id}
    )
    return result.deleted_count > 0


def _mongo_clear_history(user_id):
    """Delete one user's MongoDB scan records."""
    object_id = _mongo_user_id(user_id)
    if object_id is not None:
        scans_collection.delete_many({"user_id": object_id})


def _mongo_dashboard_match(user_object_id, start, end):
    match = {"user_id": user_object_id}
    date_filter = {}
    if start is not None:
        date_filter["$gte"] = datetime.combine(
            start, datetime.min.time(), tzinfo=timezone.utc
        )
    if end is not None:
        date_filter["$lt"] = datetime.combine(
            end, datetime.min.time(), tzinfo=timezone.utc
        )
    if date_filter:
        match["created_at"] = date_filter
    return match


def _mongo_dashboard_summary(match):
    rows = scans_collection.aggregate(
        [
            {"$match": match},
            {
                "$group": {
                    "_id": {
                        "scan_type": "$scan_type",
                        "prediction": {"$toUpper": "$prediction"},
                    },
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"_id.scan_type": 1, "_id.prediction": 1}},
        ]
    )
    return [
        {
            "scan_type": row["_id"]["scan_type"],
            "prediction": row["_id"]["prediction"],
            "count": row["count"],
        }
        for row in rows
    ]


def _mongo_get_dashboard_stats(user_id, range_name):
    """Aggregate user-scoped dashboard data through MongoDB pipelines."""
    current_start, current_end, previous_start, previous_end, today = (
        _dashboard_period(range_name)
    )
    object_id = _mongo_user_id(user_id)
    if object_id is None:
        return _assemble_dashboard_stats(
            range_name, [], [], [], [], [], [], [], 0, current_start, today
        )

    current_match = _mongo_dashboard_match(object_id, current_start, current_end)
    previous_match = (
        _mongo_dashboard_match(object_id, previous_start, previous_end)
        if previous_start is not None
        else None
    )
    current_rows = _mongo_dashboard_summary(current_match)
    previous_rows = (
        _mongo_dashboard_summary(previous_match) if previous_match else []
    )
    daily_rows = [
        {
            "day": row["_id"]["day"],
            "scan_type": row["_id"]["scan_type"],
            "count": row["count"],
        }
        for row in scans_collection.aggregate(
            [
                {"$match": current_match},
                {
                    "$group": {
                        "_id": {
                            "day": {
                                "$dateToString": {
                                    "format": "%Y-%m-%d",
                                    "date": "$created_at",
                                    "timezone": "UTC",
                                }
                            },
                            "scan_type": "$scan_type",
                        },
                        "count": {"$sum": 1},
                    }
                },
                {"$sort": {"_id.day": 1, "_id.scan_type": 1}},
            ]
        )
    ]
    source_rows = [
        {"source": row["_id"], "count": row["count"]}
        for row in scans_collection.aggregate(
            [
                {"$match": current_match},
                {
                    "$group": {
                        "_id": {"$ifNull": ["$source", "Other"]},
                        "count": {"$sum": 1},
                    }
                },
                {"$sort": {"count": -1, "_id": 1}},
            ]
        )
    ]
    category_rows = [
        {"category": row["_id"], "count": row["count"]}
        for row in scans_collection.aggregate(
            [
                {"$match": current_match},
                {"$unwind": "$categories"},
                {"$group": {"_id": "$categories", "count": {"$sum": 1}}},
                {"$sort": {"count": -1, "_id": 1}},
            ]
        )
    ]
    keyword_rows = [
        {"keyword": row["_id"], "count": row["count"]}
        for row in scans_collection.aggregate(
            [
                {"$match": current_match},
                {"$unwind": "$keywords"},
                {
                    "$group": {
                        "_id": {"$toLower": "$keywords"},
                        "count": {"$sum": 1},
                    }
                },
                {"$sort": {"count": -1, "_id": 1}},
                {"$limit": 8},
            ]
        )
    ]
    lifetime_counts = list(
        scans_collection.aggregate(
            [
                {"$match": {"user_id": object_id}},
                {"$group": {"_id": None, "count": {"$sum": 1}}},
            ]
        )
    )
    recent_scans = [
        _format_mongo_document(document)
        for document in scans_collection.aggregate(
            [
                {"$match": {"user_id": object_id}},
                {"$sort": {"created_at": -1, "_id": -1}},
                {"$limit": 8},
            ]
        )
    ]
    return _assemble_dashboard_stats(
        range_name,
        current_rows,
        previous_rows,
        daily_rows,
        source_rows,
        category_rows,
        keyword_rows,
        recent_scans,
        lifetime_counts[0]["count"] if lifetime_counts else 0,
        current_start,
        today,
    )


def init_db():
    """Initialize the configured database or prepare the SQLite fallback."""
    if USE_MONGODB:
        return _run_database_operation("init_db", _mongo_init_db)
    return _run_database_operation("init_db", _sqlite_init_db)


def create_user(name, email, password_hash):
    """Create an account and return its database ID."""
    email = email.strip().lower()
    try:
        if USE_MONGODB:
            return _mongo_create_user(name, email, password_hash)
        return _sqlite_create_user(name, email, password_hash)
    except DuplicateKeyError as error:
        raise UserAlreadyExistsError("An account with that email already exists.") from error
    except sqlite3.IntegrityError as error:
        if "users.email" in str(error):
            raise UserAlreadyExistsError(
                "An account with that email already exists."
            ) from error
        logger.exception("Database operation failed: create_user")
        raise DatabaseError("Database operation failed.") from error
    except Exception as error:
        logger.exception("Database operation failed: create_user")
        raise DatabaseError("Database operation failed.") from error


def get_user_by_email(email):
    """Return one account by its normalized email address."""
    email = email.strip().lower()
    return _run_database_operation(
        "get_user_by_email",
        lambda: (
            _mongo_get_user_by_email(email)
            if USE_MONGODB
            else _sqlite_get_user_by_email(email)
        ),
    )


def get_user_by_id(user_id):
    """Return one account by database ID."""
    return _run_database_operation(
        "get_user_by_id",
        lambda: (
            _mongo_get_user_by_id(user_id)
            if USE_MONGODB
            else _sqlite_get_user_by_id(_sqlite_user_id(user_id))
        ),
    )


def record_failed_login(user_id):
    """Increment failed attempts and lock the account for five minutes at five."""
    return _run_database_operation(
        "record_failed_login",
        lambda: (
            _mongo_record_failed_login(user_id)
            if USE_MONGODB
            else _sqlite_record_failed_login(_sqlite_user_id(user_id))
        ),
    )


def reset_failed_logins(user_id):
    """Clear failed attempts and any active lock after successful login."""
    return _run_database_operation(
        "reset_failed_logins",
        lambda: (
            _mongo_reset_failed_logins(user_id)
            if USE_MONGODB
            else _sqlite_reset_failed_logins(_sqlite_user_id(user_id))
        ),
    )


def _normalize_scan_values(values, allowed=None):
    if not isinstance(values, (list, tuple, set)):
        return []
    normalized = []
    seen = set()
    for value in values:
        if not isinstance(value, str):
            continue
        item = value.strip()
        key = item.lower()
        if not item or key in seen or (allowed is not None and item not in allowed):
            continue
        normalized.append(item)
        seen.add(key)
    return normalized


def save_scan(
    user_id,
    scan_type,
    content,
    source,
    prediction,
    score,
    explanation,
    flags,
    categories=None,
    keywords=None,
    language="en",
):
    """Save a scan using the configured database."""
    categories = _normalize_scan_values(categories, set(SCAM_CATEGORIES))
    keywords = _normalize_scan_values(keywords)
    if language not in ("en", "hinglish", "hi"):
        raise ValueError("Scan language must be 'en', 'hinglish', or 'hi'.")
    if USE_MONGODB:
        return _run_database_operation(
            "save_scan",
            lambda: _mongo_save_scan(
                user_id,
                scan_type,
                content,
                source,
                prediction,
                score,
                explanation,
                flags,
                categories,
                keywords,
                language,
            ),
        )

    try:
        normalized_prediction = _normalize_prediction(prediction)
        explanation_text = (
            " ".join(explanation) if isinstance(explanation, list) else str(explanation)
        )
        return _run_database_operation(
            "save_scan",
            lambda: _sqlite_save_scan(
                user_id,
                scan_type,
                content,
                source,
                normalized_prediction,
                score,
                explanation_text,
                flags,
                categories,
                keywords,
                language,
            ),
        )
    except DatabaseError:
        raise
    except Exception as error:
        logger.exception("Database operation failed: save_scan")
        raise DatabaseError("Database operation failed.") from error


def get_history(user_id, search=None, scan_type=None, prediction=None):
    """Return filtered history from the configured database."""
    if USE_MONGODB:
        return _run_database_operation(
            "get_history",
            lambda: _mongo_get_history(user_id, search, scan_type, prediction),
        )
    try:
        normalized_prediction = (
            _normalize_prediction(prediction) if prediction else prediction
        )
        rows = _run_database_operation(
            "get_history",
            lambda: _sqlite_get_history(
                user_id, search, scan_type, normalized_prediction
            ),
        )
        for row in rows:
            row["prediction"] = str(row["prediction"]).upper()
            row["created_at"] = _format_created_at(row["created_at"])
            row["explanation"] = (
                row["explanation"]
                if isinstance(row["explanation"], list)
                else [row["explanation"]]
            )
        return rows
    except DatabaseError:
        raise
    except Exception as error:
        logger.exception("Database operation failed: get_history")
        raise DatabaseError("Database operation failed.") from error


def get_scan_by_id(user_id, scan_id):
    """Return one scan by ID; malformed MongoDB IDs return None safely."""
    if USE_MONGODB:
        return _run_database_operation(
            "get_scan_by_id", lambda: _mongo_get_scan_by_id(user_id, scan_id)
        )
    try:
        record = _run_database_operation(
            "get_scan_by_id", lambda: _sqlite_get_scan_by_id(user_id, scan_id)
        )
        if record is not None:
            record["prediction"] = str(record["prediction"]).upper()
            record["created_at"] = _format_created_at(record["created_at"])
            record["explanation"] = (
                record["explanation"]
                if isinstance(record["explanation"], list)
                else [record["explanation"]]
            )
        return record
    except DatabaseError:
        raise
    except Exception as error:
        logger.exception("Database operation failed: get_scan_by_id")
        raise DatabaseError("Database operation failed.") from error


def delete_scan(user_id, scan_id):
    """Delete one scan; malformed MongoDB IDs return False safely."""
    if USE_MONGODB:
        return _run_database_operation(
            "delete_scan", lambda: _mongo_delete_scan(user_id, scan_id)
        )
    try:
        return _run_database_operation(
            "delete_scan", lambda: _sqlite_delete_scan(user_id, scan_id)
        )
    except DatabaseError:
        raise
    except Exception as error:
        logger.exception("Database operation failed: delete_scan")
        raise DatabaseError("Database operation failed.") from error


def clear_history(user_id):
    """Remove one user's scan history from the configured database."""
    if USE_MONGODB:
        return _run_database_operation(
            "clear_history", lambda: _mongo_clear_history(user_id)
        )
    return _run_database_operation(
        "clear_history", lambda: _sqlite_clear_history(user_id)
    )


def get_dashboard_stats(user_id, range_name="7d"):
    """Return user-scoped dashboard aggregates for a requested date range."""
    if range_name not in ("7d", "30d", "all"):
        raise ValueError("Dashboard range must be '7d', '30d', or 'all'.")
    if USE_MONGODB:
        return _run_database_operation(
            "get_dashboard_stats",
            lambda: _mongo_get_dashboard_stats(user_id, range_name),
        )
    return _run_database_operation(
        "get_dashboard_stats",
        lambda: _sqlite_get_dashboard_stats(user_id, range_name),
    )