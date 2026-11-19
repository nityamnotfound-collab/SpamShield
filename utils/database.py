import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone

from bson.errors import InvalidId
from bson.objectid import ObjectId
from dotenv import load_dotenv
from pymongo import MongoClient


# Load local configuration before checking which database to use.
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "spamshield")
USE_MONGODB = bool(MONGODB_URI)
logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Raised when a database operation fails."""


if USE_MONGODB:
    # Create one client for this module; MongoDB performs connection checks on use.
    mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    mongo_database = mongo_client[MONGODB_DB_NAME]
    scans_collection = mongo_database["scans"]
    print("Using MongoDB database:", MONGODB_DB_NAME)
else:
    mongo_client = None
    mongo_database = None
    scans_collection = None
    print("Using SQLite database.")


# Build the database path relative to this file, not the current working directory.
BASE_DIRECTORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_DIRECTORY = os.path.join(BASE_DIRECTORY, "database")
DATABASE_PATH = os.path.join(DATABASE_DIRECTORY, "spamshield.db")


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
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL CHECK (scan_type IN ('message', 'url')),
                content TEXT NOT NULL,
                source TEXT NOT NULL,
                prediction TEXT NOT NULL,
                score REAL NOT NULL,
                created_at TEXT NOT NULL
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
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)"
        )
        connection.commit()
    finally:
        connection.close()


def _sqlite_save_scan(scan_type, content, source, prediction, score, explanation, flags):
    """Save a scan and its JSON flags in one transaction."""
    connection = get_connection()
    try:
        cursor = connection.execute(
            """
            INSERT INTO scans
                (scan_type, content, source, prediction, score, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            """,
            (scan_type, content, source, prediction, float(score)),
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


def _sqlite_get_history(search=None, scan_type=None, prediction=None):
    """Return filtered scan history, optionally matching content or source text."""
    connection = get_connection()
    try:
        where_parts = []
        parameters = []

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
                   d.explanation, d.flags
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
                }
            )
        return history
    finally:
        connection.close()


def _sqlite_get_scan_by_id(scan_id):
    """Return one scan and its details by scan ID."""
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT s.id, s.scan_type, s.content, s.source, s.prediction,
                   s.score, s.created_at,
                   d.explanation, d.flags
            FROM scans AS s
            LEFT JOIN scan_details AS d ON d.scan_id = s.id
            WHERE s.id = ?
            """,
            (scan_id,),
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
        }
    finally:
        connection.close()


def _sqlite_delete_scan(scan_id):
    """Delete a scan; cascading removes its scan details."""
    connection = get_connection()
    try:
        cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        connection.commit()
        return cursor.rowcount > 0
    finally:
        connection.close()


def _sqlite_clear_history():
    """Delete every saved scan and its dependent details."""
    connection = get_connection()
    try:
        connection.execute("DELETE FROM scans")
        connection.commit()
    finally:
        connection.close()


def _sqlite_get_dashboard_stats():
    """Get dashboard totals from SQL COUNT queries."""
    connection = get_connection()
    try:
        total_scans = connection.execute(
            "SELECT COUNT(*) AS count FROM scans"
        ).fetchone()["count"]
        message_count = connection.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE scan_type = 'message'"
        ).fetchone()["count"]
        url_count = connection.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE scan_type = 'url'"
        ).fetchone()["count"]
        safe_count = connection.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE LOWER(prediction) = 'safe'"
        ).fetchone()["count"]
        spam_count = connection.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE LOWER(prediction) = 'spam'"
        ).fetchone()["count"]
        suspicious_count = connection.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE LOWER(prediction) = 'suspicious'"
        ).fetchone()["count"]

        last_five = connection.execute(
            """
            SELECT id, scan_type, content, source, prediction, score, created_at
            FROM scans
            ORDER BY id DESC
            LIMIT 5
            """
        ).fetchall()

        return {
            "total_scans": total_scans,
            "messages": message_count,
            "safe": safe_count,
            "spam": spam_count,
            "suspicious": suspicious_count,
            "urls": url_count,
            "spam_vs_safe": [
                {"prediction": "safe", "count": safe_count},
                {"prediction": "spam", "count": spam_count},
            ],
            "last_five": [dict(row) for row in last_five],
        }
    finally:
        connection.close()


def _format_created_at(created_at):
    """Format datetimes consistently for JSON-compatible return values."""
    if isinstance(created_at, datetime):
        return created_at.strftime("%Y-%m-%d %H:%M:%S")
    return str(created_at) if created_at is not None else ""


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
        "explanation": document["explanation"],
        "flags": document["flags"],
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
    """Test MongoDB connectivity and ensure scans are indexed by creation time."""
    mongo_database.command("ping")
    scans_collection.create_index("created_at")


def _mongo_save_scan(scan_type, content, source, prediction, score, explanation, flags):
    """Insert one scan record in MongoDB."""
    if scan_type not in ("message", "url"):
        raise ValueError("Scan type must be 'message' or 'url'.")

    explanation_list = explanation if isinstance(explanation, list) else [str(explanation)]
    flag_list = flags if isinstance(flags, list) else list(flags or [])

    result = scans_collection.insert_one(
        {
            "scan_type": scan_type,
            "content": content,
            "source": source,
            "prediction": _normalize_prediction(prediction),
            "score": float(score),
            "explanation": explanation_list,
            "flags": flag_list,
            "created_at": datetime.now(timezone.utc),
        }
    )
    return str(result.inserted_id)


def _mongo_get_history(search=None, scan_type=None, prediction=None):
    """Return at most 200 matching MongoDB scans, newest first."""
    query = {}
    filters = []

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


def _mongo_get_scan_by_id(scan_id):
    """Find a MongoDB scan safely using its string ObjectId."""
    try:
        object_id = ObjectId(str(scan_id))
    except (InvalidId, TypeError):
        return None

    document = scans_collection.find_one({"_id": object_id})
    if document is None:
        return None
    return _format_mongo_document(document)


def _mongo_delete_scan(scan_id):
    """Delete one MongoDB scan, returning False for malformed IDs."""
    try:
        object_id = ObjectId(str(scan_id))
    except (InvalidId, TypeError):
        return False

    result = scans_collection.delete_one({"_id": object_id})
    return result.deleted_count > 0


def _mongo_clear_history():
    """Delete all MongoDB scan records."""
    scans_collection.delete_many({})


def _mongo_get_dashboard_stats():
    """Get dashboard totals from MongoDB count_documents queries."""
    total_scans = scans_collection.count_documents({})
    message_count = scans_collection.count_documents({"scan_type": "message"})
    url_count = scans_collection.count_documents({"scan_type": "url"})
    safe_count = scans_collection.count_documents({"prediction": "SAFE"})
    spam_count = scans_collection.count_documents({"prediction": "SPAM"})
    suspicious_count = scans_collection.count_documents({"prediction": "SUSPICIOUS"})

    last_five_documents = scans_collection.find().sort("created_at", -1).limit(5)
    last_five = []
    for document in last_five_documents:
        formatted_document = _format_mongo_document(document)
        last_five.append(
            {
                "id": formatted_document["id"],
                "scan_type": formatted_document["scan_type"],
                "content": formatted_document["content"],
                "source": formatted_document["source"],
                "prediction": formatted_document["prediction"],
                "score": formatted_document["score"],
                "created_at": formatted_document["created_at"],
            }
        )

    return {
        "total_scans": total_scans,
        "messages": message_count,
        "safe": safe_count,
        "spam": spam_count,
        "suspicious": suspicious_count,
        "urls": url_count,
        "spam_vs_safe": [
            {"prediction": "SAFE", "count": safe_count},
            {"prediction": "SPAM", "count": spam_count},
        ],
        "last_five": last_five,
    }


def init_db():
    """Initialize the configured database or prepare the SQLite fallback."""
    if USE_MONGODB:
        return _run_database_operation("init_db", _mongo_init_db)
    return _run_database_operation("init_db", _sqlite_init_db)


def save_scan(scan_type, content, source, prediction, score, explanation, flags):
    """Save a scan using the configured database."""
    if USE_MONGODB:
        return _run_database_operation(
            "save_scan",
            lambda: _mongo_save_scan(
                scan_type, content, source, prediction, score, explanation, flags
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
                scan_type,
                content,
                source,
                normalized_prediction,
                score,
                explanation_text,
                flags,
            ),
        )
    except DatabaseError:
        raise
    except Exception as error:
        logger.exception("Database operation failed: save_scan")
        raise DatabaseError("Database operation failed.") from error


def get_history(search=None, scan_type=None, prediction=None):
    """Return filtered history from the configured database."""
    if USE_MONGODB:
        return _run_database_operation(
            "get_history",
            lambda: _mongo_get_history(search, scan_type, prediction),
        )
    try:
        normalized_prediction = (
            _normalize_prediction(prediction) if prediction else prediction
        )
        rows = _run_database_operation(
            "get_history",
            lambda: _sqlite_get_history(search, scan_type, normalized_prediction),
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


def get_scan_by_id(scan_id):
    """Return one scan by ID; malformed MongoDB IDs return None safely."""
    if USE_MONGODB:
        return _run_database_operation(
            "get_scan_by_id", lambda: _mongo_get_scan_by_id(scan_id)
        )
    try:
        record = _run_database_operation(
            "get_scan_by_id", lambda: _sqlite_get_scan_by_id(scan_id)
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


def delete_scan(scan_id):
    """Delete one scan; malformed MongoDB IDs return False safely."""
    if USE_MONGODB:
        return _run_database_operation("delete_scan", lambda: _mongo_delete_scan(scan_id))
    try:
        return _run_database_operation(
            "delete_scan", lambda: _sqlite_delete_scan(scan_id)
        )
    except DatabaseError:
        raise
    except Exception as error:
        logger.exception("Database operation failed: delete_scan")
        raise DatabaseError("Database operation failed.") from error


def clear_history():
    """Remove all scan history from the configured database."""
    if USE_MONGODB:
        return _run_database_operation("clear_history", _mongo_clear_history)
    return _run_database_operation("clear_history", _sqlite_clear_history)


def get_dashboard_stats():
    """Return dashboard counts and the five most recent scans."""
    if USE_MONGODB:
        return _run_database_operation(
            "get_dashboard_stats", _mongo_get_dashboard_stats
        )
    return _run_database_operation(
        "get_dashboard_stats", _sqlite_get_dashboard_stats
    )