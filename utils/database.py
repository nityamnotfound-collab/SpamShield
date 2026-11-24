import logging
import os
import re
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
logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Raised when a database operation fails."""


class UserAlreadyExistsError(Exception):
    """Raised when an account email is already registered."""


if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is required to run SpamShield.")

# MongoDB performs connection checks on use, keeping imports fast for tests.
mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
mongo_database = mongo_client[MONGODB_DB_NAME]
scans_collection = mongo_database["scans"]
users_collection = mongo_database["users"]
print("Using MongoDB database:", MONGODB_DB_NAME)


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


def _mongo_get_user_by_email(email):
    return _mongo_get_user(users_collection.find_one({"email": email}))


def _mongo_get_user_by_id(user_id):
    object_id = _mongo_user_id(user_id)
    if object_id is None:
        return None
    return _mongo_get_user(users_collection.find_one({"_id": object_id}))


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
    """Verify MongoDB and create required indexes."""
    return _run_database_operation("init_db", _mongo_init_db)


def create_user(name, email, password_hash):
    """Create an account and return its database ID."""
    email = email.strip().lower()
    try:
        return _mongo_create_user(name, email, password_hash)
    except DuplicateKeyError as error:
        raise UserAlreadyExistsError("An account with that email already exists.") from error
    except Exception as error:
        logger.exception("Database operation failed: create_user")
        raise DatabaseError("Database operation failed.") from error


def get_user_by_email(email):
    """Return one account by its normalized email address."""
    email = email.strip().lower()
    return _run_database_operation(
        "get_user_by_email", lambda: _mongo_get_user_by_email(email)
    )


def get_user_by_id(user_id):
    """Return one account by database ID."""
    return _run_database_operation(
        "get_user_by_id", lambda: _mongo_get_user_by_id(user_id)
    )


def record_failed_login(user_id):
    """Increment failed attempts and lock the account for five minutes at five."""
    return _run_database_operation(
        "record_failed_login", lambda: _mongo_record_failed_login(user_id)
    )


def reset_failed_logins(user_id):
    """Clear failed attempts and any active lock after successful login."""
    return _run_database_operation(
        "reset_failed_logins", lambda: _mongo_reset_failed_logins(user_id)
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
    """Save a scan in MongoDB."""
    categories = _normalize_scan_values(categories, set(SCAM_CATEGORIES))
    keywords = _normalize_scan_values(keywords)
    if language not in ("en", "hinglish", "hi"):
        raise ValueError("Scan language must be 'en', 'hinglish', or 'hi'.")
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


def get_history(user_id, search=None, scan_type=None, prediction=None):
    """Return filtered MongoDB history."""
    return _run_database_operation(
        "get_history",
        lambda: _mongo_get_history(user_id, search, scan_type, prediction),
    )


def get_scan_by_id(user_id, scan_id):
    """Return one MongoDB scan by ID, safely handling malformed IDs."""
    return _run_database_operation(
        "get_scan_by_id", lambda: _mongo_get_scan_by_id(user_id, scan_id)
    )


def delete_scan(user_id, scan_id):
    """Delete one MongoDB scan; malformed IDs return False safely."""
    return _run_database_operation(
        "delete_scan", lambda: _mongo_delete_scan(user_id, scan_id)
    )


def clear_history(user_id):
    """Remove one user's MongoDB scan history."""
    return _run_database_operation(
        "clear_history", lambda: _mongo_clear_history(user_id)
    )


def get_dashboard_stats(user_id, range_name="7d"):
    """Return user-scoped dashboard aggregates for a requested date range."""
    if range_name not in ("7d", "30d", "all"):
        raise ValueError("Dashboard range must be '7d', '30d', or 'all'.")
    return _run_database_operation(
        "get_dashboard_stats",
        lambda: _mongo_get_dashboard_stats(user_id, range_name),
    )