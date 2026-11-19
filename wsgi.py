"""WSGI entry point for Render and Vercel deployments."""

from app import app
from utils.database import DatabaseError, init_db


try:
    init_db()
except DatabaseError:
    app.logger.exception("Database initialization failed")
