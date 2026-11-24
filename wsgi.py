"""WSGI entry point for Render and Vercel deployments."""

from app import app
from utils.database import init_db

init_db()
