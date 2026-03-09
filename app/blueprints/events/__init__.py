from flask import Blueprint

events_bp = Blueprint('events', __name__)

from app.blueprints.events import routes  # noqa: E402, F401
