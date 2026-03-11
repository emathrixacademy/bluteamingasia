from flask import Blueprint

honeypot_bp = Blueprint('honeypot', __name__)

from app.blueprints.honeypot import routes  # noqa: E402, F401
