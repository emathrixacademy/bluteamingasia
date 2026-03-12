from flask import Blueprint

missions_bp = Blueprint('missions', __name__)

from app.blueprints.missions import routes  # noqa: E402, F401
