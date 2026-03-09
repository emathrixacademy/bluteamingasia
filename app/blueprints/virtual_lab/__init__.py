from flask import Blueprint

virtual_lab_bp = Blueprint('virtual_lab', __name__)

from app.blueprints.virtual_lab import routes  # noqa: E402, F401
