from functools import wraps
from flask import request, jsonify, current_app


def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'Missing API key'}), 401
        valid_keys = current_app.config.get('API_KEYS', [])
        if api_key not in valid_keys:
            return jsonify({'error': 'Invalid API key'}), 403
        return f(*args, **kwargs)
    return decorated
