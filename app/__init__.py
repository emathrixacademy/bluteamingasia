from flask import Flask, render_template, request
from config import config
from app.extensions import db, migrate, login_manager, csrf


def create_app(config_name='development'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'warning'

    # Import models so Alembic can detect them
    from app import models  # noqa: F401

    # Register blueprints
    from app.blueprints.main import main_bp
    from app.blueprints.auth import auth_bp
    from app.blueprints.dashboard import dashboard_bp
    from app.blueprints.devices import devices_bp
    from app.blueprints.events import events_bp
    from app.blueprints.incidents import incidents_bp
    from app.blueprints.alerts import alerts_bp
    from app.blueprints.api import api_bp
    from app.blueprints.virtual_lab import virtual_lab_bp
    from app.blueprints.honeypot import honeypot_bp
    from app.blueprints.analysis import analysis_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(devices_bp, url_prefix='/devices')
    app.register_blueprint(events_bp, url_prefix='/events')
    app.register_blueprint(incidents_bp, url_prefix='/incidents')
    app.register_blueprint(alerts_bp, url_prefix='/alerts')
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    app.register_blueprint(virtual_lab_bp, url_prefix='/lab')
    app.register_blueprint(honeypot_bp, url_prefix='/honeypot')
    app.register_blueprint(analysis_bp, url_prefix='/analysis')

    # Exempt API blueprint from CSRF
    csrf.exempt(api_bp)

    # Static asset caching for faster deployment/loading
    app.config.setdefault('SEND_FILE_MAX_AGE_DEFAULT', 31536000)  # 1 year cache

    @app.after_request
    def add_cache_headers(response):
        if 'Cache-Control' not in response.headers:
            if request.path.startswith('/static/'):
                response.headers['Cache-Control'] = 'public, max-age=31536000'
            else:
                response.headers['Cache-Control'] = 'no-cache'
        return response

    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    return app
