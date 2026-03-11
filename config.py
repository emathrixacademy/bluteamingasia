import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True

    # Embedding configuration
    EMBEDDING_MODEL = os.environ.get('EMBEDDING_MODEL', 'all-MiniLM-L6-v2')
    EMBEDDING_DIMENSION = int(os.environ.get('EMBEDDING_DIMENSION', 384))

    # API keys for device event ingestion
    API_KEYS = [k.strip() for k in os.environ.get('API_KEYS', 'dev-api-key').split(',')]

    # Pagination
    EVENTS_PER_PAGE = 25
    DEVICES_PER_PAGE = 20
    INCIDENTS_PER_PAGE = 15
    ALERTS_PER_PAGE = 25


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'postgresql://blueteam:blueteam@localhost:5432/blueteaming_dev'
    )


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'TEST_DATABASE_URL',
        'postgresql://blueteam:blueteam@localhost:5432/blueteaming_test'
    )
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    # Render provides postgres:// but SQLAlchemy 2.0 requires postgresql://
    _db_url = os.environ.get('DATABASE_URL', '')
    if _db_url.startswith('postgres://'):
        _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URI = _db_url
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}
