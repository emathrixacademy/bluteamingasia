import os
from app import create_app
from app.extensions import db
from sqlalchemy import text

app = create_app('production')

with app.app_context():
    # Enable pgvector extension if available (required for embedding columns)
    pgvector_available = False
    try:
        db.session.execute(text('CREATE EXTENSION IF NOT EXISTS vector'))
        db.session.commit()
        pgvector_available = True
    except Exception:
        db.session.rollback()

    # If pgvector extension not available, remove vector columns before create_all
    if not pgvector_available:
        from app.models.event import Event
        from app.models.knowledge import KnowledgeDocument
        # Remove embedding columns that require pgvector
        if hasattr(Event, 'embedding') and 'embedding' in Event.__table__.columns:
            Event.__table__._columns.remove(Event.__table__.columns['embedding'])
        if hasattr(KnowledgeDocument, 'embedding') and 'embedding' in KnowledgeDocument.__table__.columns:
            KnowledgeDocument.__table__._columns.remove(KnowledgeDocument.__table__.columns['embedding'])

    db.create_all()

    # Seed missions if none exist
    from app.blueprints.missions.routes import seed_missions
    seed_missions()

    # Seed default admin user if no users exist
    from app.models.user import User
    if User.query.count() == 0:
        admin = User(
            email='admin@blueteamingasia.com',
            name='Admin',
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
