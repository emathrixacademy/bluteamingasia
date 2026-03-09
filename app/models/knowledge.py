import uuid
from datetime import datetime
from app.extensions import db

try:
    from pgvector.sqlalchemy import Vector
    HAS_PGVECTOR = True
except Exception:
    HAS_PGVECTOR = False


class KnowledgeDocument(db.Model):
    __tablename__ = 'knowledge_documents'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    title = db.Column(db.String(500), nullable=False)
    content = db.Column(db.Text, nullable=False)
    doc_type = db.Column(db.String(50), nullable=False)
    source = db.Column(db.String(500))
    tags = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


if HAS_PGVECTOR:
    KnowledgeDocument.embedding = db.Column(Vector(384))
