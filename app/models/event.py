import uuid
from datetime import datetime
from app.extensions import db

try:
    from pgvector.sqlalchemy import Vector
    HAS_PGVECTOR = True
except Exception:
    HAS_PGVECTOR = False


class Event(db.Model):
    __tablename__ = 'events'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    event_type = db.Column(db.String(100), nullable=False, index=True)
    device_id = db.Column(db.Uuid, db.ForeignKey('devices.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)
    location = db.Column(db.String(255))
    raw_data = db.Column(db.JSON)
    normalized_data = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    device = db.relationship('Device', back_populates='events')
    incidents = db.relationship('IncidentEvent', back_populates='event')


# Add vector column only when pgvector is available and using PostgreSQL
if HAS_PGVECTOR:
    Event.embedding = db.Column(Vector(384))
