import uuid
from datetime import datetime
from app.extensions import db


class Incident(db.Model):
    __tablename__ = 'incidents'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    incident_number = db.Column(db.String(50), unique=True, nullable=False)
    title = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), default='open', index=True)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    ai_analysis = db.Column(db.Text)
    metadata_json = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    events = db.relationship('IncidentEvent', back_populates='incident', cascade='all, delete-orphan')
    ai_actions = db.relationship('AIAction', back_populates='incident', lazy='dynamic')


class IncidentEvent(db.Model):
    __tablename__ = 'incident_events'

    incident_id = db.Column(db.Uuid, db.ForeignKey('incidents.id'), primary_key=True)
    event_id = db.Column(db.Uuid, db.ForeignKey('events.id'), primary_key=True)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    incident = db.relationship('Incident', back_populates='events')
    event = db.relationship('Event', back_populates='incidents')
