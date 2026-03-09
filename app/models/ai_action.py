import uuid
from datetime import datetime
from app.extensions import db


class AIAction(db.Model):
    __tablename__ = 'ai_actions'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    incident_id = db.Column(db.Uuid, db.ForeignKey('incidents.id'))
    action_type = db.Column(db.String(100), nullable=False)
    tool_used = db.Column(db.String(100), nullable=False)
    parameters = db.Column(db.JSON)
    result = db.Column(db.JSON)
    status = db.Column(db.String(50), default='completed')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    incident = db.relationship('Incident', back_populates='ai_actions')
