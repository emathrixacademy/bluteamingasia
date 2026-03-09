import uuid
from datetime import datetime
from app.extensions import db


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    event_id = db.Column(db.Uuid, db.ForeignKey('events.id'))
    alert_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    message = db.Column(db.String(1000), nullable=False)
    is_acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by = db.Column(db.Uuid, db.ForeignKey('users.id'))
    metadata_json = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
