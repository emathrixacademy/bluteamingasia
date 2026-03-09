import uuid
from datetime import datetime
from app.extensions import db


class Device(db.Model):
    __tablename__ = 'devices'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(255), nullable=False)
    device_type = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(255))
    status = db.Column(db.String(50), default='active')
    ip_address = db.Column(db.String(45))
    metadata_json = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    events = db.relationship('Event', back_populates='device', lazy='dynamic')
