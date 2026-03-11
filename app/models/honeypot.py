import uuid
from datetime import datetime
from app.extensions import db


class HoneypotService(db.Model):
    __tablename__ = 'honeypot_services'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(100), nullable=False)
    service_type = db.Column(db.String(50), nullable=False)  # ssh, http, ftp, telnet, smtp, mysql, rdp
    port = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    interaction_level = db.Column(db.String(20), default='medium')  # low, medium, high
    total_connections = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    logs = db.relationship('HoneypotLog', back_populates='service', lazy='dynamic',
                           cascade='all, delete-orphan')


class HoneypotLog(db.Model):
    __tablename__ = 'honeypot_logs'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    service_id = db.Column(db.Uuid, db.ForeignKey('honeypot_services.id'), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer)
    action = db.Column(db.String(100), nullable=False)  # connect, login_attempt, command, disconnect
    payload = db.Column(db.Text)  # raw data sent by attacker
    credentials = db.Column(db.JSON)  # captured username/password attempts
    metadata_json = db.Column(db.JSON)
    threat_level = db.Column(db.String(20), default='low')  # low, medium, high, critical
    country = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    service = db.relationship('HoneypotService', back_populates='logs')
