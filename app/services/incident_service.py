import uuid
from datetime import datetime
from app.extensions import db
from app.models.incident import Incident, IncidentEvent


def generate_incident_number():
    """Generate a sequential incident number like INC-2026-0001."""
    year = datetime.utcnow().year
    last = (
        Incident.query
        .filter(Incident.incident_number.like(f'INC-{year}-%'))
        .order_by(Incident.created_at.desc())
        .first()
    )
    if last:
        seq = int(last.incident_number.split('-')[-1]) + 1
    else:
        seq = 1
    return f'INC-{year}-{seq:04d}'


def create_incident(event_ids, title, severity, description=None):
    """Create an incident from a list of event IDs."""
    incident = Incident(
        id=uuid.uuid4(),
        incident_number=generate_incident_number(),
        title=title,
        severity=severity,
        description=description,
        start_time=datetime.utcnow(),
    )
    db.session.add(incident)

    for eid in event_ids:
        ie = IncidentEvent(incident_id=incident.id, event_id=eid)
        db.session.add(ie)

    db.session.commit()
    return incident
