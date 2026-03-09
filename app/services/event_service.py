import uuid
from datetime import datetime
from app.extensions import db
from app.models.event import Event
from app.models.device import Device
from app.services.embedding_service import generate_embedding, generate_event_text


def process_event(raw_data):
    """
    MVP pipeline: Ingest -> Validate -> Normalize -> Embed -> Store -> Alert Check.
    Returns a result dict.
    """
    # Validate device exists
    device_id = raw_data.get('device_id')
    if not device_id:
        return {'status': 'rejected', 'reason': 'missing device_id'}

    try:
        device = Device.query.get(device_id)
    except Exception:
        device = None

    if not device:
        return {'status': 'rejected', 'reason': 'unknown_device'}

    # Normalize
    normalized = {
        'event_type': raw_data.get('event_type', raw_data.get('event', 'unknown')),
        'device_type': device.device_type,
        'device_id': str(device.id),
        'severity': raw_data.get('severity', 'info'),
        'location': raw_data.get('location', device.location),
        'data': raw_data.get('data', {}),
    }

    # Generate embedding
    event_text = generate_event_text(normalized)
    embedding = generate_embedding(event_text)

    # Parse timestamp
    try:
        ts = datetime.fromisoformat(raw_data.get('timestamp', datetime.utcnow().isoformat()))
    except (ValueError, TypeError):
        ts = datetime.utcnow()

    # Store event
    event = Event(
        id=uuid.uuid4(),
        event_type=normalized['event_type'],
        device_id=device.id,
        timestamp=ts,
        severity=normalized['severity'],
        location=normalized.get('location'),
        raw_data=raw_data,
        normalized_data=normalized,
        embedding=embedding,
    )
    db.session.add(event)
    db.session.commit()

    # Check for alerts
    from app.services.alert_service import check_event_for_alerts
    alerts = check_event_for_alerts(event)

    return {
        'status': 'processed',
        'event_id': str(event.id),
        'alerts_generated': len(alerts),
    }
