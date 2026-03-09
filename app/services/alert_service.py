import uuid
from app.models.alert import Alert
from app.extensions import db

SEVERITY_ALERT_RULES = {
    'high': 'High severity event detected: {event_type} from {device_type} at {location}',
    'critical': 'CRITICAL: {event_type} from {device_type} at {location} - Immediate attention required',
}

EVENT_TYPE_ALERT_RULES = {
    'intruder_detected': ('high', 'Intruder detected by {device_type} at {location}'),
    'door_forced_open': ('critical', 'Door forced open at {location}'),
    'fire_detected': ('critical', 'Fire detected at {location}'),
    'data_exfiltration': ('critical', 'Data exfiltration attempt detected from {location}'),
    'brute_force_login': ('high', 'Brute force login attempt detected'),
    'unauthorized_access': ('high', 'Unauthorized access attempt at {location}'),
    'malware_detected': ('critical', 'Malware detected on {device_type} at {location}'),
    'network_anomaly': ('medium', 'Network anomaly detected from {device_type} at {location}'),
}


def check_event_for_alerts(event):
    """Check an event against rules and generate alerts if matched."""
    alerts = []
    device_type = event.device.device_type if event.device else 'unknown'
    context = {
        'event_type': event.event_type,
        'device_type': device_type,
        'location': event.location or 'unknown',
    }

    # Severity-based rules
    if event.severity in SEVERITY_ALERT_RULES:
        alert = Alert(
            id=uuid.uuid4(),
            event_id=event.id,
            alert_type=f'severity_{event.severity}',
            severity=event.severity,
            message=SEVERITY_ALERT_RULES[event.severity].format(**context),
        )
        db.session.add(alert)
        alerts.append(alert)

    # Event-type-based rules
    if event.event_type in EVENT_TYPE_ALERT_RULES:
        sev, msg_template = EVENT_TYPE_ALERT_RULES[event.event_type]
        alert = Alert(
            id=uuid.uuid4(),
            event_id=event.id,
            alert_type=f'rule_{event.event_type}',
            severity=sev,
            message=msg_template.format(**context),
        )
        db.session.add(alert)
        alerts.append(alert)

    if alerts:
        db.session.commit()

    return alerts
