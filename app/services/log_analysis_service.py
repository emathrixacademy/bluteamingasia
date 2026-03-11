"""
Log analysis and event correlation service.
Provides SIEM-like capabilities: pattern detection, timeline correlation,
anomaly scoring, and threat intelligence matching.
"""
from datetime import datetime, timedelta
from collections import Counter
from sqlalchemy import func
from app.extensions import db
from app.models.event import Event
from app.models.alert import Alert
from app.models.device import Device


# Known IOC (Indicators of Compromise) patterns
KNOWN_MALICIOUS_IPS = {
    '185.234.67.12': {'threat': 'C2 Server', 'severity': 'critical', 'source': 'ThreatFeed-1'},
    '103.45.78.200': {'threat': 'Scanner', 'severity': 'high', 'source': 'ThreatFeed-1'},
    '91.240.118.50': {'threat': 'Botnet C2', 'severity': 'critical', 'source': 'ThreatFeed-2'},
    '45.33.32.156': {'threat': 'Known Pentest IP', 'severity': 'medium', 'source': 'ThreatFeed-1'},
    '203.0.113.42': {'threat': 'Exploit Kit Host', 'severity': 'critical', 'source': 'ThreatFeed-3'},
}

SUSPICIOUS_EVENT_PATTERNS = [
    {
        'name': 'Brute Force Attack',
        'pattern': 'login_failed',
        'threshold': 5,
        'window_minutes': 10,
        'severity': 'high',
        'description': 'Multiple failed login attempts from the same source in a short time window',
    },
    {
        'name': 'Port Scan Detected',
        'pattern': 'port_scan_detected',
        'threshold': 1,
        'window_minutes': 5,
        'severity': 'medium',
        'description': 'Systematic port scanning activity detected',
    },
    {
        'name': 'Data Exfiltration',
        'pattern': 'data_exfiltration',
        'threshold': 1,
        'window_minutes': 60,
        'severity': 'critical',
        'description': 'Large volume outbound data transfer to suspicious destination',
    },
    {
        'name': 'Privilege Escalation',
        'pattern': 'unauthorized_access',
        'threshold': 3,
        'window_minutes': 15,
        'severity': 'critical',
        'description': 'Multiple unauthorized access attempts indicating privilege escalation',
    },
    {
        'name': 'Lateral Movement',
        'pattern': 'login_success',
        'threshold': 5,
        'window_minutes': 10,
        'severity': 'high',
        'description': 'Rapid authentication across multiple systems suggesting lateral movement',
    },
]

MITRE_ATTACK_MAPPING = {
    'brute_force_login': {'technique': 'T1110', 'tactic': 'Credential Access', 'name': 'Brute Force'},
    'data_exfiltration': {'technique': 'T1041', 'tactic': 'Exfiltration', 'name': 'Exfiltration Over C2 Channel'},
    'malware_detected': {'technique': 'T1204', 'tactic': 'Execution', 'name': 'User Execution'},
    'port_scan_detected': {'technique': 'T1046', 'tactic': 'Discovery', 'name': 'Network Service Discovery'},
    'unauthorized_access': {'technique': 'T1078', 'tactic': 'Persistence', 'name': 'Valid Accounts'},
    'intruder_detected': {'technique': 'T1200', 'tactic': 'Initial Access', 'name': 'Hardware Additions'},
    'door_forced_open': {'technique': 'T1200', 'tactic': 'Initial Access', 'name': 'Hardware Additions'},
    'network_anomaly': {'technique': 'T1071', 'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
    'fire_detected': {'technique': 'N/A', 'tactic': 'Physical', 'name': 'Physical Sabotage'},
}


def correlate_events(hours: int = 24) -> list[dict]:
    """
    Correlate events across devices to detect attack patterns.
    Returns a list of correlated event chains.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    events = (
        Event.query
        .filter(Event.timestamp >= since)
        .order_by(Event.timestamp.asc())
        .all()
    )

    chains = []
    for pattern in SUSPICIOUS_EVENT_PATTERNS:
        window = timedelta(minutes=pattern['window_minutes'])
        matching = [e for e in events if e.event_type == pattern['pattern']
                    or pattern['pattern'] in (e.event_type or '')]

        # Group by source (device or IP from raw_data)
        groups = {}
        for event in matching:
            source_ip = ''
            if event.raw_data and isinstance(event.raw_data, dict):
                source_ip = event.raw_data.get('data', {}).get('ip', str(event.device_id))
            key = source_ip or str(event.device_id)
            groups.setdefault(key, []).append(event)

        for source, group_events in groups.items():
            if len(group_events) >= pattern['threshold']:
                # Check if events are within the time window
                for i in range(len(group_events)):
                    window_events = [
                        e for e in group_events[i:]
                        if e.timestamp <= group_events[i].timestamp + window
                    ]
                    if len(window_events) >= pattern['threshold']:
                        mitre = MITRE_ATTACK_MAPPING.get(pattern['pattern'], {})
                        chains.append({
                            'pattern_name': pattern['name'],
                            'severity': pattern['severity'],
                            'description': pattern['description'],
                            'source': source,
                            'event_count': len(window_events),
                            'first_seen': window_events[0].timestamp.isoformat(),
                            'last_seen': window_events[-1].timestamp.isoformat(),
                            'events': [
                                {
                                    'id': str(e.id),
                                    'type': e.event_type,
                                    'severity': e.severity,
                                    'timestamp': e.timestamp.isoformat(),
                                    'device': e.device.name if e.device else 'unknown',
                                }
                                for e in window_events
                            ],
                            'mitre_technique': mitre.get('technique', 'N/A'),
                            'mitre_tactic': mitre.get('tactic', 'N/A'),
                            'mitre_name': mitre.get('name', 'N/A'),
                        })
                        break  # One chain per source per pattern

    chains.sort(key=lambda x: x['severity'] == 'critical', reverse=True)
    return chains


def check_ioc(indicator: str) -> dict | None:
    """Check an IP/domain/hash against known IOC databases."""
    if indicator in KNOWN_MALICIOUS_IPS:
        info = KNOWN_MALICIOUS_IPS[indicator]
        return {
            'indicator': indicator,
            'type': 'ip',
            'match': True,
            'threat': info['threat'],
            'severity': info['severity'],
            'source': info['source'],
        }
    return {
        'indicator': indicator,
        'type': 'ip' if '.' in indicator and indicator.replace('.', '').isdigit() else 'other',
        'match': False,
        'threat': None,
        'severity': None,
        'source': None,
    }


def get_event_timeline(hours: int = 24) -> dict:
    """Generate an event timeline with severity distribution."""
    since = datetime.utcnow() - timedelta(hours=hours)

    events = (
        Event.query
        .filter(Event.timestamp >= since)
        .order_by(Event.timestamp.asc())
        .all()
    )

    # Hourly buckets
    buckets = {}
    for event in events:
        hour_key = event.timestamp.strftime('%Y-%m-%d %H:00')
        if hour_key not in buckets:
            buckets[hour_key] = {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        sev = event.severity or 'info'
        if sev in buckets[hour_key]:
            buckets[hour_key][sev] += 1

    # Event type distribution
    type_counts = Counter(e.event_type for e in events)

    # Device activity
    device_counts = Counter(e.device.name if e.device else 'unknown' for e in events)

    return {
        'total_events': len(events),
        'hourly_breakdown': buckets,
        'event_types': dict(type_counts.most_common(15)),
        'device_activity': dict(device_counts.most_common(10)),
        'severity_summary': {
            'info': sum(1 for e in events if e.severity == 'info'),
            'low': sum(1 for e in events if e.severity == 'low'),
            'medium': sum(1 for e in events if e.severity == 'medium'),
            'high': sum(1 for e in events if e.severity == 'high'),
            'critical': sum(1 for e in events if e.severity == 'critical'),
        },
    }


def get_anomaly_scores() -> list[dict]:
    """Calculate anomaly scores for devices based on recent activity."""
    now = datetime.utcnow()
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)

    devices = Device.query.all()
    scores = []

    for device in devices:
        # Count events in last 24h
        recent_count = Event.query.filter(
            Event.device_id == device.id,
            Event.timestamp >= day_ago,
        ).count()

        # Count events in last week (daily average)
        weekly_count = Event.query.filter(
            Event.device_id == device.id,
            Event.timestamp >= week_ago,
        ).count()
        daily_avg = weekly_count / 7 if weekly_count else 0

        # Critical/high events in last 24h
        critical_count = Event.query.filter(
            Event.device_id == device.id,
            Event.timestamp >= day_ago,
            Event.severity.in_(['critical', 'high']),
        ).count()

        # Calculate score (0-100)
        score = 0
        if daily_avg > 0:
            deviation = recent_count / daily_avg if daily_avg > 0 else 0
            if deviation > 3:
                score += 40
            elif deviation > 2:
                score += 25
            elif deviation > 1.5:
                score += 10

        score += min(critical_count * 15, 50)
        score += min(recent_count, 10)
        score = min(score, 100)

        risk_level = 'low'
        if score >= 70:
            risk_level = 'critical'
        elif score >= 50:
            risk_level = 'high'
        elif score >= 30:
            risk_level = 'medium'

        scores.append({
            'device_id': str(device.id),
            'device_name': device.name,
            'device_type': device.device_type,
            'location': device.location,
            'anomaly_score': score,
            'risk_level': risk_level,
            'events_24h': recent_count,
            'daily_average': round(daily_avg, 1),
            'critical_events': critical_count,
        })

    scores.sort(key=lambda x: x['anomaly_score'], reverse=True)
    return scores
