"""
Seed script for BlueteamingAsia platform.
Populates the database with demo devices, events, incidents, alerts, and knowledge docs.

Usage:
    python seed/seed_data.py
"""
import sys
import os
import uuid
import random
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.device import Device
from app.models.event import Event
from app.models.incident import Incident, IncidentEvent
from app.models.alert import Alert
from app.models.ai_action import AIAction
from app.models.knowledge import KnowledgeDocument

app = create_app('development')

DEMO_DEVICES = [
    {'name': 'Warehouse Camera 1', 'device_type': 'camera', 'location': 'Warehouse Sector A', 'ip_address': '10.0.1.10', 'status': 'active'},
    {'name': 'Warehouse Camera 2', 'device_type': 'camera', 'location': 'Warehouse Sector B', 'ip_address': '10.0.1.11', 'status': 'active'},
    {'name': 'Lobby Camera', 'device_type': 'camera', 'location': 'Main Lobby', 'ip_address': '10.0.1.12', 'status': 'active'},
    {'name': 'Parking Camera', 'device_type': 'camera', 'location': 'Parking Lot', 'ip_address': '10.0.1.13', 'status': 'active'},
    {'name': 'Server Room Camera', 'device_type': 'camera', 'location': 'Data Center', 'ip_address': '10.0.1.14', 'status': 'active'},
    {'name': 'Main Entrance Lock', 'device_type': 'door_lock', 'location': 'Building A Entrance', 'ip_address': '10.0.2.10', 'status': 'active'},
    {'name': 'Server Room Lock', 'device_type': 'door_lock', 'location': 'Data Center', 'ip_address': '10.0.2.11', 'status': 'active'},
    {'name': 'Warehouse Door A', 'device_type': 'door_lock', 'location': 'Warehouse Sector A', 'ip_address': '10.0.2.12', 'status': 'active'},
    {'name': 'Fire Sensor Floor 1', 'device_type': 'sensor', 'location': 'Building A Floor 1', 'ip_address': '10.0.3.10', 'status': 'active'},
    {'name': 'Fire Sensor Floor 2', 'device_type': 'sensor', 'location': 'Building A Floor 2', 'ip_address': '10.0.3.11', 'status': 'active'},
    {'name': 'Gas Sensor Warehouse', 'device_type': 'sensor', 'location': 'Warehouse', 'ip_address': '10.0.3.12', 'status': 'active'},
    {'name': 'Temperature Sensor DC', 'device_type': 'sensor', 'location': 'Data Center', 'ip_address': '10.0.3.13', 'status': 'active'},
    {'name': 'Web Server', 'device_type': 'server', 'location': 'Data Center', 'ip_address': '10.0.4.10', 'status': 'active'},
    {'name': 'Database Server', 'device_type': 'server', 'location': 'Data Center', 'ip_address': '10.0.4.11', 'status': 'active'},
    {'name': 'Auth Server', 'device_type': 'server', 'location': 'Data Center', 'ip_address': '10.0.4.12', 'status': 'active'},
    {'name': 'Perimeter Drone 1', 'device_type': 'drone', 'location': 'Facility Perimeter', 'ip_address': '10.0.5.10', 'status': 'inactive'},
]

EVENT_TEMPLATES = [
    {'event_type': 'motion_detected', 'severity': 'info', 'data': {'object_type': 'person', 'confidence': 0.92}},
    {'event_type': 'motion_detected', 'severity': 'low', 'data': {'object_type': 'vehicle', 'confidence': 0.87}},
    {'event_type': 'intruder_detected', 'severity': 'high', 'data': {'object_type': 'person', 'confidence': 0.93, 'zone': 'restricted'}},
    {'event_type': 'door_access_granted', 'severity': 'info', 'data': {'badge_id': 'EMP-1042', 'method': 'badge'}},
    {'event_type': 'door_access_denied', 'severity': 'medium', 'data': {'badge_id': 'EMP-0099', 'reason': 'not_authorized'}},
    {'event_type': 'door_forced_open', 'severity': 'critical', 'data': {'sensor': 'tamper_switch'}},
    {'event_type': 'login_success', 'severity': 'info', 'data': {'user': 'admin@corp.local', 'ip': '192.168.1.50'}},
    {'event_type': 'login_failed', 'severity': 'low', 'data': {'user': 'admin@corp.local', 'ip': '203.45.67.89'}},
    {'event_type': 'brute_force_login', 'severity': 'high', 'data': {'user': 'root', 'attempts': 47, 'ip': '185.234.67.12'}},
    {'event_type': 'network_anomaly', 'severity': 'medium', 'data': {'type': 'traffic_spike', 'deviation': '3.2x baseline'}},
    {'event_type': 'data_exfiltration', 'severity': 'critical', 'data': {'volume_mb': 2300, 'destination': '185.234.67.12', 'protocol': 'HTTPS'}},
    {'event_type': 'malware_detected', 'severity': 'critical', 'data': {'file': 'payload.exe', 'hash': 'a1b2c3d4...', 'type': 'trojan'}},
    {'event_type': 'fire_detected', 'severity': 'critical', 'data': {'temperature': 89.5, 'smoke_level': 'high'}},
    {'event_type': 'temperature_warning', 'severity': 'medium', 'data': {'current': 32.5, 'threshold': 30.0}},
    {'event_type': 'gas_leak_detected', 'severity': 'critical', 'data': {'gas_type': 'CO', 'ppm': 120}},
    {'event_type': 'port_scan_detected', 'severity': 'medium', 'data': {'source_ip': '203.45.67.89', 'ports_scanned': 1024}},
    {'event_type': 'unauthorized_access', 'severity': 'high', 'data': {'resource': '/admin/config', 'ip': '10.0.1.55'}},
]

KNOWLEDGE_DOCS = [
    {
        'title': 'Brute Force Attack Detection and Response',
        'content': 'A brute force attack involves systematically checking all possible passwords until the correct one is found. Detection indicators include multiple failed login attempts from the same IP within a short time window, attempts across multiple accounts, and login attempts from unusual geographic locations. Response: Block the source IP, enforce account lockout policies, require MFA, and investigate for credential leaks.',
        'doc_type': 'playbook',
        'tags': ['brute_force', 'authentication', 'response'],
    },
    {
        'title': 'Data Exfiltration Indicators and Prevention',
        'content': 'Data exfiltration is the unauthorized transfer of data from an organization. Key indicators include unusual outbound traffic volume especially during off-hours, connections to newly registered domains, DNS tunneling patterns, and large archive file creation. Prevention measures include DLP solutions, network segmentation, egress filtering, and monitoring for anomalous data flows.',
        'doc_type': 'threat_intel',
        'tags': ['exfiltration', 'data_loss', 'prevention'],
    },
    {
        'title': 'Physical Security Breach Response Procedure',
        'content': 'When a physical security breach is detected: 1) Lock all sector doors in the affected zone. 2) Activate camera tracking on the detected intruder. 3) Alert on-site security personnel with location data. 4) Cross-reference with access control logs to identify if the individual has valid credentials. 5) If unauthorized, contact law enforcement. 6) Preserve all video footage and access logs as evidence.',
        'doc_type': 'procedure',
        'tags': ['physical_security', 'breach', 'response'],
    },
    {
        'title': 'MITRE ATT&CK Framework - Reconnaissance Techniques',
        'content': 'Reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting. Key techniques include active scanning (T1595), gathering victim host information (T1592), searching open websites/domains (T1593), and phishing for information (T1598). Detection focuses on monitoring for port scans, DNS enumeration, and unusual OSINT activity targeting the organization.',
        'doc_type': 'reference',
        'tags': ['mitre', 'reconnaissance', 'threat_intel'],
    },
    {
        'title': 'Ransomware Incident Response Playbook',
        'content': 'Upon ransomware detection: 1) Immediately isolate affected systems from the network. 2) Identify the ransomware variant using file signatures and ransom notes. 3) Check backup integrity and recency. 4) Do NOT pay the ransom. 5) Engage incident response team and legal counsel. 6) Report to relevant authorities (CISA, FBI). 7) Begin recovery from clean backups. 8) Conduct post-incident review to identify the initial access vector.',
        'doc_type': 'playbook',
        'tags': ['ransomware', 'incident_response', 'recovery'],
    },
    {
        'title': 'Network Traffic Baseline Anomaly Detection',
        'content': 'Establish baselines for normal network traffic patterns including volume by time of day, common destination IPs, protocol distribution, and average session duration. Anomalies exceeding 2 standard deviations trigger medium alerts; 3+ standard deviations trigger high alerts. Key metrics: packets per second, bytes transferred, unique destination IPs, DNS query frequency, and connection duration.',
        'doc_type': 'reference',
        'tags': ['network', 'anomaly', 'baseline'],
    },
]


def seed():
    with app.app_context():
        print('Seeding database...')

        # Check if data already exists
        if User.query.count() > 0:
            print('Database already has data. Skipping seed.')
            return

        # Create demo admin user
        admin = User(
            email='admin@blueteamingasia.com',
            name='Admin User',
            role='admin',
            subscription_plan='enterprise',
        )
        admin.set_password('admin123')
        db.session.add(admin)

        # Create demo analyst user
        analyst = User(
            email='analyst@blueteamingasia.com',
            name='Security Analyst',
            role='analyst',
            subscription_plan='professional',
        )
        analyst.set_password('analyst123')
        db.session.add(analyst)
        print(f'  Created 2 users')

        # Create devices
        devices = []
        for d in DEMO_DEVICES:
            device = Device(**d)
            db.session.add(device)
            devices.append(device)
        db.session.flush()
        print(f'  Created {len(devices)} devices')

        # Create events (last 7 days)
        events = []
        now = datetime.utcnow()
        for i in range(100):
            template = random.choice(EVENT_TEMPLATES)
            device = random.choice(devices)
            hours_ago = random.uniform(0, 168)  # 7 days
            event = Event(
                event_type=template['event_type'],
                device_id=device.id,
                timestamp=now - timedelta(hours=hours_ago),
                severity=template['severity'],
                location=device.location,
                raw_data={
                    'source': device.name,
                    'event': template['event_type'],
                    'data': template['data'],
                },
                normalized_data={
                    'event_type': template['event_type'],
                    'device_type': device.device_type,
                    'severity': template['severity'],
                    'location': device.location,
                    'data': template['data'],
                },
            )
            db.session.add(event)
            events.append(event)
        db.session.flush()
        print(f'  Created {len(events)} events')

        # Create alerts from high/critical events
        alert_count = 0
        for event in events:
            if event.severity in ('high', 'critical'):
                alert = Alert(
                    event_id=event.id,
                    alert_type=f'rule_{event.event_type}',
                    severity=event.severity,
                    message=f'{event.severity.upper()}: {event.event_type} detected at {event.location}',
                    is_acknowledged=random.choice([True, False]),
                )
                db.session.add(alert)
                alert_count += 1
        db.session.flush()
        print(f'  Created {alert_count} alerts')

        # Create incidents
        critical_events = [e for e in events if e.severity == 'critical']
        incidents = []
        for i, evt_group_start in enumerate(range(0, min(len(critical_events), 9), 3)):
            evt_group = critical_events[evt_group_start:evt_group_start + 3]
            if not evt_group:
                break
            incident = Incident(
                incident_number=f'INC-2026-{i + 1:04d}',
                title=f'Security Incident: {evt_group[0].event_type} at {evt_group[0].location}',
                status=random.choice(['open', 'investigating', 'resolved']),
                severity='critical',
                description=f'Automated incident created from correlated critical events.',
                start_time=min(e.timestamp for e in evt_group),
                ai_analysis=f'AI Analysis: Detected correlated {evt_group[0].event_type} events '
                            f'across {len(evt_group)} sources. Threat confidence: {random.randint(75, 98)}%. '
                            f'Recommended actions: isolate affected systems, investigate root cause.',
            )
            db.session.add(incident)
            db.session.flush()

            for evt in evt_group:
                ie = IncidentEvent(incident_id=incident.id, event_id=evt.id)
                db.session.add(ie)

            # Add AI action
            action = AIAction(
                incident_id=incident.id,
                action_type='auto_response',
                tool_used='block_ip' if evt_group[0].event_type in ('brute_force_login', 'data_exfiltration') else 'lock_sector_doors',
                parameters={'target': evt_group[0].location},
                result={'status': 'success'},
                status='completed',
                timestamp=evt_group[0].timestamp + timedelta(seconds=2),
            )
            db.session.add(action)
            incidents.append(incident)

        db.session.flush()
        print(f'  Created {len(incidents)} incidents with AI actions')

        # Create knowledge documents
        for doc_data in KNOWLEDGE_DOCS:
            doc = KnowledgeDocument(**doc_data)
            db.session.add(doc)
        print(f'  Created {len(KNOWLEDGE_DOCS)} knowledge documents')

        db.session.commit()
        print('Seed complete!')
        print(f'\nDemo login credentials:')
        print(f'  Admin:   admin@blueteamingasia.com / admin123')
        print(f'  Analyst: analyst@blueteamingasia.com / analyst123')


if __name__ == '__main__':
    seed()
