from flask import render_template, request, jsonify
from flask_login import login_required
from app.blueprints.virtual_lab import virtual_lab_bp
from app.services.network_executor import execute_command, get_network_overview


# Predefined lab environments
LAB_ENVIRONMENTS = [
    {
        'id': 'network-monitor',
        'name': 'Network Monitoring Station',
        'description': 'Real-time network traffic analysis and monitoring. '
                       'View live connections, interfaces, ARP tables, and capture network traffic.',
        'tools': ['netstat', 'ipconfig', 'arp', 'ping', 'tracert', 'nslookup', 'capture', 'flood-detect'],
        'icon': 'network',
        'difficulty': 'beginner',
    },
    {
        'id': 'vuln-scanner',
        'name': 'Vulnerability Scanner Lab',
        'description': 'Scan targets for open ports, service versions, and vulnerabilities. '
                       'Full nmap-style scanning with banner grabbing and SSL analysis.',
        'tools': ['portscan', 'hostscan', 'detect', 'banner', 'vulnscan', 'sslscan', 'headers'],
        'icon': 'scanner',
        'difficulty': 'intermediate',
    },
    {
        'id': 'packet-analysis',
        'name': 'Packet Analysis Workshop',
        'description': 'Deep network analysis with real connection data and packet capture. '
                       'Monitor traffic flows, detect anomalies, and inspect connection states.',
        'tools': ['netstat', 'arp', 'route', 'connections', 'capture', 'pathping', 'flood-detect'],
        'icon': 'packets',
        'difficulty': 'intermediate',
    },
    {
        'id': 'incident-response',
        'name': 'Incident Response Lab',
        'description': 'Investigate network state for incident response and threat hunting. '
                       'Check IOCs, analyze connections, and detect attack patterns.',
        'tools': ['netstat', 'nslookup', 'arp', 'hostscan', 'portscan', 'ioc', 'capture', 'flood-detect'],
        'icon': 'forensics',
        'difficulty': 'advanced',
    },
    {
        'id': 'firewall-ids',
        'name': 'Firewall & IDS Lab',
        'description': 'Inspect firewall state, detect floods and DDoS, and analyze '
                       'network topology. Includes intrusion detection capabilities.',
        'tools': ['netstat', 'route', 'ipconfig', 'arp', 'flood-detect', 'capture', 'vulnscan'],
        'icon': 'firewall',
        'difficulty': 'advanced',
    },
    {
        'id': 'recon',
        'name': 'Reconnaissance & OSINT',
        'description': 'Gather intelligence on targets using DNS, HTTP headers, WHOIS, SSL analysis, '
                       'banner grabbing, and service fingerprinting. Map attack surfaces.',
        'tools': ['nslookup', 'dnslookup', 'headers', 'whois', 'resolve', 'portscan', 'tracert',
                  'banner', 'sslscan', 'detect', 'ioc'],
        'icon': 'malware',
        'difficulty': 'expert',
    },
    {
        'id': 'ssl-crypto',
        'name': 'SSL/TLS & Cryptography Lab',
        'description': 'Analyze SSL/TLS configurations, certificate chains, cipher suites, '
                       'and protocol security. Find weak encryption and expired certificates.',
        'tools': ['sslscan', 'headers', 'banner', 'vulnscan', 'resolve'],
        'icon': 'scanner',
        'difficulty': 'intermediate',
    },
    {
        'id': 'threat-hunt',
        'name': 'Threat Hunting Lab',
        'description': 'Advanced threat hunting with IOC checking, service detection, '
                       'vulnerability scanning, and network anomaly detection.',
        'tools': ['ioc', 'detect', 'vulnscan', 'banner', 'sslscan', 'flood-detect',
                  'capture', 'portscan', 'hostscan', 'whois'],
        'icon': 'forensics',
        'difficulty': 'expert',
    },
]


@virtual_lab_bp.route('/')
@login_required
def lab_list():
    return render_template('virtual_lab/list.html', labs=LAB_ENVIRONMENTS)


@virtual_lab_bp.route('/network-overview')
@login_required
def network_overview():
    """Real-time network overview dashboard."""
    overview = get_network_overview()
    return render_template('virtual_lab/network_overview.html', overview=overview)


@virtual_lab_bp.route('/api/network-status')
@login_required
def network_status_api():
    """API endpoint for real-time network status (AJAX refresh)."""
    overview = get_network_overview()
    return jsonify({
        'hostname': overview['hostname'],
        'local_ips': overview['local_ips'],
        'interfaces': overview['interfaces'],
        'connections': {
            'established': overview['connections']['established'],
            'listening': overview['connections']['listening'],
            'time_wait': overview['connections']['time_wait'],
            'close_wait': overview['connections']['close_wait'],
            'total': overview['connections']['total'],
        },
        'arp_count': len(overview['arp_entries']),
        'arp_entries': overview['arp_entries'][:30],
    })


@virtual_lab_bp.route('/<lab_id>')
@login_required
def lab_console(lab_id):
    lab = next((l for l in LAB_ENVIRONMENTS if l['id'] == lab_id), None)
    if not lab:
        return render_template('errors/404.html'), 404
    return render_template('virtual_lab/console.html', lab=lab)


@virtual_lab_bp.route('/api/execute', methods=['POST'])
@login_required
def execute_lab_command():
    """Execute a real network command in the lab environment."""
    data = request.get_json()
    command = data.get('command', '').strip()
    lab_id = data.get('lab_id', '')

    if not command:
        return jsonify({'error': 'No command provided'}), 400

    # Execute the real command
    result = execute_command(command, lab_id)

    output = result.get('output', '')
    error = result.get('error', '')
    is_real = result.get('is_real', False)

    # Combine output and error for display
    display = output
    if error and not output:
        display = f'Error: {error}'
    elif error:
        display = output + '\n' + error

    return jsonify({
        'output': display,
        'command': command,
        'is_real': is_real,
        'exit_code': result.get('exit_code', 0),
    })
