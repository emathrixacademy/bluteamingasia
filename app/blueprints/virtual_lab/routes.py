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
                       'View live connections, interfaces, ARP tables, and run diagnostics on your actual network.',
        'tools': ['netstat', 'ipconfig', 'arp', 'ping', 'tracert', 'nslookup', 'portscan', 'hostscan'],
        'icon': 'network',
        'difficulty': 'beginner',
    },
    {
        'id': 'vuln-scanner',
        'name': 'Vulnerability Scanner Lab',
        'description': 'Scan target hosts for open ports and services. '
                       'Identify exposed services, DNS records, and HTTP headers on real targets.',
        'tools': ['portscan', 'hostscan', 'nslookup', 'headers', 'resolve', 'dnslookup'],
        'icon': 'scanner',
        'difficulty': 'intermediate',
    },
    {
        'id': 'packet-analysis',
        'name': 'Packet Analysis Workshop',
        'description': 'Deep network analysis with real connection data. '
                       'Inspect active connections, routing tables, and network neighbors.',
        'tools': ['netstat', 'arp', 'route', 'connections', 'pathping'],
        'icon': 'packets',
        'difficulty': 'intermediate',
    },
    {
        'id': 'incident-response',
        'name': 'Incident Response Lab',
        'description': 'Investigate network state for incident response. '
                       'Check connections, DNS, routing, and host discovery for threat hunting.',
        'tools': ['netstat', 'nslookup', 'arp', 'hostscan', 'portscan', 'whois'],
        'icon': 'forensics',
        'difficulty': 'advanced',
    },
    {
        'id': 'firewall-ids',
        'name': 'Firewall & Network Config',
        'description': 'Inspect firewall state, routing tables, and network configuration. '
                       'Analyze network topology and connection states.',
        'tools': ['netstat', 'route', 'ipconfig', 'arp', 'nbtstat'],
        'icon': 'firewall',
        'difficulty': 'advanced',
    },
    {
        'id': 'recon',
        'name': 'Reconnaissance & OSINT',
        'description': 'Gather intelligence on targets using DNS, HTTP headers, WHOIS, and port scanning. '
                       'Map external attack surfaces.',
        'tools': ['nslookup', 'dnslookup', 'headers', 'whois', 'resolve', 'portscan', 'tracert'],
        'icon': 'malware',
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
