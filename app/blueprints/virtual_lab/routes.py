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


@virtual_lab_bp.route('/packet-tracer')
@login_required
def packet_tracer():
    """Interactive packet tracer simulation with visual network topology."""
    overview = get_network_overview()
    return render_template('virtual_lab/packet_tracer.html', overview=overview)


@virtual_lab_bp.route('/api/packet-trace', methods=['POST'])
@login_required
def packet_trace_api():
    """API endpoint for packet trace simulation."""
    data = request.get_json()
    source = data.get('source', '')
    destination = data.get('destination', '')
    protocol = data.get('protocol', 'TCP')
    port = data.get('port', 80)

    if not source or not destination:
        return jsonify({'error': 'Source and destination required'}), 400

    # Build simulated trace using real traceroute + connection data
    trace_result = _build_packet_trace(source, destination, protocol, int(port))
    return jsonify(trace_result)


def _build_packet_trace(source, destination, protocol, port):
    """Build a packet trace simulation with real network data."""
    import subprocess
    import platform
    import socket
    import time

    hops = []
    start_time = time.time()

    # Resolve destination
    try:
        dest_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        dest_ip = destination

    # Resolve source
    if source in ('localhost', '127.0.0.1', 'this-machine'):
        try:
            source_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            source_ip = '127.0.0.1'
    else:
        source_ip = source

    # Step 1: Source device
    hops.append({
        'hop': 0,
        'node': source_ip,
        'label': 'Source',
        'type': 'endpoint',
        'latency_ms': 0,
        'status': 'ok',
        'detail': f'Packet created: {protocol} SYN to {dest_ip}:{port}',
    })

    # Step 2: Real traceroute to get hops
    is_windows = platform.system() == 'Windows'
    cmd = ['tracert', '-d', '-w', '1000', '-h', '15', destination] if is_windows \
        else ['traceroute', '-n', '-w', '1', '-m', '15', destination]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        lines = result.stdout.strip().split('\n')
        hop_num = 1
        for line in lines:
            line = line.strip()
            if not line or 'Tracing' in line or 'over a' in line or 'traceroute' in line:
                continue
            parts = line.split()
            if not parts or not parts[0].isdigit():
                continue
            # Extract IP and latency
            ip_addr = None
            latency = None
            for part in parts[1:]:
                if part == '*':
                    continue
                if 'ms' in part:
                    try:
                        latency = float(part.replace('ms', ''))
                    except ValueError:
                        pass
                elif '.' in part and all(c.isdigit() or c == '.' for c in part):
                    ip_addr = part

            if ip_addr:
                node_type = 'router'
                label = f'Hop {hop_num}'
                # Detect gateway
                if hop_num == 1:
                    label = 'Gateway'
                    node_type = 'gateway'
                elif ip_addr == dest_ip:
                    label = 'Destination'
                    node_type = 'endpoint'

                hops.append({
                    'hop': hop_num,
                    'node': ip_addr,
                    'label': label,
                    'type': node_type,
                    'latency_ms': latency or 0,
                    'status': 'ok',
                    'detail': f'{protocol} packet forwarded via {ip_addr}' +
                              (f' ({latency:.1f}ms)' if latency else ''),
                })
                hop_num += 1
                if ip_addr == dest_ip:
                    break
    except Exception:
        # Fallback: simulated hops
        hops.append({
            'hop': 1, 'node': '192.168.1.1', 'label': 'Gateway',
            'type': 'gateway', 'latency_ms': 1, 'status': 'ok',
            'detail': 'Packet forwarded by default gateway',
        })

    # Ensure destination is in hops
    if not any(h['node'] == dest_ip for h in hops):
        hops.append({
            'hop': len(hops),
            'node': dest_ip,
            'label': 'Destination',
            'type': 'endpoint',
            'latency_ms': round((time.time() - start_time) * 1000, 1),
            'status': 'ok',
            'detail': f'{protocol} SYN-ACK received from {dest_ip}:{port}',
        })

    total_latency = sum(h['latency_ms'] for h in hops)

    # Port check
    port_open = False
    if protocol == 'TCP':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((dest_ip, port))
            port_open = result == 0
            sock.close()
        except Exception:
            pass

    return {
        'source': source_ip,
        'destination': dest_ip,
        'destination_host': destination,
        'protocol': protocol,
        'port': port,
        'port_open': port_open,
        'hops': hops,
        'total_hops': len(hops),
        'total_latency_ms': round(total_latency, 1),
        'status': 'success' if port_open or protocol == 'ICMP' else 'filtered',
        'summary': f'{protocol} trace from {source_ip} to {dest_ip}:{port} '
                   f'- {len(hops)} hops, {round(total_latency, 1)}ms total'
                   f' - Port {"OPEN" if port_open else "CLOSED/FILTERED"}',
    }


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
