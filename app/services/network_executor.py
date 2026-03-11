"""
Real network command execution service.
Executes whitelisted network commands safely on the host machine.
Cross-platform: works on both Windows and Linux (Render deployment).
"""
import subprocess
import re
import platform
import socket

IS_WINDOWS = platform.system() == 'Windows'

# Maximum execution time per command (seconds)
COMMAND_TIMEOUT = 30

# Whitelisted commands with platform-specific binaries
ALLOWED_COMMANDS = {
    # Network diagnostics
    'ping': {'win': 'ping', 'linux': 'ping', 'args_required': True},
    'traceroute': {'win': 'tracert', 'linux': 'traceroute', 'args_required': True},
    'tracert': {'win': 'tracert', 'linux': 'traceroute', 'args_required': True},
    'nslookup': {'win': 'nslookup', 'linux': 'nslookup', 'args_required': False},
    'dig': {'win': 'nslookup', 'linux': 'dig', 'args_required': False},
    'pathping': {'win': 'pathping', 'linux': 'mtr', 'args_required': True},

    # Network status
    'netstat': {'win': 'netstat', 'linux': 'ss', 'args_required': False},
    'ipconfig': {'win': 'ipconfig', 'linux': 'ip', 'args_required': False},
    'ifconfig': {'win': 'ipconfig', 'linux': 'ip', 'args_required': False},
    'arp': {'win': 'arp', 'linux': 'ip', 'args_required': False},
    'nbtstat': {'win': 'nbtstat', 'linux': 'nmblookup', 'args_required': False},
    'hostname': {'win': 'hostname', 'linux': 'hostname', 'args_required': False},
    'route': {'win': 'route', 'linux': 'ip', 'args_required': False},

    # Linux-native commands
    'ss': {'win': 'netstat', 'linux': 'ss', 'args_required': False},
    'ip': {'win': 'ipconfig', 'linux': 'ip', 'args_required': False},

    # System info
    'whoami': {'win': 'whoami', 'linux': 'whoami', 'args_required': False},
    'systeminfo': {'win': 'systeminfo', 'linux': 'uname', 'args_required': False},
}

# Dangerous patterns to block
BLOCKED_PATTERNS = [
    r'[;&|`$]',          # Command chaining/injection
    r'\.\.',             # Path traversal
    r'>(>)?',            # Output redirection
    r'<',                # Input redirection
    r'\\\\',             # UNC paths
    r'del\s',            # Delete commands
    r'rm\s',             # Remove commands
    r'format\s',         # Format commands
    r'shutdown',         # Shutdown
    r'restart',          # Restart
    r'reg\s',            # Registry
    r'net\s+user',       # User management
    r'net\s+localgroup', # Group management
    r'powershell.*-enc', # Encoded powershell
    r'cmd\s*/c',         # Cmd chaining
]


def _get_cmd(cmd_info: dict) -> str:
    """Get the platform-appropriate command binary."""
    return cmd_info['win'] if IS_WINDOWS else cmd_info['linux']


def is_safe_command(command: str) -> tuple[bool, str]:
    """Validate that a command is safe to execute."""
    if not command or not command.strip():
        return False, 'Empty command'

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f'Command contains blocked pattern for security'

    return True, ''


def execute_command(command: str, lab_id: str = '') -> dict:
    """
    Execute a whitelisted network command and return real output.
    Returns dict with 'output', 'error', 'exit_code', 'is_real'.
    """
    command = command.strip()
    if not command:
        return {'output': '', 'error': 'No command provided', 'exit_code': 1, 'is_real': False}

    # Handle built-in commands
    parts = command.split()
    base_cmd = parts[0].lower()
    args = parts[1:] if len(parts) > 1 else []

    # Safety check
    safe, reason = is_safe_command(command)
    if not safe:
        return {'output': '', 'error': f'Blocked: {reason}', 'exit_code': 1, 'is_real': False}

    # Handle special/built-in commands
    if base_cmd == 'help':
        return {'output': _get_help_text(), 'error': '', 'exit_code': 0, 'is_real': False}
    if base_cmd == 'clear':
        return {'output': '\033[2J\033[H', 'error': '', 'exit_code': 0, 'is_real': False}

    # Check if command is whitelisted
    if base_cmd not in ALLOWED_COMMANDS:
        # Try Python-based implementations
        result = _python_command(base_cmd, args)
        if result:
            return result
        return {
            'output': '',
            'error': f'Command "{base_cmd}" is not available. Type "help" for available commands.',
            'exit_code': 1,
            'is_real': False,
        }

    cmd_info = ALLOWED_COMMANDS[base_cmd]

    # Handle PowerShell-wrapped commands (Windows only)
    if IS_WINDOWS and _get_cmd(cmd_info).startswith('powershell_'):
        return _powershell_command(_get_cmd(cmd_info), args)

    # Handle dig
    if base_cmd == 'dig':
        if IS_WINDOWS:
            return _execute_dig_as_nslookup(args)
        else:
            return _run_process(['dig'] + args) if args else _run_process(['dig'])

    # Handle ifconfig / ipconfig
    if base_cmd == 'ifconfig':
        if IS_WINDOWS:
            return _run_process(['ipconfig', '/all'])
        else:
            return _run_process(['ip', 'addr'])

    # Handle ss
    if base_cmd == 'ss':
        if IS_WINDOWS:
            return _run_process(['netstat', '-an'])
        else:
            return _run_process(['ss', '-tuln'])

    # Handle ip command
    if base_cmd == 'ip':
        if IS_WINDOWS:
            if args and args[0] in ('addr', 'address', 'a'):
                return _run_process(['ipconfig', '/all'])
            elif args and args[0] in ('route', 'r'):
                return _run_process(['route', 'print'])
            elif args and args[0] == 'neigh':
                return _run_process(['arp', '-a'])
            return _run_process(['ipconfig', '/all'])
        else:
            return _run_process(['ip'] + (args if args else ['addr']))

    # Ping
    if base_cmd == 'ping':
        if not args:
            return {'output': '', 'error': 'Usage: ping <host>', 'exit_code': 1, 'is_real': False}
        if IS_WINDOWS:
            if '-n' not in args and '-t' not in args:
                actual_args = ['-n', '4'] + args
            else:
                actual_args = args
            return _run_process(['ping'] + actual_args)
        else:
            if '-c' not in args:
                actual_args = ['-c', '4'] + args
            else:
                actual_args = args
            return _run_process(['ping'] + actual_args)

    # Traceroute
    if base_cmd in ('traceroute', 'tracert'):
        if not args:
            return {'output': '', 'error': 'Usage: traceroute <host>', 'exit_code': 1, 'is_real': False}
        bin_cmd = 'tracert' if IS_WINDOWS else 'traceroute'
        return _run_process([bin_cmd] + args, timeout=60)

    # Netstat
    if base_cmd == 'netstat':
        if IS_WINDOWS:
            actual_args = args if args else ['-an']
            return _run_process(['netstat'] + actual_args)
        else:
            return _run_process(['ss', '-tuln'])

    # Route
    if base_cmd == 'route':
        if IS_WINDOWS:
            actual_args = args if args else ['print']
            return _run_process(['route'] + actual_args)
        else:
            return _run_process(['ip', 'route'])

    # ARP
    if base_cmd == 'arp':
        if IS_WINDOWS:
            actual_args = args if args else ['-a']
            return _run_process(['arp'] + actual_args)
        else:
            return _run_process(['ip', 'neigh'])

    # Systeminfo
    if base_cmd == 'systeminfo':
        if IS_WINDOWS:
            return _run_process(['systeminfo'])
        else:
            return _run_process(['uname', '-a'])

    # Pathping / mtr
    if base_cmd == 'pathping':
        if not args:
            return {'output': '', 'error': 'Usage: pathping <host>', 'exit_code': 1, 'is_real': False}
        if IS_WINDOWS:
            return _run_process(['pathping'] + args, timeout=60)
        else:
            return _run_process(['mtr', '--report', '--report-cycles', '3'] + args, timeout=60)

    # Default execution
    bin_cmd = _get_cmd(cmd_info)
    return _run_process([bin_cmd] + args)


def _run_process(cmd_list: list, timeout: int = COMMAND_TIMEOUT) -> dict:
    """Run a subprocess safely and return output."""
    try:
        # Filter out any empty strings
        cmd_list = [c for c in cmd_list if c]

        kwargs = {
            'capture_output': True,
            'text': True,
            'timeout': timeout,
            'shell': False,
        }
        if IS_WINDOWS:
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(cmd_list, **kwargs)

        output = result.stdout
        error = result.stderr

        # Combine output
        combined = output
        if error and not output:
            combined = error
        elif error:
            combined = output + '\n' + error

        return {
            'output': combined.strip(),
            'error': '' if result.returncode == 0 else error.strip(),
            'exit_code': result.returncode,
            'is_real': True,
        }

    except subprocess.TimeoutExpired:
        return {
            'output': f'Command timed out after {timeout}s',
            'error': 'timeout',
            'exit_code': 124,
            'is_real': True,
        }
    except FileNotFoundError:
        return {
            'output': '',
            'error': f'Command not found: {cmd_list[0]}',
            'exit_code': 127,
            'is_real': False,
        }
    except Exception as e:
        return {
            'output': '',
            'error': f'Execution error: {str(e)}',
            'exit_code': 1,
            'is_real': False,
        }


def _powershell_command(ps_type: str, args: list) -> dict:
    """Execute PowerShell-wrapped network commands (Windows only)."""
    if ps_type == 'powershell_ss':
        ps_cmd = 'Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | Format-Table -AutoSize'
        return _run_process(['powershell', '-NoProfile', '-Command', ps_cmd])

    if ps_type == 'powershell_ip':
        if args and args[0] in ('addr', 'a', 'address'):
            ps_cmd = 'Get-NetIPAddress | Format-Table InterfaceAlias,IPAddress,PrefixLength,AddressFamily -AutoSize'
        elif args and args[0] == 'route':
            ps_cmd = 'Get-NetRoute | Format-Table DestinationPrefix,NextHop,InterfaceAlias,RouteMetric -AutoSize'
        elif args and args[0] == 'neigh':
            ps_cmd = 'Get-NetNeighbor | Format-Table IPAddress,LinkLayerAddress,State,InterfaceAlias -AutoSize'
        else:
            ps_cmd = 'Get-NetIPAddress | Format-Table InterfaceAlias,IPAddress,PrefixLength,AddressFamily -AutoSize'
        return _run_process(['powershell', '-NoProfile', '-Command', ps_cmd])

    return {'output': '', 'error': 'Unknown PowerShell command', 'exit_code': 1, 'is_real': False}


def _execute_dig_as_nslookup(args: list) -> dict:
    """Translate dig command to nslookup on Windows."""
    if not args:
        return _run_process(['nslookup'])

    target = args[0]
    record_type = None
    for arg in args:
        if arg.upper() in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV'):
            record_type = arg.upper()

    cmd = ['nslookup']
    if record_type:
        cmd.extend(['-type=' + record_type, target])
    else:
        cmd.append(target)

    return _run_process(cmd)


def _python_command(cmd: str, args: list) -> dict | None:
    """Handle commands implemented in pure Python."""
    if cmd == 'portscan':
        return _portscan(args)
    if cmd == 'hostscan':
        return _hostscan(args)
    if cmd == 'dnslookup':
        return _dnslookup(args)
    if cmd == 'connections':
        if IS_WINDOWS:
            return _run_process(['netstat', '-ano'])
        else:
            return _run_process(['ss', '-tulnp'])
    if cmd == 'interfaces':
        if IS_WINDOWS:
            return _run_process(['ipconfig', '/all'])
        else:
            return _run_process(['ip', 'addr'])
    if cmd == 'listening':
        if IS_WINDOWS:
            return _run_process(['netstat', '-an', '-p', 'tcp'])
        else:
            return _run_process(['ss', '-tln'])
    if cmd == 'whois':
        return _whois(args)
    if cmd == 'headers':
        return _http_headers(args)
    if cmd == 'resolve':
        return _resolve(args)
    if cmd == 'banner':
        return _banner_grab(args)
    if cmd in ('sslscan', 'tlsscan', 'sslcheck'):
        return _ssl_scan(args)
    if cmd in ('detect', 'fingerprint', 'svcdetect'):
        return _service_detect(args)
    if cmd in ('capture', 'sniff', 'tcpdump'):
        return _packet_capture(args)
    if cmd in ('vuln', 'vulnscan'):
        return _vuln_scan(args)
    if cmd == 'flood-detect':
        return _flood_detect(args)
    if cmd in ('ioc', 'threatcheck'):
        return _ioc_check(args)
    return None


def _portscan(args: list) -> dict:
    """Python-based port scanner for a target host."""
    if not args:
        return {
            'output': 'Usage: portscan <host> [start_port] [end_port]\nExample: portscan 192.168.1.1 1 1024',
            'error': '', 'exit_code': 0, 'is_real': True,
        }

    target = args[0]
    start_port = int(args[1]) if len(args) > 1 else 1
    end_port = int(args[2]) if len(args) > 2 else 1024

    # Limit range for safety
    if end_port - start_port > 1024:
        end_port = start_port + 1024

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {'output': '', 'error': f'Cannot resolve host: {target}', 'exit_code': 1, 'is_real': True}

    output_lines = [
        f'Port Scan Report for {target} ({target_ip})',
        f'Scanning ports {start_port}-{end_port}...',
        '',
        f'{"PORT":<12}{"STATE":<12}{"SERVICE":<20}',
        '-' * 44,
    ]

    open_ports = []
    common_services = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'dns', 80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios-ssn',
        143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps',
        995: 'pop3s', 1433: 'ms-sql', 1521: 'oracle', 3306: 'mysql',
        3389: 'ms-wbt-server', 5432: 'postgresql', 5900: 'vnc',
        6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
        8888: 'http-alt', 27017: 'mongodb',
    }

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            if result == 0:
                service = common_services.get(port, 'unknown')
                open_ports.append(port)
                output_lines.append(f'{port}/tcp      open        {service}')
        except Exception:
            pass

    output_lines.append('')
    output_lines.append(f'Scan complete: {len(open_ports)} open port(s) found on {target_ip}')

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _hostscan(args: list) -> dict:
    """Scan a subnet for live hosts using ICMP ping."""
    if not args:
        return {
            'output': 'Usage: hostscan <subnet>\nExample: hostscan 192.168.1.0/24',
            'error': '', 'exit_code': 0, 'is_real': True,
        }

    subnet = args[0]
    try:
        if '/' in subnet:
            base_ip, prefix = subnet.split('/')
            prefix = int(prefix)
        else:
            base_ip = subnet
            prefix = 24

        if prefix < 24:
            prefix = 24

        parts = base_ip.split('.')
        base = '.'.join(parts[:3])
    except Exception:
        return {'output': '', 'error': f'Invalid subnet: {subnet}', 'exit_code': 1, 'is_real': True}

    output_lines = [
        f'Host Discovery Scan for {base}.0/{prefix}',
        'Scanning...',
        '',
        f'{"HOST":<20}{"STATUS":<12}{"LATENCY":<15}{"HOSTNAME":<30}',
        '-' * 77,
    ]

    hosts_up = 0
    for i in range(1, 255):
        ip = f'{base}.{i}'
        try:
            if IS_WINDOWS:
                ping_cmd = ['ping', '-n', '1', '-w', '500', ip]
            else:
                ping_cmd = ['ping', '-c', '1', '-W', '1', ip]

            kwargs = {
                'capture_output': True, 'text': True, 'timeout': 2,
            }
            if IS_WINDOWS:
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(ping_cmd, **kwargs)
            if result.returncode == 0:
                hosts_up += 1
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = ''

                latency = 'unknown'
                time_match = re.search(r'time[=<](\d+\.?\d*)(\s?)ms', result.stdout)
                if time_match:
                    latency = f'{time_match.group(1)}ms'

                output_lines.append(f'{ip:<20}{"UP":<12}{latency:<15}{hostname:<30}')
        except Exception:
            pass

    output_lines.append('')
    output_lines.append(f'Scan complete: {hosts_up} host(s) up out of 254 scanned')

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _dnslookup(args: list) -> dict:
    """Pure Python DNS resolution."""
    if not args:
        return {
            'output': 'Usage: dnslookup <hostname>',
            'error': '', 'exit_code': 0, 'is_real': True,
        }

    target = args[0]
    output_lines = [f'DNS Lookup for {target}', '']

    try:
        results = socket.getaddrinfo(target, None)
        seen = set()
        for family, stype, proto, canonname, sockaddr in results:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                family_name = 'IPv4' if family == socket.AF_INET else 'IPv6'
                output_lines.append(f'  {family_name}: {ip}')

        try:
            hostname = socket.gethostbyaddr(list(seen)[0])[0]
            output_lines.append(f'\n  Reverse DNS: {hostname}')
        except Exception:
            pass

    except socket.gaierror as e:
        return {'output': '', 'error': f'DNS resolution failed: {str(e)}', 'exit_code': 1, 'is_real': True}

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _resolve(args: list) -> dict:
    """Resolve hostname to IP and vice versa."""
    if not args:
        return {'output': 'Usage: resolve <hostname_or_ip>', 'error': '', 'exit_code': 0, 'is_real': True}

    target = args[0]
    output_lines = []

    try:
        socket.inet_aton(target)
        try:
            hostname, aliases, addrs = socket.gethostbyaddr(target)
            output_lines.append(f'{target} -> {hostname}')
            if aliases:
                output_lines.append(f'Aliases: {", ".join(aliases)}')
        except socket.herror:
            output_lines.append(f'{target} -> (no reverse DNS)')
    except socket.error:
        try:
            ip = socket.gethostbyname(target)
            output_lines.append(f'{target} -> {ip}')
        except socket.gaierror as e:
            return {'output': '', 'error': f'Cannot resolve: {str(e)}', 'exit_code': 1, 'is_real': True}

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _http_headers(args: list) -> dict:
    """Fetch HTTP headers from a target URL."""
    if not args:
        return {'output': 'Usage: headers <url>\nExample: headers http://example.com', 'error': '', 'exit_code': 0, 'is_real': True}

    url = args[0]
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    return _run_process(['curl', '-sI', '--max-time', '10', url])


def _whois(args: list) -> dict:
    """WHOIS lookup."""
    if not args:
        return {'output': 'Usage: whois <domain>', 'error': '', 'exit_code': 0, 'is_real': True}

    target = args[0]

    # On Linux, try native whois command first
    if not IS_WINDOWS:
        result = _run_process(['whois', target])
        if result['exit_code'] == 0:
            return result

    # Fallback: Python-based DNS info
    output_lines = [f'Domain Information for {target}', '']
    try:
        ip = socket.gethostbyname(target)
        output_lines.append(f'  Resolved IP: {ip}')
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            output_lines.append(f'  Reverse DNS: {hostname}')
        except Exception:
            pass
    except socket.gaierror:
        output_lines.append(f'  Could not resolve {target}')

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _banner_grab(args: list) -> dict:
    """Connect to a port and grab the service banner."""
    if not args:
        return {
            'output': 'Usage: banner <host> <port>\nExample: banner 192.168.1.1 22',
            'error': '', 'exit_code': 0, 'is_real': True,
        }

    target = args[0]
    port = int(args[1]) if len(args) > 1 else 80

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {'output': '', 'error': f'Cannot resolve host: {target}', 'exit_code': 1, 'is_real': True}

    output_lines = [
        f'Banner Grab Report for {target} ({target_ip}):{port}',
        '-' * 50,
        '',
    ]

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_ip, port))

        # For HTTP ports, send a request
        if port in (80, 8080, 8888, 8443, 3000, 5000):
            sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\nConnection: close\r\n\r\n')
        elif port == 25 or port == 587:
            pass  # SMTP sends banner on connect
        elif port == 21:
            pass  # FTP sends banner on connect
        else:
            # Generic: send newline to trigger banner
            sock.send(b'\r\n')

        banner = sock.recv(4096).decode('utf-8', errors='replace').strip()
        sock.close()

        if banner:
            output_lines.append(f'Banner received ({len(banner)} bytes):')
            output_lines.append('')
            for line in banner.split('\n')[:20]:
                output_lines.append(f'  {line.rstrip()}')

            # Try to identify the service
            service_id = _identify_service(banner, port)
            if service_id:
                output_lines.append('')
                output_lines.append(f'Identified service: {service_id}')
        else:
            output_lines.append('No banner received (port is open but silent).')

    except socket.timeout:
        output_lines.append('Connection timed out. Port may be filtered or service does not send banner.')
    except ConnectionRefusedError:
        output_lines.append(f'Connection refused on port {port}. Port is closed.')
    except Exception as e:
        output_lines.append(f'Error: {str(e)}')

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _identify_service(banner: str, port: int) -> str:
    """Identify a service from its banner string."""
    banner_lower = banner.lower()
    patterns = [
        ('SSH', 'ssh'),
        ('OpenSSH', 'OpenSSH'),
        ('Apache', 'Apache HTTP Server'),
        ('nginx', 'nginx'),
        ('Microsoft-IIS', 'Microsoft IIS'),
        ('220', 'FTP' if port in (21, 2121) else None),
        ('SMTP', 'SMTP Mail Server'),
        ('Postfix', 'Postfix SMTP'),
        ('MySQL', 'MySQL Database'),
        ('MariaDB', 'MariaDB Database'),
        ('PostgreSQL', 'PostgreSQL Database'),
        ('Redis', 'Redis Key-Value Store'),
        ('MongoDB', 'MongoDB'),
        ('HTTP/1.', 'HTTP Server'),
        ('HTTP/2', 'HTTP/2 Server'),
        ('220-', 'FTP Server'),
        ('IMAP', 'IMAP Mail Server'),
        ('POP3', 'POP3 Mail Server'),
        ('+OK', 'POP3 Mail Server'),
        ('* OK', 'IMAP Server'),
    ]
    for pattern, name in patterns:
        if name and pattern.lower() in banner_lower:
            return name
    return ''


def _ssl_scan(args: list) -> dict:
    """Scan SSL/TLS configuration of a target host."""
    import ssl

    if not args:
        return {
            'output': 'Usage: sslscan <host> [port]\nExample: sslscan google.com 443',
            'error': '', 'exit_code': 0, 'is_real': True,
        }

    target = args[0]
    port = int(args[1]) if len(args) > 1 else 443

    output_lines = [
        f'SSL/TLS Scan Report for {target}:{port}',
        '=' * 55,
        '',
    ]

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, port), timeout=10) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                version = ssock.version()

                output_lines.append(f'  Protocol: {version}')
                if cipher:
                    output_lines.append(f'  Cipher:   {cipher[0]}')
                    output_lines.append(f'  Bits:     {cipher[2]}')
                output_lines.append('')

                # Certificate info
                output_lines.append('Certificate Information:')
                output_lines.append('-' * 40)

                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))

                    output_lines.append(f'  Subject:     {subject.get("commonName", "N/A")}')
                    output_lines.append(f'  Issuer:      {issuer.get("commonName", "N/A")}')
                    output_lines.append(f'  Org:         {issuer.get("organizationName", "N/A")}')
                    output_lines.append(f'  Not Before:  {cert.get("notBefore", "N/A")}')
                    output_lines.append(f'  Not After:   {cert.get("notAfter", "N/A")}')
                    output_lines.append(f'  Serial:      {cert.get("serialNumber", "N/A")}')

                    # SANs
                    sans = cert.get('subjectAltName', [])
                    if sans:
                        output_lines.append(f'  SANs:        {", ".join(v for _, v in sans[:10])}')
                        if len(sans) > 10:
                            output_lines.append(f'               ... and {len(sans) - 10} more')
                else:
                    output_lines.append('  (No certificate details available)')

                # Security assessment
                output_lines.append('')
                output_lines.append('Security Assessment:')
                output_lines.append('-' * 40)

                issues = []
                if version in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
                    issues.append(f'  [CRITICAL] Outdated protocol: {version}')
                if cipher and cipher[2] < 128:
                    issues.append(f'  [HIGH] Weak cipher: {cipher[2]}-bit')
                if cert:
                    from datetime import datetime
                    try:
                        not_after = datetime.strptime(cert.get('notAfter', ''), '%b %d %H:%M:%S %Y %Z')
                        if not_after < datetime.utcnow():
                            issues.append('  [CRITICAL] Certificate has EXPIRED')
                        elif (not_after - datetime.utcnow()).days < 30:
                            issues.append(f'  [WARNING] Certificate expires in {(not_after - datetime.utcnow()).days} days')
                    except (ValueError, TypeError):
                        pass

                if issues:
                    for issue in issues:
                        output_lines.append(issue)
                else:
                    output_lines.append('  [OK] No major issues detected')

    except ssl.SSLError as e:
        output_lines.append(f'  SSL Error: {str(e)}')
    except socket.timeout:
        output_lines.append('  Connection timed out.')
    except ConnectionRefusedError:
        output_lines.append(f'  Connection refused on port {port}.')
    except Exception as e:
        output_lines.append(f'  Error: {str(e)}')

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _service_detect(args: list) -> dict:
    """Detect services running on open ports with banner grabbing and version detection."""
    if not args:
        return {
            'output': 'Usage: detect <host> [start_port] [end_port]\nExample: detect 192.168.1.1 1 100',
            'error': '', 'exit_code': 0, 'is_real': True,
        }

    target = args[0]
    start_port = int(args[1]) if len(args) > 1 else 1
    end_port = int(args[2]) if len(args) > 2 else 1024

    if end_port - start_port > 512:
        end_port = start_port + 512

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {'output': '', 'error': f'Cannot resolve host: {target}', 'exit_code': 1, 'is_real': True}

    output_lines = [
        f'Service Detection Report for {target} ({target_ip})',
        f'Scanning ports {start_port}-{end_port} with version detection...',
        '',
        f'{"PORT":<10}{"STATE":<10}{"SERVICE":<18}{"VERSION":<35}',
        '-' * 73,
    ]

    common_services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
        993: 'imaps', 995: 'pop3s', 3306: 'mysql', 3389: 'rdp',
        5432: 'postgresql', 6379: 'redis', 8080: 'http-proxy', 27017: 'mongodb',
    }

    found = 0
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                found += 1
                service = common_services.get(port, 'unknown')

                # Try to grab banner for version
                version = ''
                try:
                    if port in (80, 8080, 8888):
                        sock.send(b'HEAD / HTTP/1.0\r\nHost: ' + target.encode() + b'\r\n\r\n')
                    else:
                        sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
                    if banner:
                        identified = _identify_service(banner, port)
                        if identified:
                            service = identified.lower()
                        # Extract version from banner
                        version = banner.split('\n')[0][:35].strip()
                except Exception:
                    pass

                output_lines.append(f'{port}/tcp    open      {service:<18}{version}')
            sock.close()
        except Exception:
            pass

    output_lines.append('')
    output_lines.append(f'Detection complete: {found} service(s) identified on {target_ip}')

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _packet_capture(args: list) -> dict:
    """Capture and display current network connections with details (packet-capture-like view)."""
    output_lines = [
        'Network Packet Capture (Connection Monitor)',
        '=' * 70,
        '',
        'Capturing active connections and traffic statistics...',
        '',
    ]

    # Get current connections
    if IS_WINDOWS:
        result = _run_process(['netstat', '-ano'])
    else:
        result = _run_process(['ss', '-tupn'])

    if result['exit_code'] != 0:
        return result

    raw_output = result['output']
    lines = raw_output.strip().split('\n')

    # Parse and categorize connections
    established = []
    listening = []
    other = []

    for line in lines:
        if 'ESTABLISHED' in line or 'ESTAB' in line:
            established.append(line.strip())
        elif 'LISTEN' in line:
            listening.append(line.strip())
        elif any(s in line for s in ('TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT')):
            other.append(line.strip())

    output_lines.append(f'--- ESTABLISHED CONNECTIONS ({len(established)}) ---')
    output_lines.append('')
    for conn in established[:30]:
        output_lines.append(f'  {conn}')
    if len(established) > 30:
        output_lines.append(f'  ... and {len(established) - 30} more')

    output_lines.append('')
    output_lines.append(f'--- LISTENING SERVICES ({len(listening)}) ---')
    output_lines.append('')
    for conn in listening[:20]:
        output_lines.append(f'  {conn}')

    if other:
        output_lines.append('')
        output_lines.append(f'--- OTHER STATES ({len(other)}) ---')
        output_lines.append('')
        for conn in other[:15]:
            output_lines.append(f'  {conn}')

    output_lines.append('')
    output_lines.append('-' * 70)
    output_lines.append(f'Summary: {len(established)} established, {len(listening)} listening, {len(other)} other')
    output_lines.append(f'Total captured: {len(established) + len(listening) + len(other)} connections')

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _vuln_scan(args: list) -> dict:
    """Basic vulnerability scanner - checks for common security issues."""
    import ssl

    if not args:
        return {
            'output': 'Usage: vulnscan <host> [port]\nExample: vulnscan example.com 443',
            'error': '', 'exit_code': 0, 'is_real': True,
        }

    target = args[0]
    port = int(args[1]) if len(args) > 1 else None

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {'output': '', 'error': f'Cannot resolve host: {target}', 'exit_code': 1, 'is_real': True}

    output_lines = [
        f'Vulnerability Scan Report for {target} ({target_ip})',
        '=' * 60,
        '',
    ]

    vulns_found = 0

    # Check common vulnerable ports
    vuln_ports = {
        21: ('FTP', 'Anonymous login, clear-text credentials'),
        23: ('Telnet', 'Unencrypted remote access'),
        25: ('SMTP', 'Open relay, email spoofing'),
        80: ('HTTP', 'Unencrypted web traffic'),
        135: ('MSRPC', 'Windows RPC exploitation'),
        139: ('NetBIOS', 'SMB enumeration, EternalBlue'),
        445: ('SMB', 'EternalBlue (MS17-010), SMB signing disabled'),
        1433: ('MSSQL', 'SQL injection, weak credentials'),
        3306: ('MySQL', 'Authentication bypass, data exposure'),
        3389: ('RDP', 'BlueKeep (CVE-2019-0708), brute force'),
        5432: ('PostgreSQL', 'Weak authentication, data exposure'),
        5900: ('VNC', 'Weak/no authentication'),
        6379: ('Redis', 'Unauthenticated access, RCE'),
        8080: ('HTTP-Proxy', 'Open proxy, admin interfaces'),
        27017: ('MongoDB', 'No authentication, data exposure'),
    }

    ports_to_check = [port] if port else list(vuln_ports.keys())

    output_lines.append('Port Vulnerability Assessment:')
    output_lines.append('-' * 50)

    for p in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target_ip, p))
            sock.close()
            if result == 0:
                info = vuln_ports.get(p, ('Unknown', 'Unknown service'))
                output_lines.append(f'  [OPEN] {p}/tcp - {info[0]}')
                output_lines.append(f'         Risk: {info[1]}')
                vulns_found += 1
        except Exception:
            pass

    # Check SSL on 443
    if port in (None, 443):
        output_lines.append('')
        output_lines.append('SSL/TLS Assessment:')
        output_lines.append('-' * 50)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target_ip, 443), timeout=5) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=target) as ssock:
                    ver = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert(binary_form=False)

                    if ver in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
                        output_lines.append(f'  [VULN] Outdated TLS version: {ver}')
                        vulns_found += 1
                    else:
                        output_lines.append(f'  [OK]   TLS version: {ver}')

                    if cipher and cipher[2] < 128:
                        output_lines.append(f'  [VULN] Weak cipher: {cipher[0]} ({cipher[2]}-bit)')
                        vulns_found += 1
                    elif cipher:
                        output_lines.append(f'  [OK]   Cipher: {cipher[0]} ({cipher[2]}-bit)')

                    if cert:
                        from datetime import datetime
                        try:
                            not_after = datetime.strptime(cert.get('notAfter', ''), '%b %d %H:%M:%S %Y %Z')
                            if not_after < datetime.utcnow():
                                output_lines.append('  [VULN] Certificate EXPIRED')
                                vulns_found += 1
                            else:
                                days = (not_after - datetime.utcnow()).days
                                output_lines.append(f'  [OK]   Certificate valid for {days} days')
                        except (ValueError, TypeError):
                            pass
        except Exception:
            output_lines.append('  [INFO] SSL not available on port 443')

    # HTTP security headers check
    if port in (None, 80, 443, 8080):
        check_port = port or 80
        output_lines.append('')
        output_lines.append('HTTP Security Headers:')
        output_lines.append('-' * 50)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target_ip, check_port))
            sock.send(f'HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n'.encode())
            response = sock.recv(4096).decode('utf-8', errors='replace')
            sock.close()

            response_lower = response.lower()
            security_headers = {
                'strict-transport-security': 'HSTS',
                'x-content-type-options': 'X-Content-Type-Options',
                'x-frame-options': 'X-Frame-Options',
                'x-xss-protection': 'X-XSS-Protection',
                'content-security-policy': 'CSP',
                'referrer-policy': 'Referrer-Policy',
                'permissions-policy': 'Permissions-Policy',
            }
            for header, name in security_headers.items():
                if header in response_lower:
                    output_lines.append(f'  [OK]   {name}: Present')
                else:
                    output_lines.append(f'  [MISS] {name}: Missing')
                    vulns_found += 1
        except Exception:
            output_lines.append('  [INFO] Could not check HTTP headers')

    output_lines.append('')
    output_lines.append('=' * 60)
    severity = 'CRITICAL' if vulns_found > 5 else 'HIGH' if vulns_found > 3 else 'MEDIUM' if vulns_found > 0 else 'LOW'
    output_lines.append(f'Scan complete: {vulns_found} potential issue(s) found | Risk: {severity}')

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _flood_detect(args: list) -> dict:
    """Detect potential flood/DDoS by analyzing connection states."""
    output_lines = [
        'Flood/DDoS Detection Analysis',
        '=' * 55,
        '',
    ]

    # Get connection data
    if IS_WINDOWS:
        result = _run_process(['netstat', '-ano'])
    else:
        result = _run_process(['ss', '-tun'])

    if result['exit_code'] != 0:
        return result

    lines = result['output'].split('\n')

    # Count connection states
    states = {}
    remote_ips = {}
    for line in lines:
        parts = line.split()
        if len(parts) >= 4:
            state = parts[3].upper() if len(parts) > 3 else ''
            states[state] = states.get(state, 0) + 1

            # Count by remote IP
            if len(parts) >= 3:
                remote = parts[2].rsplit(':', 1)[0] if ':' in parts[2] else parts[2]
                remote_ips[remote] = remote_ips.get(remote, 0) + 1

    output_lines.append('Connection State Analysis:')
    output_lines.append('-' * 40)
    for state, count in sorted(states.items(), key=lambda x: x[1], reverse=True):
        if state and count > 0:
            flag = ' [!]' if (state == 'SYN_RECV' and count > 20) or (state == 'TIME_WAIT' and count > 100) else ''
            output_lines.append(f'  {state:<20} {count:>6}{flag}')

    # Detect anomalies
    output_lines.append('')
    output_lines.append('Threat Assessment:')
    output_lines.append('-' * 40)

    alerts = []
    syn_recv = states.get('SYN_RECV', states.get('SYN-RECV', 0))
    time_wait = states.get('TIME_WAIT', states.get('TIME-WAIT', 0))
    total = sum(states.values())

    if syn_recv > 20:
        alerts.append(f'  [CRITICAL] SYN flood detected: {syn_recv} half-open connections')
    if time_wait > 100:
        alerts.append(f'  [WARNING]  High TIME_WAIT count: {time_wait} (possible flood aftermath)')

    # Check for single IP with many connections
    for ip, count in sorted(remote_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
        if count > 50 and ip not in ('0.0.0.0', '*', '[::]', '127.0.0.1'):
            alerts.append(f'  [HIGH]     Suspicious: {ip} has {count} connections')

    if alerts:
        for alert in alerts:
            output_lines.append(alert)
    else:
        output_lines.append('  [OK] No flood indicators detected')

    # Top remote IPs
    output_lines.append('')
    output_lines.append('Top Remote IPs by Connection Count:')
    output_lines.append('-' * 40)
    for ip, count in sorted(remote_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
        if ip and ip not in ('0.0.0.0', '*', '[::]'):
            output_lines.append(f'  {ip:<35} {count:>5}')

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _ioc_check(args: list) -> dict:
    """Check an IP/domain against built-in threat intelligence."""
    if not args:
        return {
            'output': 'Usage: ioc <ip_or_domain>\nExample: ioc 185.234.67.12',
            'error': '', 'exit_code': 0, 'is_real': True,
        }

    target = args[0]

    known_threats = {
        '185.234.67.12': 'C2 Server (APT28)',
        '103.45.78.200': 'Known Scanner (Shodan-like)',
        '91.240.118.50': 'Botnet C2 (Mirai variant)',
        '45.33.32.156': 'Penetration Testing IP (scanme.nmap.org)',
        '203.0.113.42': 'Exploit Kit Host',
        '177.54.123.89': 'Brute Force Operator',
        '196.52.43.88': 'Reconnaissance Scanner',
    }

    output_lines = [
        f'Threat Intelligence Check for: {target}',
        '=' * 50,
        '',
    ]

    # Resolve if domain
    resolved_ip = target
    try:
        resolved_ip = socket.gethostbyname(target)
        if resolved_ip != target:
            output_lines.append(f'  Resolved: {target} -> {resolved_ip}')
            output_lines.append('')
    except socket.gaierror:
        pass

    # Check against known threats
    if target in known_threats or resolved_ip in known_threats:
        threat = known_threats.get(target, known_threats.get(resolved_ip, ''))
        output_lines.append(f'  [THREAT FOUND]')
        output_lines.append(f'  Indicator: {target}')
        output_lines.append(f'  Classification: {threat}')
        output_lines.append(f'  Recommendation: BLOCK immediately and investigate')
    else:
        output_lines.append(f'  [CLEAN] No threat intelligence matches found')
        output_lines.append(f'  Note: Checked against built-in threat feeds')

    # Reverse DNS info
    try:
        hostname = socket.gethostbyaddr(resolved_ip)[0]
        output_lines.append(f'')
        output_lines.append(f'  Reverse DNS: {hostname}')
    except Exception:
        pass

    return {'output': '\n'.join(output_lines), 'error': '', 'exit_code': 0, 'is_real': True}


def _get_help_text() -> str:
    """Generate help text for available commands."""
    return """Available Commands:
  Network Diagnostics:
    ping <host>              - Send ICMP echo requests
    traceroute <host>        - Trace route to host
    nslookup <host>          - DNS lookup
    dnslookup <host>         - DNS resolution (Python-based)
    pathping <host>          - Path ping / MTR

  Network Status:
    netstat                  - Show network connections
    ipconfig / ifconfig      - Show network interfaces
    arp                      - Show ARP table
    route                    - Show routing table
    hostname                 - Show hostname
    ss                       - Socket statistics
    ip [addr|route|neigh]    - IP configuration
    capture / sniff          - Capture and analyze live connections

  Scanning & Detection:
    portscan <host> [start] [end]  - Scan ports on a host
    hostscan <subnet>              - Discover live hosts
    detect <host> [start] [end]    - Service version detection (like nmap -sV)
    banner <host> <port>           - Grab service banner from a port
    vulnscan <host> [port]         - Vulnerability assessment scan

  SSL/TLS Analysis:
    sslscan <host> [port]    - SSL/TLS certificate and cipher analysis

  Threat Intelligence:
    ioc <ip_or_domain>       - Check against threat intelligence feeds
    flood-detect             - Detect SYN flood / DDoS indicators

  Reconnaissance:
    headers <url>            - Fetch HTTP headers
    whois <domain>           - Domain information
    resolve <host_or_ip>     - Forward/reverse DNS lookup

  System:
    whoami                   - Current user
    systeminfo               - System information

  Utilities:
    help                     - Show this help
    clear                    - Clear terminal"""


def get_network_overview() -> dict:
    """Get a real-time overview of the network state for the dashboard."""
    overview = {}

    # Get interfaces
    try:
        if IS_WINDOWS:
            cmd = ['ipconfig', '/all']
        else:
            cmd = ['ip', 'addr']

        kwargs = {'capture_output': True, 'text': True, 'timeout': 10}
        if IS_WINDOWS:
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(cmd, **kwargs)
        overview['interfaces_raw'] = result.stdout
        if IS_WINDOWS:
            overview['interfaces'] = _parse_ipconfig(result.stdout)
        else:
            overview['interfaces'] = _parse_ip_addr(result.stdout)
    except Exception as e:
        overview['interfaces'] = []
        overview['interfaces_raw'] = str(e)

    # Get active connections
    try:
        if IS_WINDOWS:
            cmd = ['netstat', '-ano']
        else:
            cmd = ['ss', '-tuln']

        kwargs = {'capture_output': True, 'text': True, 'timeout': 10}
        if IS_WINDOWS:
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(cmd, **kwargs)
        overview['connections_raw'] = result.stdout
        if IS_WINDOWS:
            overview['connections'] = _parse_netstat(result.stdout)
        else:
            overview['connections'] = _parse_ss(result.stdout)
    except Exception as e:
        overview['connections'] = {'established': 0, 'listening': 0, 'time_wait': 0, 'close_wait': 0, 'total': 0}
        overview['connections_raw'] = str(e)

    # Get ARP table
    try:
        if IS_WINDOWS:
            cmd = ['arp', '-a']
        else:
            cmd = ['ip', 'neigh']

        kwargs = {'capture_output': True, 'text': True, 'timeout': 10}
        if IS_WINDOWS:
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(cmd, **kwargs)
        overview['arp_raw'] = result.stdout
        overview['arp_entries'] = _parse_arp(result.stdout)
    except Exception as e:
        overview['arp_entries'] = []
        overview['arp_raw'] = str(e)

    # Get routing table
    try:
        if IS_WINDOWS:
            cmd = ['route', 'print']
        else:
            cmd = ['ip', 'route']

        kwargs = {'capture_output': True, 'text': True, 'timeout': 10}
        if IS_WINDOWS:
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(cmd, **kwargs)
        overview['routes_raw'] = result.stdout
    except Exception:
        overview['routes_raw'] = ''

    # Get hostname
    overview['hostname'] = socket.gethostname()

    # Get local IPs
    try:
        overview['local_ips'] = _get_local_ips()
    except Exception:
        overview['local_ips'] = []

    return overview


def _parse_ipconfig(text: str) -> list:
    """Parse ipconfig /all output into structured data (Windows)."""
    interfaces = []
    current = None

    for line in text.split('\n'):
        line = line.rstrip()
        if not line:
            continue

        if not line.startswith(' ') and ':' in line and 'adapter' in line.lower():
            if current:
                interfaces.append(current)
            adapter_name = line.split('adapter')[-1].strip().rstrip(':')
            current = {'name': adapter_name, 'status': 'up', 'ipv4': '', 'ipv6': '', 'mac': '', 'gateway': '', 'dns': '', 'dhcp': ''}
        elif current and line.strip():
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip().rstrip('.')
                val = parts[1].strip()
                key_lower = key.lower()
                if 'ipv4' in key_lower:
                    current['ipv4'] = val.split('(')[0].strip()
                elif 'ipv6' in key_lower and 'link-local' not in key_lower:
                    current['ipv6'] = val.split('%')[0].strip()
                elif 'physical' in key_lower:
                    current['mac'] = val
                elif 'default gateway' in key_lower and val:
                    current['gateway'] = val
                elif 'dns servers' in key_lower and val:
                    current['dns'] = val
                elif 'dhcp enabled' in key_lower:
                    current['dhcp'] = val
                elif 'media state' in key_lower and 'disconnected' in val.lower():
                    current['status'] = 'down'

    if current:
        interfaces.append(current)

    return interfaces


def _parse_ip_addr(text: str) -> list:
    """Parse 'ip addr' output into structured data (Linux)."""
    interfaces = []
    current = None

    for line in text.split('\n'):
        # New interface: "2: eth0: <BROADCAST,..."
        match = re.match(r'^\d+:\s+(\S+):', line)
        if match:
            if current:
                interfaces.append(current)
            name = match.group(1)
            status = 'up' if 'UP' in line else 'down'
            current = {'name': name, 'status': status, 'ipv4': '', 'ipv6': '', 'mac': '', 'gateway': '', 'dns': '', 'dhcp': ''}
        elif current:
            line = line.strip()
            if line.startswith('inet '):
                ip = line.split()[1].split('/')[0]
                current['ipv4'] = ip
            elif line.startswith('inet6 '):
                ip = line.split()[1].split('/')[0]
                if not current['ipv6']:
                    current['ipv6'] = ip
            elif line.startswith('link/ether'):
                current['mac'] = line.split()[1]

    if current:
        interfaces.append(current)

    return interfaces


def _parse_netstat(text: str) -> dict:
    """Parse netstat -ano output into connection counts (Windows)."""
    counts = {'established': 0, 'listening': 0, 'time_wait': 0, 'close_wait': 0, 'total': 0, 'entries': []}

    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith('Active') or line.startswith('Proto'):
            continue

        parts = line.split()
        if len(parts) >= 4:
            state = parts[3].upper() if len(parts) > 3 else ''
            counts['total'] += 1

            if state == 'ESTABLISHED':
                counts['established'] += 1
            elif state == 'LISTENING':
                counts['listening'] += 1
            elif state == 'TIME_WAIT':
                counts['time_wait'] += 1
            elif state == 'CLOSE_WAIT':
                counts['close_wait'] += 1

            if len(counts['entries']) < 50:
                try:
                    entry = {
                        'proto': parts[0],
                        'local': parts[1],
                        'remote': parts[2],
                        'state': state,
                        'pid': parts[4] if len(parts) > 4 else '',
                    }
                    counts['entries'].append(entry)
                except IndexError:
                    pass

    return counts


def _parse_ss(text: str) -> dict:
    """Parse ss -tuln output into connection counts (Linux)."""
    counts = {'established': 0, 'listening': 0, 'time_wait': 0, 'close_wait': 0, 'total': 0, 'entries': []}

    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith('State') or line.startswith('Netid'):
            continue

        parts = line.split()
        if len(parts) >= 4:
            state = parts[0].upper() if parts[0] else ''
            counts['total'] += 1

            if state == 'ESTAB':
                counts['established'] += 1
            elif state == 'LISTEN':
                counts['listening'] += 1
            elif state == 'TIME-WAIT':
                counts['time_wait'] += 1
            elif state == 'CLOSE-WAIT':
                counts['close_wait'] += 1

            if len(counts['entries']) < 50:
                try:
                    entry = {
                        'proto': parts[0],
                        'local': parts[3] if len(parts) > 3 else '',
                        'remote': parts[4] if len(parts) > 4 else '',
                        'state': state,
                        'pid': '',
                    }
                    counts['entries'].append(entry)
                except IndexError:
                    pass

    return counts


def _parse_arp(text: str) -> list:
    """Parse arp output into structured data (cross-platform)."""
    entries = []
    for line in text.split('\n'):
        line = line.strip()
        parts = line.split()
        # Windows format: 192.168.1.1  00-aa-bb-cc-dd-ee  dynamic
        if len(parts) >= 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
            entries.append({
                'ip': parts[0],
                'mac': parts[1],
                'type': parts[2] if len(parts) > 2 else 'unknown',
            })
        # Linux 'ip neigh' format: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        elif len(parts) >= 5 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]) and 'lladdr' in parts:
            lladdr_idx = parts.index('lladdr')
            entries.append({
                'ip': parts[0],
                'mac': parts[lladdr_idx + 1] if lladdr_idx + 1 < len(parts) else 'unknown',
                'type': parts[-1] if parts[-1] in ('REACHABLE', 'STALE', 'DELAY', 'PROBE', 'FAILED') else 'unknown',
            })
    return entries


def _get_local_ips() -> list:
    """Get all local IP addresses."""
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip not in ips and not ip.startswith('::') and ip != '127.0.0.1':
                ips.append(ip)
    except Exception:
        pass
    return ips
