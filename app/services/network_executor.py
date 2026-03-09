"""
Real network command execution service.
Executes whitelisted network commands safely on the host machine.
Designed for Windows with cross-platform fallbacks.
"""
import subprocess
import shlex
import re
import platform
import socket
import struct
import time

# Maximum execution time per command (seconds)
COMMAND_TIMEOUT = 30

# Whitelisted commands and their Windows equivalents
ALLOWED_COMMANDS = {
    # Network diagnostics
    'ping': {'win': 'ping', 'args_required': True},
    'traceroute': {'win': 'tracert', 'args_required': True},
    'tracert': {'win': 'tracert', 'args_required': True},
    'nslookup': {'win': 'nslookup', 'args_required': False},
    'dig': {'win': 'nslookup', 'args_required': False},
    'pathping': {'win': 'pathping', 'args_required': True},

    # Network status
    'netstat': {'win': 'netstat', 'args_required': False},
    'ipconfig': {'win': 'ipconfig', 'args_required': False},
    'ifconfig': {'win': 'ipconfig', 'args_required': False},
    'arp': {'win': 'arp', 'args_required': False},
    'nbtstat': {'win': 'nbtstat', 'args_required': False},
    'hostname': {'win': 'hostname', 'args_required': False},
    'route': {'win': 'route', 'args_required': False},

    # PowerShell network commands (wrapped)
    'ss': {'win': 'powershell_ss', 'args_required': False},
    'ip': {'win': 'powershell_ip', 'args_required': False},

    # System info
    'whoami': {'win': 'whoami', 'args_required': False},
    'systeminfo': {'win': 'systeminfo', 'args_required': False},
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

    # Handle PowerShell-wrapped commands
    if cmd_info['win'].startswith('powershell_'):
        return _powershell_command(cmd_info['win'], args)

    # Handle dig -> nslookup translation
    if base_cmd == 'dig':
        return _execute_dig_as_nslookup(args)

    # Handle ifconfig -> ipconfig translation
    if base_cmd == 'ifconfig':
        return _run_process(['ipconfig', '/all'])

    # Handle ss -> netstat translation
    if base_cmd == 'ss':
        return _run_process(['netstat', '-an'])

    # Handle ip -> ipconfig translation
    if base_cmd == 'ip':
        if args and args[0] in ('addr', 'address', 'a'):
            return _run_process(['ipconfig', '/all'])
        elif args and args[0] in ('route', 'r'):
            return _run_process(['route', 'print'])
        elif args and args[0] == 'neigh':
            return _run_process(['arp', '-a'])
        return _run_process(['ipconfig', '/all'])

    # Build the actual command
    win_cmd = cmd_info['win']

    # Ping: limit to 4 packets on Windows by default
    if base_cmd == 'ping':
        if not args:
            return {'output': '', 'error': 'Usage: ping <host>', 'exit_code': 1, 'is_real': False}
        # If no -n flag specified, add -n 4
        if '-n' not in args and '-t' not in args:
            actual_args = ['-n', '4'] + args
        else:
            actual_args = args
        return _run_process([win_cmd] + actual_args)

    # Tracert: set max hops
    if base_cmd in ('traceroute', 'tracert'):
        if not args:
            return {'output': '', 'error': 'Usage: traceroute <host>', 'exit_code': 1, 'is_real': False}
        return _run_process([win_cmd] + args, timeout=60)

    # Netstat
    if base_cmd == 'netstat':
        if not args:
            actual_args = ['-an']
        else:
            actual_args = args
        return _run_process([win_cmd] + actual_args)

    # Route
    if base_cmd == 'route':
        if not args:
            actual_args = ['print']
        else:
            actual_args = args
        return _run_process([win_cmd] + actual_args)

    # ARP
    if base_cmd == 'arp':
        if not args:
            actual_args = ['-a']
        else:
            actual_args = args
        return _run_process([win_cmd] + actual_args)

    # Default execution
    return _run_process([win_cmd] + args)


def _run_process(cmd_list: list, timeout: int = COMMAND_TIMEOUT) -> dict:
    """Run a subprocess safely and return output."""
    try:
        # Filter out any empty strings
        cmd_list = [c for c in cmd_list if c]

        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # Never use shell=True for security
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0,
        )

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
    """Execute PowerShell-wrapped network commands."""
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
    # Check for record type flags
    record_type = None
    for i, arg in enumerate(args):
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
        return _run_process(['netstat', '-ano'])
    if cmd == 'interfaces':
        return _run_process(['ipconfig', '/all'])
    if cmd == 'listening':
        return _run_process(['netstat', '-an', '-p', 'tcp'])
    if cmd == 'whois':
        return _whois(args)
    if cmd == 'headers':
        return _http_headers(args)
    if cmd == 'resolve':
        return _resolve(args)
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
        3389: 'ms-wbt-server', 5432: 'postgresql', 5433: 'postgresql',
        5434: 'postgresql', 5900: 'vnc', 6379: 'redis', 8080: 'http-proxy',
        8443: 'https-alt', 8888: 'http-alt', 27017: 'mongodb',
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
    # Parse CIDR notation
    try:
        if '/' in subnet:
            base_ip, prefix = subnet.split('/')
            prefix = int(prefix)
        else:
            base_ip = subnet
            prefix = 24

        # Only allow /24 or smaller for safety
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
    # Scan .1 to .254
    for i in range(1, 255):
        ip = f'{base}.{i}'
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '500', ip],
                capture_output=True, text=True, timeout=2,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0,
            )
            if result.returncode == 0:
                hosts_up += 1
                # Try to resolve hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = ''

                # Extract latency
                latency = 'unknown'
                time_match = re.search(r'time[=<](\d+)ms', result.stdout)
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
        # Get all address info
        results = socket.getaddrinfo(target, None)
        seen = set()
        for family, stype, proto, canonname, sockaddr in results:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                family_name = 'IPv4' if family == socket.AF_INET else 'IPv6'
                output_lines.append(f'  {family_name}: {ip}')

        # Reverse lookup
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

    # Check if it's an IP address
    try:
        socket.inet_aton(target)
        # It's an IP, do reverse lookup
        try:
            hostname, aliases, addrs = socket.gethostbyaddr(target)
            output_lines.append(f'{target} -> {hostname}')
            if aliases:
                output_lines.append(f'Aliases: {", ".join(aliases)}')
        except socket.herror:
            output_lines.append(f'{target} -> (no reverse DNS)')
    except socket.error:
        # It's a hostname, do forward lookup
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
    """WHOIS lookup using PowerShell."""
    if not args:
        return {'output': 'Usage: whois <domain>', 'error': '', 'exit_code': 0, 'is_real': True}

    # Use nslookup as a basic alternative on Windows
    target = args[0]
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


def get_network_overview() -> dict:
    """Get a real-time overview of the network state for the dashboard."""
    overview = {}

    # Get interfaces
    try:
        result = subprocess.run(
            ['ipconfig', '/all'], capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0,
        )
        overview['interfaces_raw'] = result.stdout
        overview['interfaces'] = _parse_ipconfig(result.stdout)
    except Exception as e:
        overview['interfaces'] = []
        overview['interfaces_raw'] = str(e)

    # Get active connections
    try:
        result = subprocess.run(
            ['netstat', '-ano'], capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0,
        )
        overview['connections_raw'] = result.stdout
        overview['connections'] = _parse_netstat(result.stdout)
    except Exception as e:
        overview['connections'] = {'established': 0, 'listening': 0, 'time_wait': 0, 'close_wait': 0, 'total': 0}
        overview['connections_raw'] = str(e)

    # Get ARP table
    try:
        result = subprocess.run(
            ['arp', '-a'], capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0,
        )
        overview['arp_raw'] = result.stdout
        overview['arp_entries'] = _parse_arp(result.stdout)
    except Exception as e:
        overview['arp_entries'] = []
        overview['arp_raw'] = str(e)

    # Get routing table
    try:
        result = subprocess.run(
            ['route', 'print'], capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0,
        )
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
    """Parse ipconfig /all output into structured data."""
    interfaces = []
    current = None

    for line in text.split('\n'):
        line = line.rstrip()
        if not line:
            continue

        # New adapter section
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


def _parse_netstat(text: str) -> dict:
    """Parse netstat -ano output into connection counts."""
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

            # Collect first 50 entries for display
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


def _parse_arp(text: str) -> list:
    """Parse arp -a output into structured data."""
    entries = []
    for line in text.split('\n'):
        line = line.strip()
        # Match lines like: 192.168.1.1     00-aa-bb-cc-dd-ee     dynamic
        parts = line.split()
        if len(parts) >= 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
            entries.append({
                'ip': parts[0],
                'mac': parts[1],
                'type': parts[2] if len(parts) > 2 else 'unknown',
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
