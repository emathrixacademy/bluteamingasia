import re
from flask import render_template, request, jsonify, redirect, url_for
from flask_login import login_required, current_user
from app.blueprints.missions import missions_bp
from app.models.mission import Mission, Challenge, UserMissionProgress, UserChallengeCompletion
from app.extensions import db


@missions_bp.route('/')
@login_required
def mission_list():
    """List all available missions."""
    missions = Mission.query.filter_by(is_active=True).order_by(Mission.order).all()

    # Get user progress for each mission
    progress_map = {}
    if current_user.is_authenticated:
        progresses = UserMissionProgress.query.filter_by(user_id=current_user.id).all()
        for p in progresses:
            progress_map[p.mission_id] = p

    # Get completed challenge counts
    completion_map = {}
    if current_user.is_authenticated:
        completions = UserChallengeCompletion.query.filter_by(user_id=current_user.id).all()
        for c in completions:
            ch = Challenge.query.get(c.challenge_id)
            if ch:
                mid = ch.mission_id
                completion_map.setdefault(mid, 0)
                completion_map[mid] += 1

    mission_data = []
    for m in missions:
        total = m.challenges.count()
        completed = completion_map.get(m.id, 0)
        progress = progress_map.get(m.id)
        mission_data.append({
            'mission': m,
            'total_challenges': total,
            'completed_challenges': completed,
            'progress': progress,
            'percent': round(completed / total * 100) if total > 0 else 0,
        })

    # Leaderboard
    top_users = db.session.query(
        UserMissionProgress.user_id,
        db.func.sum(UserMissionProgress.points_earned).label('total_points'),
        db.func.count(db.case((UserMissionProgress.status == 'completed', 1))).label('missions_done')
    ).group_by(UserMissionProgress.user_id)\
     .order_by(db.desc('total_points'))\
     .limit(10).all()

    from app.models.user import User
    leaderboard = []
    for uid, pts, done in top_users:
        u = User.query.get(uid)
        if u:
            leaderboard.append({'name': u.name, 'points': pts or 0, 'missions': done})

    # User total points
    my_points = 0
    if current_user.is_authenticated:
        result = db.session.query(db.func.sum(UserMissionProgress.points_earned))\
            .filter_by(user_id=current_user.id).scalar()
        my_points = result or 0

    return render_template('missions/list.html',
                           mission_data=mission_data,
                           leaderboard=leaderboard,
                           my_points=my_points)


@missions_bp.route('/<mission_id>')
@login_required
def mission_detail(mission_id):
    """View mission briefing and challenges."""
    mission = Mission.query.get_or_404(mission_id)
    challenges = mission.challenges.all()

    # Ensure progress record exists
    progress = UserMissionProgress.query.filter_by(
        user_id=current_user.id, mission_id=mission.id
    ).first()
    if not progress:
        progress = UserMissionProgress(user_id=current_user.id, mission_id=mission.id)
        db.session.add(progress)
        db.session.commit()

    # Get user completions
    completed_ids = set()
    completions = UserChallengeCompletion.query.filter_by(user_id=current_user.id).all()
    for c in completions:
        completed_ids.add(c.challenge_id)

    challenge_data = []
    for ch in challenges:
        is_done = ch.id in completed_ids
        # Determine if this challenge is unlocked (previous one completed, or it's the first)
        idx = challenge_data.__len__()
        is_unlocked = (idx == 0) or (len(challenge_data) > 0 and challenge_data[-1]['completed'])
        challenge_data.append({
            'challenge': ch,
            'completed': is_done,
            'unlocked': is_unlocked or is_done,
        })

    total = len(challenges)
    done = len(completed_ids.intersection(ch.id for ch in challenges))

    return render_template('missions/detail.html',
                           mission=mission,
                           challenge_data=challenge_data,
                           progress=progress,
                           total=total,
                           done=done)


@missions_bp.route('/<mission_id>/challenge/<challenge_id>')
@login_required
def play_challenge(mission_id, challenge_id):
    """Play a specific challenge."""
    mission = Mission.query.get_or_404(mission_id)
    challenge = Challenge.query.get_or_404(challenge_id)

    # Check already completed
    completion = UserChallengeCompletion.query.filter_by(
        user_id=current_user.id, challenge_id=challenge.id
    ).first()

    challenges = mission.challenges.all()
    current_idx = next((i for i, c in enumerate(challenges) if c.id == challenge.id), 0)
    next_challenge = challenges[current_idx + 1] if current_idx + 1 < len(challenges) else None
    prev_challenge = challenges[current_idx - 1] if current_idx > 0 else None

    return render_template('missions/play.html',
                           mission=mission,
                           challenge=challenge,
                           completion=completion,
                           current_idx=current_idx,
                           total=len(challenges),
                           next_challenge=next_challenge,
                           prev_challenge=prev_challenge)


@missions_bp.route('/api/submit', methods=['POST'])
@login_required
def submit_answer():
    """Submit an answer for a challenge."""
    data = request.get_json()
    challenge_id = data.get('challenge_id')
    answer = data.get('answer', '').strip()

    if not challenge_id or not answer:
        return jsonify({'correct': False, 'message': 'Answer required'}), 400

    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        return jsonify({'correct': False, 'message': 'Challenge not found'}), 404

    # Already completed?
    existing = UserChallengeCompletion.query.filter_by(
        user_id=current_user.id, challenge_id=challenge.id
    ).first()
    if existing:
        return jsonify({'correct': True, 'message': 'Already completed!', 'already': True})

    # Check answer
    correct = False
    if challenge.answer_is_regex:
        try:
            correct = bool(re.match(challenge.answer, answer, re.IGNORECASE))
        except re.error:
            correct = answer.lower() == challenge.answer.lower()
    else:
        correct = answer.lower().strip() == challenge.answer.lower().strip()

    if correct:
        # Record completion
        comp = UserChallengeCompletion(
            user_id=current_user.id,
            challenge_id=challenge.id,
            points_earned=challenge.points,
        )
        db.session.add(comp)

        # Update mission progress
        mission = challenge.mission
        progress = UserMissionProgress.query.filter_by(
            user_id=current_user.id, mission_id=mission.id
        ).first()
        if progress:
            progress.points_earned += challenge.points
            # Check if all challenges completed
            total = mission.challenges.count()
            done = UserChallengeCompletion.query.join(Challenge).filter(
                UserChallengeCompletion.user_id == current_user.id,
                Challenge.mission_id == mission.id
            ).count() + 1  # +1 for current
            if done >= total:
                progress.status = 'completed'
                from datetime import datetime
                progress.completed_at = datetime.utcnow()

        db.session.commit()

        return jsonify({
            'correct': True,
            'message': 'Correct! Well done.',
            'points': challenge.points,
            'explanation': challenge.explanation or '',
        })
    else:
        # Track attempts
        return jsonify({
            'correct': False,
            'message': 'Incorrect. Try again.',
        })


@missions_bp.route('/api/hint', methods=['POST'])
@login_required
def get_hint():
    """Get hint for a challenge."""
    data = request.get_json()
    challenge_id = data.get('challenge_id')
    challenge = Challenge.query.get(challenge_id)
    if not challenge or not challenge.hint:
        return jsonify({'hint': 'No hint available for this challenge.'})
    return jsonify({'hint': challenge.hint})


def seed_missions():
    """Seed the database with sample CTF missions."""
    if Mission.query.count() > 0:
        return

    # ─── Mission 1: Network Recon Basics ───
    m1 = Mission(
        title='Network Recon 101',
        description='Learn the fundamentals of network reconnaissance. Identify hosts, scan ports, and map network topology.',
        briefing='You have been assigned to the Blue Team at CyberShield Corp. Reports indicate suspicious traffic on the internal network. Your first task: understand the network layout before investigating further.',
        difficulty='beginner',
        category='network',
        icon='network',
        points_total=50,
        order=1,
    )
    db.session.add(m1)
    db.session.flush()

    challenges_m1 = [
        Challenge(mission_id=m1.id, order=1, title='What is an IP Address?',
                  description='An IP address uniquely identifies a device on a network. IPv4 addresses have 4 octets separated by dots.\n\nWhat is the default loopback IP address used to refer to "this machine"?',
                  task_type='text_answer', answer='127.0.0.1', points=10,
                  hint='It starts with 127 and is commonly called "localhost".',
                  explanation='127.0.0.1 is the IPv4 loopback address. Traffic sent to this address never leaves the machine — it loops back internally.'),
        Challenge(mission_id=m1.id, order=2, title='Common Ports',
                  description='Network services run on specific port numbers. Knowing common ports is essential for reconnaissance.\n\nWhat is the default port number for HTTPS (secure web traffic)?',
                  task_type='text_answer', answer='443', points=10,
                  hint='HTTP uses port 80. The secure version uses a different well-known port.',
                  explanation='HTTPS runs on port 443 by default. HTTP uses port 80, SSH uses 22, DNS uses 53, and FTP uses 21.'),
        Challenge(mission_id=m1.id, order=3, title='DNS Resolution',
                  description='DNS translates domain names to IP addresses. The command `nslookup` is used to query DNS.\n\nWhat type of DNS record maps a domain name to an IPv4 address?',
                  task_type='multiple_choice', answer='A',
                  choices=['A', 'AAAA', 'MX', 'CNAME'], points=10,
                  hint='It\'s a single letter representing "Address".',
                  explanation='An "A" record maps a domain to an IPv4 address. AAAA maps to IPv6. MX is for mail servers. CNAME is an alias.'),
        Challenge(mission_id=m1.id, order=4, title='Subnet Masks',
                  description='A subnet mask determines which part of an IP address is the network vs. host portion.\n\nHow many usable host addresses are in a /24 subnet (255.255.255.0)?',
                  task_type='text_answer', answer='254', points=10,
                  hint='A /24 has 256 total addresses. Subtract the network address and broadcast address.',
                  explanation='/24 = 256 addresses. Subtract 1 for network address (x.x.x.0) and 1 for broadcast (x.x.x.255) = 254 usable hosts.'),
        Challenge(mission_id=m1.id, order=5, title='Capture the Flag',
                  description='You\'ve learned the basics! Now find the hidden flag.\n\nDecode this Base64 string to find the flag:\n```\nQlRBe24zdHdvcmtfcmVjb25fbWFzdGVyfQ==\n```',
                  task_type='flag_submission', answer='BTA{n3twork_recon_master}', points=10,
                  hint='Use a Base64 decoder. The flag format is BTA{...}.',
                  explanation='Base64 decoding reveals: BTA{n3twork_recon_master}. Base64 is a common encoding (not encryption!) used to represent binary data as text.'),
    ]
    db.session.add_all(challenges_m1)

    # ─── Mission 2: Incident Response ───
    m2 = Mission(
        title='Incident Response: Phishing Attack',
        description='Investigate a phishing attack that compromised employee credentials. Analyze logs, identify the attacker, and contain the breach.',
        briefing='ALERT: The SOC has detected unusual login activity from multiple employee accounts at 3:47 AM. Email logs show a phishing campaign was sent 6 hours ago. You are the incident responder. Time is critical.',
        difficulty='intermediate',
        category='incident_response',
        icon='forensics',
        points_total=80,
        order=2,
    )
    db.session.add(m2)
    db.session.flush()

    challenges_m2 = [
        Challenge(mission_id=m2.id, order=1, title='Identify the Phishing Email',
                  description='Review the suspicious email header below:\n\n```\nFrom: IT-Support@cybersh1eld-corp.com\nTo: all-employees@cybershield-corp.com\nSubject: Urgent: Password Reset Required\nDate: Mon, 10 Mar 2026 21:30:00 +0000\nReply-To: hacker@evil-domain.xyz\n```\n\nWhat is the attacker\'s actual email domain found in the Reply-To header?',
                  task_type='text_answer', answer='evil-domain.xyz', points=15,
                  hint='Look at the Reply-To header, not the From header.',
                  explanation='The Reply-To header reveals the attacker\'s real email. The From address uses "cybersh1eld" (with a 1) to impersonate the legitimate "cybershield" domain — a classic typosquatting technique.'),
        Challenge(mission_id=m2.id, order=2, title='Analyze the Malicious URL',
                  description='The phishing email contains this link:\n```\nhttps://cybershield-corp.login-secure.evil-domain.xyz/reset?id=4829\n```\n\nWhat technique is the attacker using with the subdomain structure?',
                  task_type='multiple_choice', answer='Subdomain spoofing',
                  choices=['SQL Injection', 'Subdomain spoofing', 'DNS poisoning', 'ARP spoofing'], points=15,
                  hint='The legitimate domain name appears as a subdomain of the attacker\'s domain.',
                  explanation='The attacker uses subdomain spoofing — placing "cybershield-corp.login-secure" as subdomains of their malicious domain "evil-domain.xyz". Users see the familiar name and trust it.'),
        Challenge(mission_id=m2.id, order=3, title='Compromised Accounts',
                  description='Login logs show these failed/successful attempts from IP 185.243.115.42:\n\n```\n03:47:12 john.doe@cybershield-corp.com    LOGIN_SUCCESS  (normally logs in from 10.0.1.x)\n03:47:15 jane.smith@cybershield-corp.com  LOGIN_SUCCESS  (normally logs in from 10.0.2.x)\n03:47:18 bob.wilson@cybershield-corp.com  LOGIN_FAILED\n03:47:22 alice.chen@cybershield-corp.com  LOGIN_SUCCESS  (normally logs in from 10.0.1.x)\n03:48:01 admin@cybershield-corp.com       LOGIN_FAILED\n```\n\nHow many accounts were successfully compromised?',
                  task_type='text_answer', answer='3', points=15,
                  hint='Count only the LOGIN_SUCCESS entries.',
                  explanation='3 accounts were compromised: john.doe, jane.smith, and alice.chen. All successful logins came from an external IP (185.243.x.x) instead of internal IPs (10.0.x.x), confirming unauthorized access.'),
        Challenge(mission_id=m2.id, order=4, title='Containment Action',
                  description='You need to contain this breach immediately. Which of the following should be your FIRST action?',
                  task_type='multiple_choice', answer='Force password reset for compromised accounts and revoke active sessions',
                  choices=[
                      'Delete the phishing email from all mailboxes',
                      'Force password reset for compromised accounts and revoke active sessions',
                      'Block the attacker IP at the firewall',
                      'Send a company-wide email warning about the attack'
                  ], points=15,
                  hint='Think about what stops the attacker from using stolen credentials RIGHT NOW.',
                  explanation='First priority: revoke active sessions and force password resets to immediately cut off attacker access. Then block the IP, remove emails, and notify users. Containment before communication.'),
        Challenge(mission_id=m2.id, order=5, title='Incident Report Flag',
                  description='After your investigation, compile your findings.\n\nThe flag is the MD5 hash of the attacker\'s Reply-To email address. Use this to verify:\n\nMD5 of "hacker@evil-domain.xyz" = ?\n\nHint: `echo -n "hacker@evil-domain.xyz" | md5sum`\n\nThe flag format is: BTA{first_8_chars_of_md5}',
                  task_type='flag_submission', answer='BTA{5d5b71e4}', points=20,
                  hint='Calculate MD5 of "hacker@evil-domain.xyz". The full hash starts with 5d5b71e4.',
                  explanation='MD5("hacker@evil-domain.xyz") = 5d5b71e4... Flag: BTA{5d5b71e4}. In real IR, hashing IOCs helps with threat intelligence sharing without exposing raw indicators.'),
    ]
    db.session.add_all(challenges_m2)

    # ─── Mission 3: Log Analysis ───
    m3 = Mission(
        title='Log Analysis: Detecting the Insider',
        description='Analyze system and network logs to identify an insider threat exfiltrating sensitive data from the company.',
        briefing='The DLP (Data Loss Prevention) system flagged unusual file transfers at odd hours. Management suspects an insider threat. You have access to authentication logs, file access logs, and network flow data. Find the insider.',
        difficulty='intermediate',
        category='log_analysis',
        icon='forensics',
        points_total=70,
        order=3,
    )
    db.session.add(m3)
    db.session.flush()

    challenges_m3 = [
        Challenge(mission_id=m3.id, order=1, title='Suspicious Login Pattern',
                  description='Review authentication logs:\n\n```\n2026-03-08 02:14:00  user: mthompson  LOGIN  src: VPN-Gateway  status: SUCCESS\n2026-03-08 02:15:33  user: mthompson  ACCESS /finance/Q4-report.xlsx  status: READ\n2026-03-08 02:16:01  user: mthompson  ACCESS /hr/salary-data.csv      status: READ\n2026-03-08 02:17:45  user: mthompson  ACCESS /legal/merger-docs.pdf    status: READ\n2026-03-08 02:18:22  user: mthompson  USB_COPY 3 files (48.2 MB)      status: SUCCESS\n2026-03-08 02:19:00  user: mthompson  LOGOUT\n```\n\nWhat is the username of the suspicious user?',
                  task_type='text_answer', answer='mthompson', points=15,
                  hint='Look at who is accessing multiple sensitive departments at 2 AM.',
                  explanation='mthompson logged in via VPN at 2:14 AM, accessed files across Finance, HR, and Legal departments (unusual cross-department access), copied to USB, and logged out — all within 5 minutes. Classic insider exfiltration pattern.'),
        Challenge(mission_id=m3.id, order=2, title='Data Classification',
                  description='The files accessed were:\n- Q4-report.xlsx (Financial)\n- salary-data.csv (HR/PII)\n- merger-docs.pdf (Legal/Confidential)\n\nUnder most data classification policies, what is the highest classification level of these documents?',
                  task_type='multiple_choice', answer='Confidential',
                  choices=['Public', 'Internal', 'Confidential', 'Restricted'], points=15,
                  hint='Merger documents and salary data are typically classified as one of the higher levels.',
                  explanation='Merger documents are typically "Confidential" — their premature disclosure could impact stock prices and legal proceedings. Salary data is PII. Financial reports pre-release are also confidential.'),
        Challenge(mission_id=m3.id, order=3, title='Network Evidence',
                  description='NetFlow data shows:\n\n```\n2026-03-08 02:20:00  src:10.0.5.44  dst:185.100.87.33  port:443  bytes_out:52,428,800  protocol:TLS\n2026-03-08 02:20:45  src:10.0.5.44  dst:185.100.87.33  port:443  bytes_out:0           protocol:TLS (session end)\n```\n\n10.0.5.44 is mthompson\'s VPN-assigned IP. How many megabytes were uploaded to the external server?',
                  task_type='text_answer', answer='50', points=15,
                  answer_is_regex=True,
                  hint='Convert 52,428,800 bytes to megabytes (divide by 1,048,576).',
                  explanation='52,428,800 bytes = 50 MB exactly (52,428,800 / 1,048,576). This matches the ~48.2 MB of files copied to USB, plus protocol overhead. The data was uploaded to an external server over TLS.'),
        Challenge(mission_id=m3.id, order=4, title='Investigation Flag',
                  description='Based on your analysis, construct the flag using this format:\n\nBTA{username_department_count_method}\n\nWhere:\n- username = the insider\'s username\n- department_count = number of different departments accessed\n- method = exfiltration method (3 letters, lowercase)',
                  task_type='flag_submission', answer='BTA{mthompson_3_usb}', points=25,
                  hint='Username accessed Finance, HR, Legal departments. Copied to what device?',
                  explanation='BTA{mthompson_3_usb} — mthompson accessed 3 departments (Finance, HR, Legal) and exfiltrated data via USB drive before uploading externally.'),
    ]
    db.session.add_all(challenges_m3)

    # ─── Mission 4: Malware Analysis ───
    m4 = Mission(
        title='Malware Triage: Suspicious Executable',
        description='A suspicious file was found on a workstation. Analyze its properties, behavior indicators, and determine the threat level.',
        briefing='Workstation WS-0142 triggered an antivirus alert but the file wasn\'t quarantined. The file is named "invoice_march2026.pdf.exe". Your job: analyze without executing.',
        difficulty='advanced',
        category='malware',
        icon='malware',
        points_total=90,
        order=4,
    )
    db.session.add(m4)
    db.session.flush()

    challenges_m4 = [
        Challenge(mission_id=m4.id, order=1, title='File Extension Trick',
                  description='The file is named: `invoice_march2026.pdf.exe`\n\nWhat social engineering technique is being used with the filename?',
                  task_type='multiple_choice', answer='Double extension',
                  choices=['Double extension', 'Right-to-Left Override', 'Homograph attack', 'DLL sideloading'], points=15,
                  hint='The file appears to be a PDF but is actually an executable.',
                  explanation='Double extension attack: the file looks like a PDF to users who have "hide known file extensions" enabled in Windows. They see "invoice_march2026.pdf" but it\'s actually an .exe file.'),
        Challenge(mission_id=m4.id, order=2, title='Hash Analysis',
                  description='File hashes:\n```\nMD5:    e99a18c428cb38d5f260853678922e03\nSHA1:   6f1ed002ab5595859014ebf0951522d9e17d6bb0\nSHA256: 5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5\n```\n\nYou check VirusTotal and find 47/72 engines detect it. What category of detection ratio is this?',
                  task_type='multiple_choice', answer='High (known malware)',
                  choices=['Clean (false positive)', 'Low (potentially unwanted)', 'Medium (suspicious)', 'High (known malware)'], points=15,
                  hint='47 out of 72 is about 65% detection rate.',
                  explanation='47/72 (65%) is a very high detection rate — this is well-known malware. Low would be <10%, Medium 10-30%, High >30%. At 65%, this is clearly malicious and well-documented.'),
        Challenge(mission_id=m4.id, order=3, title='Behavioral Indicators',
                  description='Sandbox analysis shows these behaviors:\n\n```\n[+] Creates registry key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateSvc\n[+] Drops file: C:\\Users\\<user>\\AppData\\Local\\Temp\\svchost32.exe\n[+] Connects to: 45.33.32.156:4444\n[+] Executes: cmd.exe /c whoami && ipconfig && systeminfo\n[+] Modifies: Windows Defender exclusion path\n```\n\nThe registry key created under `CurrentVersion\\Run` achieves what objective?',
                  task_type='text_answer', answer='persistence', points=20,
                  answer_is_regex=True,
                  hint='Adding a program to the Run key makes it start automatically when...',
                  explanation='Registry Run keys provide persistence — the malware auto-starts every time the user logs in. This is one of the most common persistence mechanisms (MITRE ATT&CK: T1547.001).'),
        Challenge(mission_id=m4.id, order=4, title='C2 Communication',
                  description='The malware connects to 45.33.32.156 on port 4444.\n\nPort 4444 is the default port for which common penetration testing tool?',
                  task_type='multiple_choice', answer='Metasploit (Meterpreter)',
                  choices=['Nmap', 'Metasploit (Meterpreter)', 'Wireshark', 'Burp Suite'], points=20,
                  hint='This framework is the most widely used exploitation tool, and its default reverse shell uses this port.',
                  explanation='Port 4444 is the default port for Metasploit\'s Meterpreter reverse shell. Seeing this in malware strongly suggests the attacker used Metasploit to generate the payload.'),
        Challenge(mission_id=m4.id, order=5, title='MITRE ATT&CK Flag',
                  description='Map the malware behaviors to MITRE ATT&CK:\n\n1. Double extension filename → Initial Access\n2. Run key persistence → ?\n3. whoami/ipconfig → Discovery\n4. C2 connection → Command & Control\n\nWhat is the MITRE ATT&CK tactic name for behavior #2?\n\nFlag format: BTA{tactic_name_lowercase_with_underscores}',
                  task_type='flag_submission', answer='BTA{persistence}', points=20,
                  hint='The tactic is about maintaining access across reboots.',
                  explanation='Persistence (TA0003) ensures the attacker maintains access. The full kill chain here: Initial Access → Execution → Persistence → Discovery → C2.'),
    ]
    db.session.add_all(challenges_m4)

    # ─── Mission 5: Firewall Rules ───
    m5 = Mission(
        title='Firewall Fortress',
        description='Configure and audit firewall rules to protect a corporate network. Identify misconfigurations and block threats.',
        briefing='You\'re the new firewall administrator at TechSecure Inc. An audit revealed the previous admin left several misconfigurations. Fix the rules before the attackers exploit them.',
        difficulty='beginner',
        category='network',
        icon='firewall',
        points_total=60,
        order=5,
    )
    db.session.add(m5)
    db.session.flush()

    challenges_m5 = [
        Challenge(mission_id=m5.id, order=1, title='Default Deny',
                  description='What is the security principle that says a firewall should block all traffic by default, and only allow explicitly permitted traffic?',
                  task_type='multiple_choice', answer='Default deny / implicit deny',
                  choices=['Defense in depth', 'Default deny / implicit deny', 'Least privilege', 'Zero trust'], points=15,
                  hint='This principle means "if there\'s no rule allowing it, it\'s blocked".',
                  explanation='Default deny (implicit deny) means all traffic is blocked unless a specific rule permits it. This is the foundation of secure firewall configuration.'),
        Challenge(mission_id=m5.id, order=2, title='Dangerous Rule',
                  description='Review this firewall ruleset:\n\n```\nRule 1: ALLOW TCP  src:10.0.0.0/8    dst:ANY     port:80,443\nRule 2: ALLOW TCP  src:ANY           dst:ANY     port:ANY\nRule 3: DENY  TCP  src:ANY           dst:10.0.0.5 port:22\nRule 4: DENY  ALL  src:ANY           dst:ANY     port:ANY\n```\n\nWhich rule number is dangerously misconfigured and makes Rule 3 and 4 ineffective?',
                  task_type='text_answer', answer='2', points=15,
                  hint='Firewall rules are processed top-to-bottom. Once a match is found, processing stops.',
                  explanation='Rule 2 allows ALL TCP traffic from ANY source to ANY destination on ANY port. Since rules are processed top-down, Rule 2 matches everything before Rules 3 and 4 are ever reached.'),
        Challenge(mission_id=m5.id, order=3, title='Port Blocking',
                  description='Which of these ports should be blocked from external access on a corporate network to prevent remote desktop attacks?',
                  task_type='multiple_choice', answer='3389',
                  choices=['80', '443', '3389', '53'], points=15,
                  hint='This is the default port for Windows Remote Desktop Protocol (RDP).',
                  explanation='Port 3389 (RDP) should be blocked from external access. RDP is one of the most commonly exploited services — attackers use brute force and exploits like BlueKeep (CVE-2019-0708).'),
        Challenge(mission_id=m5.id, order=4, title='Firewall Flag',
                  description='A properly configured firewall follows this order of rules:\n1. Anti-spoofing rules\n2. Allow established/related connections\n3. Allow specific permitted services\n4. Log and deny everything else\n\nWhat is the technical term for rule #2 that allows return traffic for connections initiated from inside the network?\n\nFlag: BTA{answer_lowercase}',
                  task_type='flag_submission', answer='BTA{stateful_inspection}', points=15,
                  answer_is_regex=True,
                  hint='This type of firewall tracks connection states (NEW, ESTABLISHED, RELATED).',
                  explanation='Stateful inspection (or stateful packet filtering) tracks the state of network connections. It allows return traffic for outbound connections without needing explicit inbound rules.'),
    ]
    db.session.add_all(challenges_m5)

    db.session.commit()
