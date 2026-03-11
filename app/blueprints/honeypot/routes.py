from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required
from app.blueprints.honeypot import honeypot_bp
from app.models.honeypot import HoneypotService, HoneypotLog
from app.services.honeypot_service import (
    get_service_templates, create_honeypot, delete_honeypot,
    toggle_honeypot, simulate_attack, get_honeypot_stats,
)
from app.extensions import db


@honeypot_bp.route('/')
@login_required
def dashboard():
    """Honeypot management dashboard."""
    services = HoneypotService.query.order_by(HoneypotService.created_at.desc()).all()
    templates = get_service_templates()
    stats = get_honeypot_stats()
    return render_template('honeypot/dashboard.html',
                           services=services, templates=templates, stats=stats)


@honeypot_bp.route('/deploy', methods=['POST'])
@login_required
def deploy():
    """Deploy a new honeypot service."""
    service_type = request.form.get('service_type', '')
    service = create_honeypot(service_type)
    if service:
        flash(f'Honeypot "{service.name}" deployed on port {service.port}.', 'success')
    else:
        flash(f'Unknown service type: {service_type}', 'danger')
    return redirect(url_for('honeypot.dashboard'))


@honeypot_bp.route('/<uuid:service_id>/toggle', methods=['POST'])
@login_required
def toggle(service_id):
    """Toggle honeypot on/off."""
    service = toggle_honeypot(str(service_id))
    if service:
        state = 'activated' if service.is_active else 'deactivated'
        flash(f'{service.name} {state}.', 'success')
    return redirect(url_for('honeypot.dashboard'))


@honeypot_bp.route('/<uuid:service_id>/delete', methods=['POST'])
@login_required
def remove(service_id):
    """Delete a honeypot service."""
    if delete_honeypot(str(service_id)):
        flash('Honeypot removed.', 'success')
    return redirect(url_for('honeypot.dashboard'))


@honeypot_bp.route('/<uuid:service_id>/simulate', methods=['POST'])
@login_required
def simulate(service_id):
    """Simulate an attack for training purposes."""
    logs = simulate_attack(str(service_id))
    if logs:
        flash(f'Simulated attack generated {len(logs)} log entries.', 'info')
    else:
        flash('Could not simulate attack. Is the honeypot active?', 'warning')
    return redirect(url_for('honeypot.logs', service_id=service_id))


@honeypot_bp.route('/<uuid:service_id>/logs')
@login_required
def logs(service_id):
    """View logs for a specific honeypot service."""
    service = HoneypotService.query.get_or_404(service_id)
    page = request.args.get('page', 1, type=int)
    threat_filter = request.args.get('threat', '')

    query = HoneypotLog.query.filter_by(service_id=service.id)
    if threat_filter:
        query = query.filter_by(threat_level=threat_filter)

    log_entries = query.order_by(HoneypotLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    return render_template('honeypot/logs.html', service=service,
                           logs=log_entries, current_threat=threat_filter)


@honeypot_bp.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for honeypot statistics (AJAX)."""
    return jsonify(get_honeypot_stats())


@honeypot_bp.route('/api/recent-attacks')
@login_required
def api_recent_attacks():
    """API endpoint for recent attack logs across all honeypots."""
    recent = (
        HoneypotLog.query
        .filter(HoneypotLog.action != 'disconnect')
        .order_by(HoneypotLog.timestamp.desc())
        .limit(50)
        .all()
    )
    return jsonify([
        {
            'id': str(log.id),
            'service': log.service.name,
            'source_ip': log.source_ip,
            'action': log.action,
            'payload': (log.payload or '')[:200],
            'threat_level': log.threat_level,
            'country': log.country,
            'timestamp': log.timestamp.isoformat(),
        }
        for log in recent
    ])
