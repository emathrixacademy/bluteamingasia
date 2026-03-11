from flask import render_template, request, jsonify
from flask_login import login_required
from app.blueprints.analysis import analysis_bp
from app.services.log_analysis_service import (
    correlate_events, check_ioc, get_event_timeline,
    get_anomaly_scores, MITRE_ATTACK_MAPPING,
)


@analysis_bp.route('/')
@login_required
def dashboard():
    """Log analysis and SIEM dashboard."""
    hours = request.args.get('hours', 24, type=int)
    timeline = get_event_timeline(hours)
    correlations = correlate_events(hours)
    anomalies = get_anomaly_scores()
    return render_template('analysis/dashboard.html',
                           timeline=timeline,
                           correlations=correlations,
                           anomalies=anomalies,
                           hours=hours,
                           mitre_map=MITRE_ATTACK_MAPPING)


@analysis_bp.route('/correlations')
@login_required
def correlations():
    """View event correlation chains."""
    hours = request.args.get('hours', 24, type=int)
    chains = correlate_events(hours)
    return render_template('analysis/correlations.html', chains=chains, hours=hours)


@analysis_bp.route('/ioc-check', methods=['GET', 'POST'])
@login_required
def ioc_check():
    """Check indicators of compromise."""
    result = None
    indicator = ''
    if request.method == 'POST':
        indicator = request.form.get('indicator', '').strip()
        if indicator:
            result = check_ioc(indicator)
    return render_template('analysis/ioc_check.html', result=result, indicator=indicator)


@analysis_bp.route('/api/timeline')
@login_required
def api_timeline():
    """API endpoint for event timeline data."""
    hours = request.args.get('hours', 24, type=int)
    return jsonify(get_event_timeline(hours))


@analysis_bp.route('/api/anomalies')
@login_required
def api_anomalies():
    """API endpoint for anomaly scores."""
    return jsonify(get_anomaly_scores())


@analysis_bp.route('/api/correlations')
@login_required
def api_correlations():
    """API endpoint for event correlations."""
    hours = request.args.get('hours', 24, type=int)
    return jsonify(correlate_events(hours))


@analysis_bp.route('/api/ioc/<indicator>')
@login_required
def api_ioc(indicator):
    """API endpoint for IOC check."""
    return jsonify(check_ioc(indicator))
