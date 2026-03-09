from flask import render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from app.blueprints.alerts import alerts_bp
from app.models.alert import Alert
from app.extensions import db


@alerts_bp.route('/')
@login_required
def list_alerts():
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    acknowledged = request.args.get('acknowledged', '')

    query = Alert.query
    if severity:
        query = query.filter_by(severity=severity)
    if acknowledged == 'yes':
        query = query.filter_by(is_acknowledged=True)
    elif acknowledged == 'no':
        query = query.filter_by(is_acknowledged=False)

    alerts = query.order_by(Alert.created_at.desc()).paginate(
        page=page, per_page=current_app.config['ALERTS_PER_PAGE'], error_out=False
    )
    return render_template('alerts/list.html', alerts=alerts,
                           current_severity=severity, current_acknowledged=acknowledged)


@alerts_bp.route('/<uuid:alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.is_acknowledged = True
    alert.acknowledged_by = current_user.id
    db.session.commit()
    flash('Alert acknowledged.', 'success')
    return redirect(url_for('alerts.list_alerts'))
