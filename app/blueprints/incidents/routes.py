from flask import render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required
from app.blueprints.incidents import incidents_bp
from app.blueprints.incidents.forms import IncidentUpdateForm
from app.models.incident import Incident
from app.models.ai_action import AIAction
from app.extensions import db


@incidents_bp.route('/')
@login_required
def list_incidents():
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', '')
    severity = request.args.get('severity', '')

    query = Incident.query
    if status:
        query = query.filter_by(status=status)
    if severity:
        query = query.filter_by(severity=severity)

    incidents = query.order_by(Incident.created_at.desc()).paginate(
        page=page, per_page=current_app.config['INCIDENTS_PER_PAGE'], error_out=False
    )
    return render_template('incidents/list.html', incidents=incidents,
                           current_status=status, current_severity=severity)


@incidents_bp.route('/<uuid:incident_id>', methods=['GET', 'POST'])
@login_required
def detail(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    form = IncidentUpdateForm(obj=incident)

    if form.validate_on_submit():
        incident.status = form.status.data
        if form.notes.data:
            existing = incident.description or ''
            incident.description = existing + '\n\n---\n' + form.notes.data
        db.session.commit()
        flash('Incident updated.', 'success')
        return redirect(url_for('incidents.detail', incident_id=incident.id))

    # Get timeline events
    timeline_events = []
    for ie in incident.events:
        evt = ie.event
        timeline_events.append({
            'time': evt.timestamp.strftime('%H:%M:%S'),
            'timestamp': evt.timestamp.isoformat(),
            'event': evt.event_type,
            'severity': evt.severity,
            'source': evt.device.name if evt.device else 'unknown',
            'location': evt.location or '',
        })
    timeline_events.sort(key=lambda x: x['timestamp'])

    # AI actions
    ai_actions = (
        AIAction.query
        .filter_by(incident_id=incident.id)
        .order_by(AIAction.timestamp.desc())
        .all()
    )

    return render_template(
        'incidents/detail.html',
        incident=incident,
        form=form,
        timeline_events=timeline_events,
        ai_actions=ai_actions,
    )
