from flask import render_template, request, current_app
from flask_login import login_required
from app.blueprints.events import events_bp
from app.models.event import Event
from app.services.vector_search_service import find_similar_events


@events_bp.route('/')
@login_required
def list_events():
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    event_type = request.args.get('type', '')

    query = Event.query
    if severity:
        query = query.filter_by(severity=severity)
    if event_type:
        query = query.filter(Event.event_type.ilike(f'%{event_type}%'))

    events = query.order_by(Event.timestamp.desc()).paginate(
        page=page, per_page=current_app.config['EVENTS_PER_PAGE'], error_out=False
    )
    return render_template('events/list.html', events=events,
                           current_severity=severity, current_type=event_type)


@events_bp.route('/<uuid:event_id>')
@login_required
def detail(event_id):
    event = Event.query.get_or_404(event_id)
    similar = find_similar_events(str(event_id), limit=5)
    return render_template('events/detail.html', event=event, similar_events=similar)
