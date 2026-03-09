from datetime import datetime, timedelta
from flask import render_template
from flask_login import login_required
from sqlalchemy import func
from app.blueprints.dashboard import dashboard_bp
from app.models.device import Device
from app.models.event import Event
from app.models.incident import Incident
from app.models.alert import Alert
from app.extensions import db


@dashboard_bp.route('/')
@login_required
def index():
    now = datetime.utcnow()
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)

    # Stats
    total_devices = Device.query.count()
    events_24h = Event.query.filter(Event.timestamp >= day_ago).count()
    open_incidents = Incident.query.filter(
        Incident.status.in_(['open', 'investigating'])
    ).count()
    unacked_alerts = Alert.query.filter_by(is_acknowledged=False).count()

    # Recent events
    recent_events = (
        Event.query
        .order_by(Event.timestamp.desc())
        .limit(10)
        .all()
    )

    # Active incidents
    active_incidents = (
        Incident.query
        .filter(Incident.status.in_(['open', 'investigating']))
        .order_by(Incident.created_at.desc())
        .limit(5)
        .all()
    )

    # Events by severity (last 7 days) for chart
    severity_counts = (
        db.session.query(Event.severity, func.count(Event.id))
        .filter(Event.timestamp >= week_ago)
        .group_by(Event.severity)
        .all()
    )
    severity_data = {s: c for s, c in severity_counts}

    # Events per day (last 7 days) for chart
    daily_counts = []
    for i in range(6, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        count = Event.query.filter(
            Event.timestamp >= day_start,
            Event.timestamp < day_end
        ).count()
        daily_counts.append({
            'date': day_start.strftime('%b %d'),
            'count': count,
        })

    return render_template(
        'dashboard/index.html',
        total_devices=total_devices,
        events_24h=events_24h,
        open_incidents=open_incidents,
        unacked_alerts=unacked_alerts,
        recent_events=recent_events,
        active_incidents=active_incidents,
        severity_data=severity_data,
        daily_counts=daily_counts,
    )
