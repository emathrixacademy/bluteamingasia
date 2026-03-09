from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required
from app.blueprints.devices import devices_bp
from app.blueprints.devices.forms import DeviceForm
from app.models.device import Device
from app.models.event import Event
from app.extensions import db
from flask import current_app


@devices_bp.route('/')
@login_required
def list_devices():
    page = request.args.get('page', 1, type=int)
    device_type = request.args.get('type', '')
    status = request.args.get('status', '')

    query = Device.query
    if device_type:
        query = query.filter_by(device_type=device_type)
    if status:
        query = query.filter_by(status=status)

    devices = query.order_by(Device.created_at.desc()).paginate(
        page=page, per_page=current_app.config['DEVICES_PER_PAGE'], error_out=False
    )
    return render_template('devices/list.html', devices=devices,
                           current_type=device_type, current_status=status)


@devices_bp.route('/<uuid:device_id>')
@login_required
def detail(device_id):
    device = Device.query.get_or_404(device_id)
    recent_events = (
        Event.query
        .filter_by(device_id=device.id)
        .order_by(Event.timestamp.desc())
        .limit(20)
        .all()
    )
    return render_template('devices/detail.html', device=device, recent_events=recent_events)


@devices_bp.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    form = DeviceForm()
    if form.validate_on_submit():
        device = Device(
            name=form.name.data,
            device_type=form.device_type.data,
            location=form.location.data or None,
            ip_address=form.ip_address.data or None,
        )
        db.session.add(device)
        db.session.commit()
        flash(f'Device "{device.name}" registered successfully.', 'success')
        return redirect(url_for('devices.list_devices'))
    return render_template('devices/register.html', form=form)
