from flask_wtf import FlaskForm
from wtforms import StringField, SelectField
from wtforms.validators import DataRequired, Optional, Length


class DeviceForm(FlaskForm):
    name = StringField('Device Name', validators=[DataRequired(), Length(max=255)])
    device_type = SelectField('Device Type', choices=[
        ('camera', 'Camera'),
        ('door_lock', 'Door Lock'),
        ('sensor', 'Sensor'),
        ('server', 'Server'),
        ('robot', 'Robot'),
        ('drone', 'Drone'),
        ('vehicle', 'Vehicle'),
    ], validators=[DataRequired()])
    location = StringField('Location', validators=[Optional(), Length(max=255)])
    ip_address = StringField('IP Address', validators=[Optional(), Length(max=45)])
