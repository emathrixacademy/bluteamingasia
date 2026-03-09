from flask_wtf import FlaskForm
from wtforms import SelectField, TextAreaField
from wtforms.validators import DataRequired


class IncidentUpdateForm(FlaskForm):
    status = SelectField('Status', choices=[
        ('open', 'Open'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed'),
    ], validators=[DataRequired()])
    notes = TextAreaField('Notes')
