from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Email, Regexp

class ContactForm(FlaskForm):
    fname = StringField('First Name', validators=[
        DataRequired(),
        Regexp(r'^[A-Za-z\s\-\']+$', message='Invalid characters in first name.')
    ])
    lname = StringField('Last Name', validators=[
        DataRequired(),
        Regexp(r'^[A-Za-z\s\-\']+$', message='Invalid characters in last name.')
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message='Invalid email format.')
    ])
    submit = SubmitField('Submit')
