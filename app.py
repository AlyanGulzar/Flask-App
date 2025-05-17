from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from flask_bcrypt import Bcrypt
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Regexp, Length
from datetime import datetime
import os

app = Flask(__name__)

#Security Configs
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firstapp.db'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

#Database Models
class Contact(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(100))
    lname = db.Column(db.String(100))
    email = db.Column(db.String(120))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

# New User model with secure password storage
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # stores bcrypt hash

#WTForms
class ContactForm(FlaskForm):
    fname = StringField('First Name', validators=[DataRequired(), Regexp(r'^[A-Za-z\s\-\']+$', message='Invalid characters in first name.')])
    lname = StringField('Last Name', validators=[DataRequired(), Regexp(r'^[A-Za-z\s\-\']+$', message='Invalid characters in last name.')])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')


@app.route('/register-test', methods=['POST'])
def register_test():
    email = request.form.get('email')
    password = request.form.get('password')
    if email and password:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return "User registered with hashed password."
    return "Missing email or password."

@app.route('/login-test', methods=['POST'])
def login_test():
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        return "Login successful."
    return "Invalid credentials."

#Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    form = ContactForm()
    if form.validate_on_submit():
        new_contact = Contact(
            fname=form.fname.data,
            lname=form.lname.data,
            email=form.email.data
        )
        db.session.add(new_contact)
        db.session.commit()
        flash("Contact added successfully!", "success")
        return redirect(url_for('index'))
    contacts = Contact.query.all()
    return render_template('index.html', form=form, contacts=contacts)

@app.route('/delete/<int:sno>')
def delete(sno):
    contact = Contact.query.get_or_404(sno)
    db.session.delete(contact)
    db.session.commit()
    flash("Contact deleted successfully!", "info")
    return redirect(url_for('index'))

#Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

if __name__ == '__main__':
    app.run(debug=False)
