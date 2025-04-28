# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from models import User # Import User model to check if email exists

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')
        

"""
forms.py

This module defines the web forms used for user authentication in the Flask Security Monitoring App.
It uses Flask-WTF (Flask extension for WTForms) to handle form rendering and validation.

Forms:
--------
1. LoginForm:
    - Used for user login.
    - Fields: email, password, remember_me (checkbox), submit.
    - Validates presence and correct format of email and password.

2. RegistrationForm:
    - Used for new user registration.
    - Fields: email, password, repeat password, submit.
    - Enforces:
        - Required input
        - Valid email format
        - Password length (minimum 8 characters)
        - Password confirmation match
        - Unique email validation (checks against existing users in the database)

Usage:
--------
- These forms are rendered in your HTML templates via Jinja2 (`{{ form.email.label }}`, `{{ form.email() }}` etc.).
- On form submission, validation is performed automatically using the specified validators.
- The `validate_email` method ensures no two users can register with the same email address.

Security:
--------
- Automatically handles CSRF protection (built-in via Flask-WTF).
- Ensures user input is validated and safe before processing.

Note:
--------
- `models.User` is imported to check if the submitted registration email already exists.
"""
