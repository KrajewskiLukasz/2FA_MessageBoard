from flask import logging
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import re  

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Hasło", validators=[DataRequired()])
    totp = StringField("Kod weryfikacyjny 2FA", validators=[DataRequired()])
    honeypot = HiddenField("Honeypot")
    submit = SubmitField("Zaloguj się")

    def validate_honeypot(self, honeypot):
        if honeypot.data: 
            raise ValidationError("Wykryto nieautoryzowaną aktywność. Formularz został odrzucony.")
        
    def validate_email(self, email):
        blocked_keywords = ["DROP TABLE", "SELECT", "--", ";", "<script>", "<iframe>", "UNION"]
        for keyword in blocked_keywords:
            if keyword.lower() in email.data.lower():
                logging.warning(f"Niebezpieczne dane wejściowe: {email.data}")
                raise ValidationError("Niedozwolone wyrażenia w danych wejściowych.")

    def validate_password(self, password):
        blocked_keywords = ["DROP TABLE", "SELECT", "--", ";", "<script>"]
        for keyword in blocked_keywords:
            if keyword.lower() in password.data.lower():
                logging.warning(f"Niebezpieczne dane wejściowe: {password.data}")
                raise ValidationError("Niedozwolone wyrażenia w danych wejściowych.")



class AddMessageForm(FlaskForm):
    title = StringField("Tytuł", validators=[DataRequired(), Length(min=1, max=100)])
    content = TextAreaField("Treść", validators=[DataRequired()])
    submit = SubmitField("Dodaj notatkę")

    def validate_content(self, content):
        blocked_keywords = ["DROP TABLE", "SELECT", "--", ";", "<script>", "<img>"]
        for keyword in blocked_keywords:
            if keyword.lower() in content.data.lower():
                raise ValidationError("Niedozwolone wyrażenia w treści wiadomości.")


class RegistrationForm(FlaskForm):
    username = StringField("Nazwa użytkownika", validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    
    password = PasswordField(
        "Hasło",
        validators=[
            DataRequired(),
            Length(min=8, message="Hasło musi mieć co najmniej 8 znaków."),
        ]
    )
    confirm_password = PasswordField(
        "Potwierdź hasło",
        validators=[
            DataRequired(),
            EqualTo("password", message="Hasła muszą być takie same.")
        ]
    )
    honeypot = HiddenField("Honeypot")
    submit = SubmitField("Zarejestruj się")
    
    def validate_honeypot(self, honeypot):
        if honeypot.data:
            raise ValidationError("Wykryto nieautoryzowaną aktywność. Formularz został odrzucony.")
    
    def validate_password(self, password):
        password_data = password.data
        if not re.search(r'[A-Z]', password_data):
            raise ValidationError("Hasło musi zawierać co najmniej jedną wielką literę.")
        if not re.search(r'[a-z]', password_data):
            raise ValidationError("Hasło musi zawierać co najmniej jedną małą literę.")
        if not re.search(r'[0-9]', password_data):
            raise ValidationError("Hasło musi zawierać co najmniej jedną cyfrę.")
        if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password_data):
            raise ValidationError("Hasło musi zawierać co najmniej jeden znak specjalny (!@#$%^&*(), itp.).")
        
class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    honeypot = HiddenField("Honeypot")
    new_password = PasswordField('Nowe hasło', validators=[
        DataRequired(),
        Length(min=8, message='Hasło musi mieć co najmniej 8 znaków.')
    ])
    confirm_password = PasswordField('Potwierdź nowe hasło', validators=[
        DataRequired(),
        EqualTo('new_password', message='Hasła muszą się zgadzać.')
    ])
    totp = StringField('Kod weryfikacyjny 2FA', validators=[DataRequired()])
    submit = SubmitField('Zresetuj hasło')
    def validate_new_password(self, new_password):
        password_data = new_password.data
        if len(password_data) < 8:
            raise ValidationError("Hasło musi mieć co najmniej 8 znaków.")
        if not re.search(r'[A-Z]', password_data):
            raise ValidationError("Hasło musi zawierać co najmniej jedną wielką literę.")
        if not re.search(r'[a-z]', password_data):
            raise ValidationError("Hasło musi zawierać co najmniej jedną małą literę.")
        if not re.search(r'[0-9]', password_data):
            raise ValidationError("Hasło musi zawierać co najmniej jedną cyfrę.")
        if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password_data):
            raise ValidationError("Hasło musi zawierać co najmniej jeden znak specjalny (!@#$%^&*(), itp.).")
        