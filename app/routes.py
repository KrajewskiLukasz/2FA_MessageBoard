from flask import Blueprint, current_app, render_template, redirect, url_for, after_this_request, flash, request
from flask_login import current_user, login_user, logout_user, login_required
from .forms import LoginForm, RegistrationForm, AddMessageForm, ResetPasswordForm
from .models import User, Message, LoginAttempt
from app import db, bcrypt
import pyotp
from markdown import markdown
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import bleach
from datetime import datetime, time, timedelta
from time import sleep
import logging

main = Blueprint('main', __name__)
logging.basicConfig(level=logging.WARNING, filename="security.log")

@main.route("/", methods=["GET", "POST"])
@main.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    form = LoginForm()
    ip_address = request.remote_addr 

    login_attempt = LoginAttempt.query.filter_by(ip_address=ip_address).first()
    if login_attempt:
        if login_attempt.blocked_until and login_attempt.blocked_until > datetime.utcnow():
            remaining_time = (login_attempt.blocked_until - datetime.utcnow()).seconds
            flash(f"Twoje konto jest zablokowane. Spróbuj ponownie za {remaining_time} sekund.", "danger")
            return render_template("login.html", form=form)

    if form.validate_on_submit():
        if form.honeypot.data: 
            logging.warning(f"Honeypot wypełniony na IP: {ip_address}")
            flash("Wykryto nieautoryzowaną aktywność. Formularz został odrzucony.", "danger")
            return redirect(url_for("main.login"))

        user = User.query.filter_by(email=form.email.data).first()

        if not user or not bcrypt.check_password_hash(user.password_hash, form.password.data):
            if not login_attempt:
                login_attempt = LoginAttempt(ip_address=ip_address, attempts=1)
                db.session.add(login_attempt)
            else:
                login_attempt.attempts += 1
                login_attempt.last_attempt = datetime.utcnow()

                
                if login_attempt.attempts >= current_app.config["MAX_LOGIN_ATTEMPTS"]:
                    login_attempt.blocked_until = datetime.utcnow() + timedelta(seconds=current_app.config["BLOCK_DURATION"])
                    flash("Twoje konto zostało tymczasowo zablokowane z powodu wielu nieudanych prób logowania.", "danger")

            db.session.commit()
            flash("Niepoprawne dane logowania.", "danger")
            sleep(current_app.config["LOGIN_DELAY"])  
            return render_template("login.html", form=form)

        if login_attempt:
            db.session.delete(login_attempt)
            db.session.commit()

        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(form.totp.data):
            login_user(user)
            flash("Zalogowano pomyślnie!", "success")
            return redirect(url_for("main.home"))
        else:
            flash("Niepoprawny kod weryfikacyjny 2FA.", "danger")

    return render_template("login.html", form=form)

@main.after_request
def apply_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "  
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "  
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "  
        "img-src 'self' data: https://www.markdownguide.org https://api.qrserver.com; "  
        "font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; " 
        "connect-src 'self'; " 
        "frame-ancestors 'none'; "  
        "object-src 'none'; "  
    )
    return response

@main.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))
    form = RegistrationForm()
    if form.validate_on_submit():
        if form.honeypot.data:
            logging.warning(f"Honeypot wypełniony na IP: {request.remote_addr}")
            flash("Wykryto nieautoryzowaną aktywność. Formularz został odrzucony.", "danger")
            return redirect(url_for("main.register"))
        
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        otp_secret = pyotp.random_base32()  

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            otp_secret=otp_secret,
            private_key=private_key_pem,
            public_key=public_key_pem
        )
        db.session.add(user)
        db.session.commit()

        return redirect(url_for("main.qr", email=user.email))
    return render_template("register.html", form=form)

@main.route("/qr/<email>")
def qr(email):
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))
    user = User.query.filter_by(email=email).first_or_404()
    totp = pyotp.TOTP(user.otp_secret)
    otp_url = totp.provisioning_uri(name=user.email, issuer_name="TwojaAplikacja")
    return render_template("qr.html", otp_url=otp_url)

@main.route("/home", methods=["GET", "POST"])
@login_required
def home():
    form = AddMessageForm()
    if form.validate_on_submit():
        sanitized_title = bleach.clean(
            form.title.data,
            tags=["b", "i", "u", "strong", "em", "h1", "h2", "h3", "h4", "h5", "h6"],
            attributes={},
            strip=True
        )
        sanitized_content = bleach.clean(
            form.content.data,
            tags=["b", "i", "u", "strong", "em", "h1", "h2", "h3", "h4", "h5", "h6", "img"],
            attributes={"img": ["src", "alt", "width", "height"]},
            strip=True
        )

        private_key = serialization.load_pem_private_key(
            current_user.private_key.encode('utf-8'),
            password=None
        )
        message_content = f"{sanitized_title}:{sanitized_content}"
        signature = private_key.sign(
            message_content.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        new_message = Message(
            title=form.title.data,
            content=form.content.data,
            author=current_user,
            signature=signature.hex()
        )
        db.session.add(new_message)
        db.session.commit()
        flash("Wiadomość została dodana i podpisana!", "success")
        return redirect(url_for("main.home"))

    messages = Message.query.order_by(Message.date_posted.desc()).all()
    for message in messages:
        
        public_key = serialization.load_pem_public_key(message.author.public_key.encode('utf-8'))
        message_content = f"{message.title}:{message.content}"
        try:
            public_key.verify(
                bytes.fromhex(message.signature),
                message_content.encode('utf-8'),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            message.verified = True
        except Exception:
            message.verified = False

        message.content = markdown(
            bleach.clean(
                message.content,
                tags=["b", "i", "u", "strong", "em", "h1", "h2", "h3", "h4", "h5", "h6", "img", "a"],
                attributes={"img": ["src", "alt", "width", "height"], "a": ["href", "title"]},
                strip=True
            ),
            extensions=["extra", "codehilite", "tables"]
        )


    return render_template("home.html", form=form, messages=messages)

@main.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Wylogowano pomyślnie!", "info")
    return redirect(url_for("main.login"))

@main.route("/profile/<username>")
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    messages = Message.query.filter_by(author=user).order_by(Message.date_posted.desc()).all()

    for message in messages:
        public_key = serialization.load_pem_public_key(message.author.public_key.encode('utf-8'))
        message_content = f"{message.title}:{message.content}"
        try:
            public_key.verify(
                bytes.fromhex(message.signature),
                message_content.encode('utf-8'),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            message.verified = True
        except Exception:
            message.verified = False

        message.content = markdown(
            bleach.clean(
                message.content,
                tags=["b", "i", "u", "strong", "em", "h1", "h2", "h3", "h4", "h5", "h6", "img"],
                attributes={"img": ["src", "alt", "width", "height"]},
                strip=True
            )
        )

    return render_template("profile.html", user=user, messages=messages)

@main.route("/verify/<int:message_id>")
@login_required
def verify_message(message_id):
    message = Message.query.get_or_404(message_id)
    user = message.author

    public_key = serialization.load_pem_public_key(user.public_key.encode('utf-8'))

    message_content = f"{message.title}:{message.content}"
    try:
        
        public_key.verify(
            bytes.fromhex(message.signature),
            message_content.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        flash("Podpis wiadomości jest poprawny!", "success")
    except Exception:
        flash("Podpis wiadomości jest niepoprawny!", "danger")

    return redirect(url_for("main.home"))

@main.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        if form.honeypot.data:
            logging.warning(f"Honeypot wypełniony na IP: {request.remote_addr}")
            flash("Wykryto nieautoryzowaną aktywność. Formularz został odrzucony.", "danger")
            return redirect(url_for("main.reset_password"))
        
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash("Nie znaleziono użytkownika z podanym adresem email.", "danger")
            return redirect(url_for('main.reset_password'))

        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(form.totp.data):
            flash("Niepoprawny kod weryfikacyjny 2FA.", "danger")
            return redirect(url_for('main.reset_password'))
        
        user.password_hash = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
        db.session.commit()
        flash("Hasło zostało zresetowane pomyślnie! Możesz się teraz zalogować.", "success")
        return redirect(url_for('main.login'))
    
    return render_template("reset_password.html", form=form)
