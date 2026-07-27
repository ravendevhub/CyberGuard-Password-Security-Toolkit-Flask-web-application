import os
import csv
import io
import string
import secrets
import hashlib
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, redirect, url_for, request,
    session, flash, jsonify, send_file, Response
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Initialize Flask app
app = Flask(__name__)
app.jinja_env.globals.update(datetime=datetime)

# Configure instance folder paths and database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(app.instance_path, 'cyberguard.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Ensure instance folder exists
os.makedirs(app.instance_path, exist_ok=True)

# Set up Flask secret key from file or generate a persistent one
flask_secret_file = os.path.join(app.instance_path, 'flask_secret.key')
if not os.path.exists(flask_secret_file):
    f_secret = secrets.token_hex(24)
    with open(flask_secret_file, 'w') as f:
        f.write(f_secret)
else:
    with open(flask_secret_file, 'r') as f:
        f_secret = f.read().strip()
app.config['SECRET_KEY'] = f_secret

# Initialize database
db = SQLAlchemy(app)

# ==========================================
# CRYPTOGRAPHY & ENCRYPTION SETUP
# ==========================================
# We store vault passwords encrypted in the SQLite database.
# We generate a unique Fernet symmetric key stored locally in
# instance/secret.key.
key_file = os.path.join(app.instance_path, 'secret.key')
if not os.path.exists(key_file):
    fernet_key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(fernet_key)
else:
    with open(key_file, 'rb') as f:
        fernet_key = f.read()
cipher_suite = Fernet(fernet_key)


def encrypt_password(plain_text):
    """Encrypts a password string using Fernet and returns a base64 string."""
    if not plain_text:
        return ""
    encrypted_bytes = cipher_suite.encrypt(plain_text.encode('utf-8'))
    return encrypted_bytes.decode('utf-8')


def decrypt_password(cipher_text):
    """Decrypts a base64 Fernet token back into a plain text password."""
    if not cipher_text:
        return ""
    try:
        decrypted_bytes = cipher_suite.decrypt(cipher_text.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except Exception:
        return "[Decryption Error: Invalid Key]"

# ==========================================
# DATABASE MODELS
# ==========================================


class User(db.Model):
    """Stores user accounts with hashed credentials."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    passwords = db.relationship(
        'PasswordHistory',
        backref='user',
        lazy=True,
        cascade="all, delete-orphan")
    activities = db.relationship(
        'ActivityLog',
        backref='user',
        lazy=True,
        cascade="all, delete-orphan")


class PasswordHistory(db.Model):
    """Stores user credentials with encrypted passwords."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Service name, e.g., 'Google'
    title = db.Column(db.String(100), nullable=False)
    # Username for that service
    username = db.Column(db.String(100), nullable=True)
    encrypted_password = db.Column(db.String(255), nullable=False)
    strength_score = db.Column(db.Integer, nullable=False)
    strength_label = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ActivityLog(db.Model):
    """Audit logs for student learning on password operations."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    # E.g., 'Login', 'Breach Check'
    action = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# Create database tables
with app.app_context():
    db.create_all()

# ==========================================
# SECURITY UTILITIES & LOGIC
# ==========================================


def log_activity(action, description, user_id=None):
    """Helper function to record an security or system activity log."""
    if not user_id and 'user_id' in session:
        user_id = session['user_id']

    ip_addr = request.remote_addr or '127.0.0.1'
    # Handle proxies
    if request.headers.getlist("X-Forwarded-For"):
        ip_addr = request.headers.getlist("X-Forwarded-For")[0]

    log_entry = ActivityLog(
        user_id=user_id,
        action=action,
        description=description,
        ip_address=ip_addr
    )
    db.session.add(log_entry)
    db.session.commit()


def check_password_strength(password):
    """
    Analyzes password strength using length, case mix, digits,
    special characters, and offline dictionary list.
    """
    score = 0
    feedback = []

    # 1. Length check
    length = len(password)
    if length >= 12:
        score += 2
        feedback.append("Excellent length (12+ characters)")
    elif length >= 8:
        score += 1
        feedback.append("Acceptable length (8+ characters)")
    else:
        feedback.append("Critically short (must be at least 8 characters)")

    # 2. Case check (upper & lower)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    if has_upper and has_lower:
        score += 1
        feedback.append("Contains a mix of uppercase and lowercase letters")
    else:
        if not has_upper:
            feedback.append("Missing uppercase letters")
        if not has_lower:
            feedback.append("Missing lowercase letters")

    # 3. Numeric check
    has_digit = any(c.isdigit() for c in password)
    if has_digit:
        score += 1
        feedback.append("Contains numbers")
    else:
        feedback.append("Missing numbers")

    # 4. Special character check
    special_chars = string.punctuation
    has_special = any(c in special_chars for c in password)
    if has_special:
        score += 1
        feedback.append("Contains special characters/symbols")
    else:
        feedback.append("Missing special characters/symbols")

    # 5. Offline common password check
    is_common = False
    common_file_path = os.path.join(
        app.static_folder or 'static',
        'common_passwords.txt')
    if os.path.exists(common_file_path):
        try:
            with open(common_file_path, 'r', encoding='utf-8') as f:
                common_passwords = {line.strip().lower() for line in f}
            if password.lower() in common_passwords:
                is_common = True
        except Exception as e:
            print(f"Error reading common passwords list: {e}")

    if is_common:
        # Cap score at 1 if matched in common passwords list
        score = min(score, 1)
        feedback.append(
            "CRITICAL: Password matched a known dictionary leak list!")
    else:
        feedback.append(
            "Not found in the dictionary list of 1,000 common passwords")

    # Standardize score between 0 and 5
    score = min(max(score, 0), 5)

    ratings = {
        0: "Very Weak",
        1: "Very Weak" if is_common else "Weak",
        2: "Weak",
        3: "Medium",
        4: "Strong",
        5: "Very Strong"
    }

    return {
        "score": score,
        "label": ratings[score],
        "feedback": feedback,
        "is_common": is_common
    }


def generate_strong_password(
        length=12,
        use_upper=True,
        use_lower=True,
        use_digits=True,
        use_symbols=True):
    """Generates a secure random password using Python secrets."""
    pool = ""
    if use_upper:
        pool += string.ascii_uppercase
    if use_lower:
        pool += string.ascii_lowercase
    if use_digits:
        pool += string.digits
    if use_symbols:
        pool += string.punctuation

    if not pool:
        pool = string.ascii_letters + string.digits

    # Guarantee at least one character of each active pool
    password = []
    if use_upper:
        password.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        password.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        password.append(secrets.choice(string.digits))
    if use_symbols:
        password.append(secrets.choice(string.punctuation))

    # Fill the remaining length
    remaining_length = length - len(password)
    if remaining_length > 0:
        password.extend(secrets.choice(pool) for _ in range(remaining_length))

    # Securely shuffle using secrets.SystemRandom
    secrets.SystemRandom().shuffle(password)
    return "".join(password)

# ==========================================
# ROUTE DECORATORS
# ==========================================


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# ROUTING & CONTROLLERS
# ==========================================

# 1. Login / Register Routes


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        # Validations
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template('register.html')

        # Check existing user
        user_exists = User.query.filter(
            (User.username == username) | (
                User.email == email)).first()
        if user_exists:
            flash("Username or Email already registered.", "danger")
            return render_template('register.html')

        # Create user
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Log registration activity
        log_activity(
            "Register",
            f"User account created: {username}",
            new_user.id)

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username_or_email = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter(
            (User.username == username_or_email) | (
                User.email == username_or_email)).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username

            # Log login activity
            log_activity("Login", f"User logged in: {user.username}", user.id)

            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Please try again.", "danger")
            # Audit log failed attempt (anonymous log)
            log_activity(
                "Login Failed",
                f"Failed login attempt for input: {username_or_email}")

    return render_template('login.html')


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity("Logout", f"User logged out: {session['username']}")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# 2. Dashboard Route


@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    user = db.session.get(User, session['user_id'])
    vault_entries = PasswordHistory.query.filter_by(user_id=user.id).all()

    # Calculate stats
    total_saved = len(vault_entries)
    avg_strength = 0.0
    if total_saved > 0:
        avg_strength = sum(
            item.strength_score for item in vault_entries) / total_saved

    # Get last 5 activity logs
    recent_logs = ActivityLog.query.filter_by(
        user_id=user.id).order_by(
        ActivityLog.timestamp.desc()).limit(5).all()

    # Static Security Tips pool
    security_tips = [
        "Use multi-factor authentication (MFA/2FA) on critical web accounts.",
        "A strong passphrase (4 random words) is often stronger and "
        "easier to remember than random characters.",
        "Avoid using public Wi-Fi networks when logging into sensitive "
        "portals (use a VPN or mobile hotspot).",
        "Check your passwords periodically on local breach checkers or "
        "HaveIBeenPwned.",
        "Do not reuse the same password across multiple online accounts; "
        "if one gets hacked, all of them are at risk.",
        "Be cautious of phishing emails asking you to click link/reset "
        "passwords immediately."
    ]
    # Pick a Tip of the day based on the calendar date index
    tip_index = datetime.now().day % len(security_tips)
    tip_of_the_day = security_tips[tip_index]

    return render_template(
        'dashboard.html',
        user=user,
        total_saved=total_saved,
        avg_strength=round(avg_strength, 2),
        recent_logs=recent_logs,
        tip_of_the_day=tip_of_the_day
    )

# 3. Password Strength Analyzer Route


@app.route('/analyzer', methods=['GET', 'POST'])
def analyzer():
    result = None
    input_password = ""

    if request.method == 'POST':
        input_password = request.form.get('password', '')
        if input_password:
            result = check_password_strength(input_password)
            log_activity(
                "Analyze Password",
                "Evaluated password strength score")

            is_ajax = (
                request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
                request.args.get('format') == 'json'
            )
            if is_ajax:
                return jsonify(result)

    return render_template(
        'analyzer.html',
        result=result,
        input_password=input_password)

# 4. Strong Password Generator Route


@app.route('/generator', methods=['GET', 'POST'])
def generator():
    generated_pass = ""
    length = 12
    use_upper = True
    use_lower = True
    use_digits = True
    use_symbols = True

    if request.method == 'POST':
        try:
            length = int(request.form.get('length', 12))
            length = min(max(length, 8), 64)  # Bound length range 8 to 64
        except ValueError:
            length = 12

        use_upper = 'uppercase' in request.form
        use_lower = 'lowercase' in request.form
        use_digits = 'digits' in request.form
        use_symbols = 'symbols' in request.form

        generated_pass = generate_strong_password(
            length, use_upper, use_lower, use_digits, use_symbols)
        log_activity(
            "Generate Password",
            f"Generated strong password of length {length}")

        is_ajax = (
            request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
            request.args.get('format') == 'json'
        )
        if is_ajax:
            return jsonify({"password": generated_pass})

    return render_template(
        'generator.html',
        password=generated_pass,
        length=length,
        use_upper=use_upper,
        use_lower=use_lower,
        use_digits=use_digits,
        use_symbols=use_symbols
    )

# 5. Offline Password Breach Checker Route


@app.route('/breach-checker', methods=['GET', 'POST'])
def breach_checker():
    checked = False
    is_breached = False
    sha1_hash = ""
    input_password = ""

    if request.method == 'POST':
        input_password = request.form.get('password', '')
        if input_password:
            checked = True

            # Calculate SHA-1 hash for demonstration
            sha1 = hashlib.sha1(
                input_password.encode('utf-8')).hexdigest().upper()
            sha1_hash = sha1

            # Read local breach database file
            common_file_path = os.path.join(
                app.static_folder or 'static', 'common_passwords.txt')
            if os.path.exists(common_file_path):
                with open(common_file_path, 'r', encoding='utf-8') as f:
                    common_passwords = {line.strip().lower() for line in f}
                if input_password.lower() in common_passwords:
                    is_breached = True

            log_activity(
                "Breach Check",
                f"Checked password breach status (Breached: {is_breached})")

            is_ajax = (
                request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
                request.args.get('format') == 'json'
            )
            if is_ajax:
                return jsonify({
                    "is_breached": is_breached,
                    "sha1_hash": sha1_hash
                })

    return render_template(
        'breach_checker.html',
        checked=checked,
        is_breached=is_breached,
        sha1_hash=sha1_hash,
        input_password=input_password
    )

# 6. Password Vault / History Route


@app.route('/vault', methods=['GET', 'POST'])
@login_required
def vault():
    user = db.session.get(User, session['user_id'])

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            title = request.form.get('title', '').strip()
            username = request.form.get('username', '').strip()
            plain_password = request.form.get('password', '')

            if not title or not plain_password:
                flash("Title and Password are required to save.", "danger")
            else:
                encrypted = encrypt_password(plain_password)
                strength_info = check_password_strength(plain_password)

                new_entry = PasswordHistory(
                    user_id=user.id,
                    title=title,
                    username=username or None,
                    encrypted_password=encrypted,
                    strength_score=strength_info['score'],
                    strength_label=strength_info['label']
                )
                db.session.add(new_entry)
                db.session.commit()
                log_activity("Vault Add", f"Added credentials for: {title}")
                flash("Password saved to Vault successfully.", "success")

        elif action == 'edit':
            entry_id = request.form.get('entry_id')
            title = request.form.get('title', '').strip()
            username = request.form.get('username', '').strip()
            plain_password = request.form.get('password', '')

            entry = PasswordHistory.query.filter_by(
                id=entry_id, user_id=user.id).first()
            if entry:
                entry.title = title
                entry.username = username or None
                if plain_password:
                    entry.encrypted_password = encrypt_password(plain_password)
                    strength_info = check_password_strength(plain_password)
                    entry.strength_score = strength_info['score']
                    entry.strength_label = strength_info['label']
                db.session.commit()
                log_activity("Vault Edit", f"Edited credentials for: {title}")
                flash("Vault record updated.", "success")

        elif action == 'delete':
            entry_id = request.form.get('entry_id')
            entry = PasswordHistory.query.filter_by(
                id=entry_id, user_id=user.id).first()
            if entry:
                title = entry.title
                db.session.delete(entry)
                db.session.commit()
                log_activity(
                    "Vault Delete",
                    f"Deleted credentials for: {title}")
                flash("Vault record deleted.", "success")

        return redirect(url_for('vault'))

    # Get all vault records and decrypt them for view toggles
    vault_records = PasswordHistory.query.filter_by(
        user_id=user.id).order_by(
        PasswordHistory.created_at.desc()).all()

    # We decrypt the passwords in python before rendering to support the JS
    # Show/Hide client-side
    decrypted_records = []
    for record in vault_records:
        decrypted_records.append({
            "id": record.id,
            "title": record.title,
            "username": record.username or "",
            "password": decrypt_password(record.encrypted_password),
            "strength_score": record.strength_score,
            "strength_label": record.strength_label,
            "created_at": record.created_at
        })

    return render_template('history.html', records=decrypted_records)

# 7. User Profile Route


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = db.session.get(User, session['user_id'])
    vault_entries = PasswordHistory.query.filter_by(user_id=user.id).all()

    # Statistics calculations
    total_passwords = len(vault_entries)
    strength_distribution = {
        "Very Weak": 0,
        "Weak": 0,
        "Medium": 0,
        "Strong": 0,
        "Very Strong": 0
    }

    for item in vault_entries:
        label = item.strength_label
        if label in strength_distribution:
            strength_distribution[label] += 1

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_profile':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()

            if not username or not email:
                flash("Username and Email are required.", "danger")
            else:
                # Check conflict
                conflict = User.query.filter(
                    (User.username == username) | (
                        User.email == email)).filter(
                    User.id != user.id).first()
                if conflict:
                    flash("Username or Email already in use.", "danger")
                else:
                    user.username = username
                    user.email = email
                    db.session.commit()
                    session['username'] = username
                    log_activity(
                        "Profile Update",
                        "Updated contact profile details")
                    flash("Profile updated successfully.", "success")

        elif action == 'change_password':
            curr_pass = request.form.get('current_password', '')
            new_pass = request.form.get('new_password', '')

            if not curr_pass or not new_pass:
                flash("Both password fields are required.", "danger")
            elif not check_password_hash(user.password_hash, curr_pass):
                flash("Incorrect current password.", "danger")
            else:
                user.password_hash = generate_password_hash(
                    new_pass, method='scrypt')
                db.session.commit()
                log_activity("Profile Security", "Changed account password")
                flash("Password updated successfully.", "success")

        return redirect(url_for('profile'))

    return render_template(
        'profile.html',
        user=user,
        total_passwords=total_passwords,
        strength_distribution=strength_distribution
    )

# 8. Activity Log Route


@app.route('/logs')
@login_required
def activity_log():
    user = db.session.get(User, session['user_id'])
    logs = ActivityLog.query.filter_by(
        user_id=user.id).order_by(
        ActivityLog.timestamp.desc()).all()
    return render_template('activity_log.html', logs=logs)

# 9. Security Tips Route


@app.route('/tips')
def security_tips_page():
    return render_template('tips.html')

# 10. Exports Routes


@app.route('/export/csv')
@login_required
def export_csv():
    user = db.session.get(User, session['user_id'])
    vault_entries = PasswordHistory.query.filter_by(user_id=user.id).all()

    # Generate CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Write headers (Security Warning: CSV holds cleartext passwords)
    writer.writerow(
        ["# SECURITY WARNING: This file stores decrypted "
         "passwords in cleartext. Keep it secure!"])
    writer.writerow(["Service Name",
                     "Username/Email",
                     "Decrypted Password",
                     "Strength Score (0-5)",
                     "Strength Label",
                     "Created Date"])

    for item in vault_entries:
        decrypted = decrypt_password(item.encrypted_password)
        writer.writerow([
            item.title,
            item.username or "",
            decrypted,
            item.strength_score,
            item.strength_label,
            item.created_at.strftime("%Y-%m-%d %H:%M:%S")
        ])

    output.seek(0)

    log_activity("Export CSV", "Exported vault entries to CSV")

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": (
            "attachment; filename="
            f"cyberguard_export_{user.username}.csv"
        )}
    )


@app.route('/export/pdf')
@login_required
def export_pdf():
    user = db.session.get(User, session['user_id'])
    vault_entries = PasswordHistory.query.filter_by(user_id=user.id).all()

    total_saved = len(vault_entries)
    avg_strength = 0.0
    if total_saved > 0:
        avg_strength = sum(
            item.strength_score for item in vault_entries) / total_saved

    logs_count = ActivityLog.query.filter_by(user_id=user.id).count()

    try:
        # Build ReportLab PDF Document in memory
        pdf_buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40)
        story = []
        styles = getSampleStyleSheet()

        # Setup specific styles
        title_style = ParagraphStyle(
            'PdfTitle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#0d6efd'),
            spaceAfter=15
        )
        subtitle_style = ParagraphStyle(
            'PdfSubtitle',
            parent=styles['Heading2'],
            fontSize=13,
            textColor=colors.HexColor('#198754'),
            spaceAfter=10
        )
        normal_style = styles['Normal']
        bold_label = ParagraphStyle(
            'BoldLabel',
            parent=normal_style,
            fontName='Helvetica-Bold')

        # Add Header elements
        story.append(
            Paragraph(
                "CyberGuard – Password Security Toolkit",
                title_style))
        story.append(
            Paragraph(
                "Personal Password Audit & Security Report",
                subtitle_style))
        story.append(Spacer(1, 10))

        # General Information Summary Table
        info_data = [
            [Paragraph("Report Timestamp:", bold_label), datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            [Paragraph("Audited Account:", bold_label), user.username],
            [Paragraph("Account Email:", bold_label), user.email],
            [Paragraph("Total Saved Accounts:", bold_label), str(total_saved)],
            [Paragraph("Average Vault Security Score:", bold_label), f"{avg_strength:.2f} / 5.0"],
            [Paragraph("Total Security Events Audited:", bold_label), str(logs_count)]
        ]
        info_table = Table(info_data, colWidths=[200, 310])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 15))

        # Vault Status Audit Table
        story.append(Paragraph("Saved Password Audit Log", subtitle_style))
        story.append(
            Paragraph(
                "Passwords are securely hashed and stored in database. Passwords themselves are masked in this report.",
                normal_style))
        story.append(Spacer(1, 10))

        vault_data = [["Service Name", "Username",
                       "Strength Rating", "Security Audit", "Saved Date"]]
        for item in vault_entries:
            security_note = "Weak (Reset Recommended)" if item.strength_score <= 2 else (
                "Medium" if item.strength_score <= 4 else "Strong (Safe)")
            vault_data.append([
                item.title,
                item.username or "N/A",
                f"{item.strength_score} / 5 ({item.strength_label})",
                security_note,
                item.created_at.strftime("%Y-%m-%d")
            ])

        vault_table = Table(vault_data, colWidths=[110, 110, 110, 110, 70])
        t_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ]

        # Add visual highlighting rules for strength
        for i, item in enumerate(vault_entries, start=1):
            if item.strength_score <= 2:
                t_style.append(
                    ('BACKGROUND', (3, i), (3, i), colors.HexColor('#f8d7da')))
                t_style.append(
                    ('TEXTCOLOR', (3, i), (3, i), colors.HexColor('#842029')))
            elif item.strength_score >= 4:
                t_style.append(
                    ('BACKGROUND', (3, i), (3, i), colors.HexColor('#d1e7dd')))
                t_style.append(
                    ('TEXTCOLOR', (3, i), (3, i), colors.HexColor('#0f5132')))

        vault_table.setStyle(TableStyle(t_style))
        story.append(vault_table)
        story.append(Spacer(1, 15))

        # Recommendations
        story.append(
            Paragraph(
                "Action Plan & Recommendations",
                subtitle_style))
        story.append(Spacer(1, 5))

        recommendations = []
        if any(item.strength_score <= 2 for item in vault_entries):
            recommendations.append(
                "<b>[CRITICAL]</b> Replace weak credentials. Passwords with a score <= 2 can be easily cracked via dictionary attacks.")
        if avg_strength < 4.0:
            recommendations.append(
                "<b>[WARNING]</b> Boost your average vault score to at least 4.0 by utilizing symbols, numeric digits, and mixed cases.")
        recommendations.append(
            "<b>[INFO]</b> Never use duplicate passwords. Ensure you generate random combinations for each of your key services.")
        recommendations.append(
            "<b>[INFO]</b> Check your emails on offline or online breach lists to identify if any connected accounts are leaked.")

        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", normal_style))
            story.append(Spacer(1, 4))

        doc.build(story)
        pdf_buffer.seek(0)

        log_activity(
            "Export PDF",
            "Exported vault entries and security audit report to PDF")

        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"cyberguard_report_{user.username}.pdf"
        )
    except Exception as e:
        print(f"Error creating PDF: {e}")
        flash(
            "An error occurred generating your PDF. Please try again later.",
            "danger")
        return redirect(url_for('vault'))


# ==========================================
# APPLICATION ENTRYPOINT
# ==========================================
if __name__ == '__main__':
    # Runs on localhost:5004
    app.run(debug=True, host='127.0.0.1', port=5004)

