# app.py
from flask import Flask, request, render_template, redirect, url_for, session, send_from_directory, jsonify, make_response
from flask_session import Session
from authlib.integrations.flask_client import OAuth
import sqlite3
import pyotp
import qrcode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import bcrypt
import os
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
import re
import secrets
import shutil

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey123")
if not app.secret_key:
    logging.warning("FLASK_SECRET_KEY not set in .env, using default secret key")

# Session configuration
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
Session(app)

# OAuth setup for Google Sign-In
oauth = OAuth(app)
try:
    google = oauth.register(
        name="google",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"}
    )
except Exception as e:
    logging.error(f"Failed to initialize Google OAuth: {e}")

# AES key for TOTP secret encryption
AES_KEY = os.getenv("AES_KEY", base64.b64encode(get_random_bytes(32)).decode())
try:
    decoded_key = base64.b64decode(AES_KEY)
    if len(decoded_key) != 32:
        raise ValueError(f"AES_KEY must decode to 32 bytes, got {len(decoded_key)} bytes")
except Exception as e:
    logging.error(f"Invalid AES_KEY: {e}")
    AES_KEY = base64.b64encode(get_random_bytes(32)).decode()
    decoded_key = base64.b64decode(AES_KEY)
    logging.warning(f"Generated fallback AES_KEY: {AES_KEY}")

# CSRF protection
csrf_serializer = URLSafeTimedSerializer(app.secret_key)

# Logging setup
logging.basicConfig(filename="app.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def cleanup_sessions():
    """Clean up old session files to prevent conflicts."""
    try:
        shutil.rmtree("flask_session", ignore_errors=True)
        os.makedirs("flask_session", exist_ok=True)
        logging.info("Session directory cleaned up")
    except Exception as e:
        logging.warning(f"Session cleanup failed: {e}")

def init_db():
    """Initialize the database with users, refresh_tokens, and leaderboard tables."""
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password TEXT,
            totp_secret TEXT,
            google_id TEXT,
            failed_attempts INTEGER DEFAULT 0,
            last_login TIMESTAMP,
            is_locked BOOLEAN DEFAULT FALSE,
            high_score INTEGER DEFAULT 0
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS refresh_tokens (
            email TEXT PRIMARY KEY,
            token TEXT,
            expires_at TIMESTAMP,
            FOREIGN KEY (email) REFERENCES users(email)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS leaderboard (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            score INTEGER,
            timestamp TIMESTAMP,
            FOREIGN KEY (email) REFERENCES users(email)
        )''')
        conn.commit()
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")
    finally:
        conn.close()

def encrypt_secret(secret):
    """Encrypt TOTP secret using AES."""
    try:
        cipher = AES.new(decoded_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(secret.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    except Exception as e:
        logging.error(f"Secret encryption failed: {e}")
        raise

def decrypt_secret(encrypted_secret):
    """Decrypt TOTP secret."""
    try:
        encrypted_bytes = base64.b64decode(encrypted_secret)
        nonce, tag, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:]
        cipher = AES.new(decoded_key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        logging.error(f"Secret decryption failed: {e}")
        raise

def validate_email(email):
    """Validate email format."""
    return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email)

def validate_password(password):
    """Validate password strength."""
    return (len(password) >= 8 and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password))

def require_csrf(f):
    """Decorator for CSRF protection on POST requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get("csrf_token")
            try:
                if not token or not csrf_serializer.loads(token, max_age=3600):
                    logging.warning("CSRF token invalid")
                    return render_template("login.html", error="Invalid CSRF token", csrf_token=session.get("csrf_token"))
            except Exception as e:
                logging.error(f"CSRF validation failed: {e}")
                return render_template("login.html", error="CSRF validation error", csrf_token=session.get("csrf_token"))
        return f(*args, **kwargs)
    return decorated

def require_no_session(f):
    """Decorator to redirect authenticated users with verified 2FA to dashboard."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "email" in session and session.get("2fa_verified", False):
            logging.info(f"User {session['email']} redirected to dashboard from {request.path}")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

def generate_csrf_token():
    """Generate a CSRF token with retry mechanism."""
    try:
        random_string = secrets.token_urlsafe(32)
        token = csrf_serializer.dumps(random_string)
        logging.info("CSRF token generated successfully")
        return token
    except Exception as e:
        logging.error(f"CSRF token generation failed: {e}", exc_info=True)
        try:
            random_string = secrets.token_urlsafe(32)
            token = csrf_serializer.dumps(random_string)
            logging.info("CSRF token generated on retry")
            return token
        except Exception as e:
            logging.error(f"CSRF token generation failed on retry: {e}")
            return None

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logging.error(f"Internal Server Error: {error}")
    return render_template("error.html", error="An unexpected error occurred. Please try again later."), 500

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

@app.route("/")
def home():
    """Render the home page."""
    try:
        logged_in = "email" in session and session.get("2fa_verified", False)
        csrf_token = generate_csrf_token()
        if not csrf_token:
            logging.error("Failed to generate CSRF token for home")
            return render_template("error.html", error="Failed to load home page"), 500
        session["csrf_token"] = csrf_token
        style_nonce = secrets.token_hex(16)
        script_nonce = secrets.token_hex(16)
        logging.info("Rendering landing page")
        response = make_response(render_template(
            "index.html",
            logged_in=logged_in,
            csrf_token=csrf_token,
            style_nonce=style_nonce,
            script_nonce=script_nonce
        ))
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; "
            f"script-src 'self' https://unpkg.com 'nonce-{script_nonce}'; "
            f"style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://unpkg.com 'nonce-{style_nonce}'; "
            f"font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            f"img-src 'self' data:; "
            f"media-src 'self'"
        )
        return response
    except Exception as e:
        logging.error(f"Home route error: {e}")
        return render_template("error.html", error="Failed to load home page"), 500

@app.route("/favicon.ico")
def favicon():
    """Serve the favicon."""
    return send_from_directory(app.static_folder, "favicon.ico")

@app.route("/qrcode/<filename>")
def serve_qrcode(filename):
    """Serve and delete the QR code file."""
    try:
        file_path = os.path.join("static", filename)
        if os.path.exists(file_path):
            response = send_from_directory("static", filename)
            try:
                os.remove(file_path)
                logging.info(f"QR code {filename} served and deleted")
            except OSError as e:
                logging.warning(f"Failed to delete QR code {filename}: {e}")
            return response
        logging.warning(f"QR code {filename} not found")
        return "QR code not found", 404
    except Exception as e:
        logging.error(f"QR code serve error: {e}")
        return render_template("error.html", error="Failed to serve QR code"), 500

@app.route("/privacy")
def privacy():
    """Render the privacy policy page."""
    try:
        return render_template("privacy.html")
    except Exception as e:
        logging.error(f"Privacy route error: {e}")
        return render_template("error.html", error="Failed to load privacy policy"), 500

@app.route("/register", methods=["GET", "POST"])
@require_csrf
@require_no_session
def register():
    """Handle user registration and TOTP setup."""
    try:
        if request.method == "POST":
            email = request.form["email"].strip().lower()
            password = request.form["password"]
            consent = request.form.get("consent")

            if not validate_email(email):
                return render_template("register.html", error="Invalid email format.", csrf_token=session.get("csrf_token"))
            if not validate_password(password):
                return render_template("register.html", error="Password must be 8+ characters with uppercase, digits, and special characters.", csrf_token=session.get("csrf_token"))
            if not consent:
                return render_template("register.html", error="You must agree to the terms and conditions.", csrf_token=session.get("csrf_token"))

            conn = sqlite3.connect("users.db")
            try:
                c = conn.cursor()
                c.execute("SELECT google_id, password FROM users WHERE email = ?", (email,))
                user = c.fetchone()

                if user:
                    if user[0]:  # Email is associated with a Google Sign-In account
                        return render_template(
                            "register.html",
                            error=f"This email ({email}) is already registered with Google Sign-In. Please sign in with Google or use a different email.",
                            csrf_token=session.get("csrf_token"),
                            show_google_blink=True,
                            show_login_blink=False
                        )
                    elif user[1]:  # Email is associated with an email/password account
                        return render_template(
                            "register.html",
                            error=f"This email ({email}) is already registered with email/password. Please sign in with your email and password.",
                            csrf_token=session.get("csrf_token"),
                            show_login_blink=True,
                            show_google_blink=False
                        )
                    else:
                        logging.error(f"User {email} has invalid registration data in the database")
                        return render_template(
                            "register.html",
                            error="An error occurred. Please contact support.",
                            csrf_token=session.get("csrf_token"),
                            show_login_blink=False,
                            show_google_blink=False
                        )

                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                secret = pyotp.random_base32()
                try:
                    encrypted_secret = encrypt_secret(secret)
                except Exception as e:
                    logging.error(f"Failed to encrypt TOTP secret for {email}: {e}")
                    return render_template("register.html", error="Failed to set up 2FA. Please try again.", csrf_token=session.get("csrf_token"))

                try:
                    c.execute("INSERT INTO users (email, password, totp_secret) VALUES (?, ?, ?)",
                              (email, hashed_password, encrypted_secret))
                    conn.commit()
                    logging.info(f"User {email} registered successfully via email/password")
                    qr_filename = f"qrcode_{email.replace('@', '_').replace('.', '_')}.png"
                    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="Tanzania E-Service")
                    try:
                        qr = qrcode.make(totp_uri)
                        qr.save(f"static/{qr_filename}")
                        logging.info(f"QR code saved for {email} as static/{qr_filename}")
                    except Exception as e:
                        logging.error(f"QR code generation failed for {email}: {e}")
                        return render_template("register.html", error="Failed to generate QR code. Try again.", csrf_token=session.get("csrf_token"))
                    session["pending_email"] = email
                    return render_template("totp_setup.html", qr_image=qr_filename, success="Registration successful! Set up 2FA below.")
                except sqlite3.IntegrityError as e:
                    logging.error(f"IntegrityError for email {email}: {e}")
                    c.execute("SELECT google_id FROM users WHERE email = ?", (email,))
                    existing_google_id = c.fetchone()
                    if existing_google_id and existing_google_id[0]:
                        return render_template(
                            "register.html",
                            error=f"This email ({email}) is already registered with Google Sign-In. Please sign in with Google or use a different email.",
                            csrf_token=session.get("csrf_token"),
                            show_google_blink=True,
                            show_login_blink=False
                        )
                    return render_template(
                        "register.html",
                        error="An unexpected error occurred. This email might already be registered.",
                        csrf_token=session.get("csrf_token")
                    )
            finally:
                conn.close()
        csrf_token = generate_csrf_token()
        if not csrf_token:
            logging.error("Failed to generate CSRF token in register route")
            return redirect(url_for("logout"))
        session["csrf_token"] = csrf_token
        return render_template("register.html", csrf_token=csrf_token)
    except Exception as e:
        logging.error(f"Register route error: {e}")
        return render_template("error.html", error="Registration failed"), 500

@app.route("/login", methods=["GET", "POST"])
@require_csrf
@require_no_session
def login():
    """Handle user login."""
    try:
        if request.method == "POST":
            email = request.form["email"].strip().lower()
            password = request.form["password"]
            
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("SELECT password, failed_attempts, is_locked FROM users WHERE email = ?", (email,))
            user = c.fetchone()
            
            if user and not user[2]:
                if bcrypt.checkpw(password.encode(), user[0].encode()):
                    logging.info(f"Successful password login for {email}")
                    c.execute("UPDATE users SET failed_attempts = 0 WHERE email = ?", (email,))
                    conn.commit()
                    session["pending_email"] = email
                    return redirect(url_for("totp_verify"))
                else:
                    logging.warning(f"Failed password login for {email}")
                    failed_attempts = user[1] + 1
                    c.execute("UPDATE users SET failed_attempts = ? WHERE email = ?", (failed_attempts, email))
                    if failed_attempts >= 5:
                        c.execute("UPDATE users SET is_locked = TRUE WHERE email = ?", (email,))
                        logging.warning(f"Account {email} locked after {failed_attempts} failed attempts")
                        return render_template("login.html", error="Account locked. Contact support.", csrf_token=session.get("csrf_token"))
                    conn.commit()
                    return render_template("login.html", error=f"Invalid password. {5 - failed_attempts} attempts left.", csrf_token=session.get("csrf_token"))
            else:
                logging.warning(f"Login attempt for non-existent or locked account: {email}")
                return render_template("login.html", error="Invalid email or account locked.", csrf_token=session.get("csrf_token"))
            conn.close()
        csrf_token = generate_csrf_token()
        if not csrf_token:
            logging.error("Failed to generate CSRF token in login route")
            return redirect(url_for("logout"))
        session["csrf_token"] = csrf_token
        style_nonce = secrets.token_hex(16)
        return render_template("login.html", csrf_token=csrf_token, style_nonce=style_nonce)
    except Exception as e:
        logging.error(f"Login route error: {e}")
        return render_template("error.html", error="Login failed"), 500

@app.route("/google_login")
@require_no_session
def google_login():
    """Initiate Google Sign-In with account selection prompt."""
    try:
        nonce = secrets.token_urlsafe(16)
        session['nonce'] = nonce
        if "csrf_token" not in session:
            csrf_token = generate_csrf_token()
            if not csrf_token:
                logging.error("Failed to generate CSRF token in google_login route")
                return render_template("error.html", error="Failed to initiate Google Sign-In"), 500
            session["csrf_token"] = csrf_token
        redirect_uri = url_for("google_callback", _external=True)
        # Add prompt=select_account to force account selection
        return google.authorize_redirect(redirect_uri, nonce=nonce, prompt="select_account")
    except Exception as e:
        logging.error(f"Google login error: {e}")
        return render_template("error.html", error="Google Sign-In failed"), 500

@app.route("/google_callback")
def google_callback():
    """Handle Google Sign-In callback."""
    try:
        nonce = session.pop('nonce', None)
        if not nonce:
            raise ValueError("No nonce found in session")

        token = google.authorize_access_token()
        user_info = google.parse_id_token(token, nonce=nonce)
        google_id = user_info["sub"]
        email = user_info["email"].lower()

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT email, totp_secret FROM users WHERE google_id = ? OR email = ?", (google_id, email))
        user = c.fetchone()

        if user:
            session["pending_email"] = user[0]
            c.execute("UPDATE users SET last_login = ? WHERE email = ?",
                      (datetime.utcnow().isoformat(), user[0]))
            conn.commit()
            logging.info(f"User {user[0]} logged in via Google")
            if user[1]:
                return redirect(url_for("totp_verify"))
            else:
                secret = pyotp.random_base32()
                try:
                    encrypted_secret = encrypt_secret(secret)
                except Exception as e:
                    logging.error(f"Failed to encrypt TOTP secret for {email}: {e}")
                    return render_template("error.html", error="Failed to set up 2FA for Google Sign-In user"), 500
                c.execute("UPDATE users SET totp_secret = ? WHERE email = ?",
                          (encrypted_secret, user[0]))
                conn.commit()
                qr_filename = f"qrcode_{user[0].replace('@', '_').replace('.', '_')}.png"
                totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user[0], issuer_name="Tanzania E-Service")
                try:
                    qr = qrcode.make(totp_uri)
                    qr.save(f"static/{qr_filename}")
                    logging.info(f"QR code saved for {user[0]} as static/{qr_filename}")
                except Exception as e:
                    logging.error(f"QR code generation failed for {user[0]}: {e}")
                    return render_template("error.html", error="Failed to generate QR code for 2FA setup"), 500
                session["pending_email"] = user[0]
                return render_template("totp_setup.html", qr_image=qr_filename, success="Google Sign-In successful! Set up 2FA below.")
        else:
            secret = pyotp.random_base32()
            try:
                encrypted_secret = encrypt_secret(secret)
            except Exception as e:
                logging.error(f"Failed to encrypt TOTP secret for {email}: {e}")
                return render_template("error.html", error="Failed to set up 2FA for new Google Sign-In user"), 500
            c.execute("INSERT INTO users (email, google_id, totp_secret) VALUES (?, ?, ?)",
                      (email, google_id, encrypted_secret))
            conn.commit()
            logging.info(f"New user {email} registered via Google")
            qr_filename = f"qrcode_{email.replace('@', '_').replace('.', '_')}.png"
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="Tanzania E-Service")
            try:
                qr = qrcode.make(totp_uri)
                qr.save(f"static/{qr_filename}")
                logging.info(f"QR code saved for {email} as static/{qr_filename}")
            except Exception as e:
                logging.error(f"QR code generation failed for {email}: {e}")
                return render_template("error.html", error="Failed to generate QR code for 2FA setup"), 500
            session["pending_email"] = email
            return render_template("totp_setup.html", qr_image=qr_filename, success="Google Sign-In successful! Set up 2FA below.")
    except Exception as e:
        logging.error(f"Google callback error: {e}")
        return render_template("error.html", error="Google Sign-In callback failed"), 500
    finally:
        conn.close()

@app.route("/totp_verify", methods=["GET", "POST"])
@require_csrf
def totp_verify():
    """Verify TOTP code."""
    try:
        if "pending_email" not in session:
            logging.warning("No pending email for TOTP verification")
            return redirect(url_for("login"))
        
        email = session["pending_email"]
        if request.method == "POST":
            totp_code = request.form["totp_code"]
            
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("SELECT totp_secret FROM users WHERE email = ?", (email,))
            user = c.fetchone()
            
            if user and user[0]:
                secret = decrypt_secret(user[0])
                totp = pyotp.TOTP(secret)
                if totp.verify(totp_code):
                    logging.info(f"Successful TOTP verification for {email}")
                    session["email"] = email
                    session["2fa_verified"] = True
                    session.pop("pending_email", None)
                    c.execute("UPDATE users SET last_login = ? WHERE email = ?",
                              (datetime.utcnow().isoformat(), email))
                    conn.commit()
                    refresh_token = base64.b64encode(os.urandom(32)).decode()
                    expires_at = datetime.utcnow() + timedelta(days=30)
                    c.execute("INSERT OR REPLACE INTO refresh_tokens (email, token, expires_at) VALUES (?, ?, ?)",
                              (email, refresh_token, expires_at.isoformat()))
                    conn.commit()
                    return redirect(url_for("dashboard"))
                else:
                    logging.warning(f"Failed TOTP verification for {email}")
                    return render_template("totp_verify.html", error="Invalid 2FA code!", csrf_token=session.get("csrf_token"), pending_email=email)
            conn.close()
        csrf_token = generate_csrf_token()
        if not csrf_token:
            logging.error("Failed to generate CSRF token in totp_verify route")
            return redirect(url_for("logout"))
        session["csrf_token"] = csrf_token
        return render_template("totp_verify.html", csrf_token=csrf_token, pending_email=email)
    except Exception as e:
        logging.error(f"TOTP verify error: {e}")
        return render_template("error.html", error="2FA verification failed"), 500

@app.route("/dashboard")
def dashboard():
    """Render the user dashboard."""
    try:
        if "email" not in session or not session.get("2fa_verified", False):
            logging.warning("Unauthorized access attempt to dashboard")
            return redirect(url_for("login"))
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT failed_attempts, last_login, totp_secret, google_id, high_score FROM users WHERE email = ?", (session["email"],))
        user = c.fetchone()
        conn.close()
        auth_method = "Google Sign-In" if user[3] else ("Email + 2FA" if user[2] else "Email")
        return render_template("dashboard.html", email=session["email"],
                              failed_attempts=user[0], last_login=user[1] or "Never",
                              auth_method=auth_method, high_score=user[4], csrf_token=session.get("csrf_token"))
    except Exception as e:
        logging.error(f"Dashboard error: {e}")
        return render_template("error.html", error="Failed to load dashboard"), 500

@app.route("/snake-game")
def snake_game():
    """Render the Snake game page for authenticated users."""
    try:
        if "email" not in session or not session.get("2fa_verified", False):
            logging.warning("Unauthorized access attempt to snake-game")
            return redirect(url_for("login"))
        # Retrieve previous lives from session or set to 5 if not present, deduct 1 on reload
        prev_lives = session.get("prev_lives", 5)
        session["lives"] = max(0, prev_lives - 1) if prev_lives > 0 else 0  # Penalty on reload
        session["prev_lives"] = session["lives"]  # Update session for next load
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT high_score FROM users WHERE email = ?", (session["email"],))
        high_score = c.fetchone()[0]
        conn.close()
        return render_template("snake-game.html", email=session["email"], csrf_token=session.get("csrf_token"), initial_lives=session["lives"], high_score=high_score)
    except Exception as e:
        logging.error(f"Snake game route error: {e}")
        return render_template("error.html", error="Failed to load Snake game"), 500    

@app.route("/submit_score", methods=["POST"])
@require_csrf
def submit_score():
    """Submit a score to the leaderboard and update high score."""
    try:
        if "email" not in session or not session.get("2fa_verified", False):
            logging.warning("Unauthorized score submission attempt")
            return jsonify({"error": "Unauthorized"}), 401

        score = request.json.get("score")
        if not isinstance(score, int) or score < 0:
            return jsonify({"error": "Invalid score"}), 400

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT high_score FROM users WHERE email = ?", (session["email"],))
        current_high_score = c.fetchone()[0]
        new_high_score = max(score, current_high_score)
        c.execute("UPDATE users SET high_score = ? WHERE email = ?", (new_high_score, session["email"]))
        c.execute("INSERT INTO leaderboard (email, score, timestamp) VALUES (?, ?, ?)",
                  (session["email"], score, datetime.utcnow().isoformat()))
        conn.commit()
        logging.info(f"Score {score} submitted by {session['email']}, new high score: {new_high_score}")
        return jsonify({"message": "Score submitted successfully", "high_score": new_high_score})
    except Exception as e:
        logging.error(f"Score submission error: {e}")
        return jsonify({"error": "Failed to submit score"}), 500
    finally:
        conn.close()

@app.route("/leaderboard")
def leaderboard():
    """Retrieve the top 10 leaderboard scores."""
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT email, MAX(score) as score, MAX(timestamp) as timestamp FROM leaderboard GROUP BY email ORDER BY score DESC LIMIT 10")
        leaderboard_data = [{"email": row[0], "score": row[1], "timestamp": row[2]} for row in c.fetchall()]
        conn.close()
        return jsonify(leaderboard_data)
    except Exception as e:
        logging.error(f"Leaderboard retrieval error: {e}")
        return jsonify({"error": "Failed to load leaderboard"}), 500

@app.route("/logout")
def logout():
    """Log out the user."""
    try:
        email = session.get("email", "unknown")
        session.clear()
        logging.info(f"User {email} logged out")
        return redirect(url_for("home"))
    except Exception as e:
        logging.error(f"Logout error: {e}")
        return render_template("error.html", error="Logout failed"), 500

@app.route("/refresh_token", methods=["POST"])
@require_csrf
def refresh_token():
    """Refresh the user session."""
    try:
        old_token = request.form.get("refresh_token")
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT email, expires_at FROM refresh_tokens WHERE token = ?", (old_token,))
        token_data = c.fetchone()
        
        if token_data and datetime.fromisoformat(token_data[1]) > datetime.utcnow():
            email = token_data[0]
            session["email"] = email
            session["2fa_verified"] = True
            new_token = base64.b64encode(os.urandom(32)).decode()
            expires_at = datetime.utcnow() + timedelta(days=30)
            c.execute("UPDATE refresh_tokens SET token = ?, expires_at = ? WHERE email = ?",
                      (new_token, expires_at.isoformat(), email))
            conn.commit()
            logging.info(f"Session refreshed for {email}")
            return jsonify({"refresh_token": new_token})
        else:
            logging.warning("Invalid or expired refresh token")
            return jsonify({"error": "Invalid or expired refresh token"}), 401
    except Exception as e:
        logging.error(f"Refresh token error: {e}")
        return render_template("error.html", error="Session refresh failed"), 500
    finally:
        conn.close()

if __name__ == "__main__":
    cleanup_sessions()
    init_db()
    app.run(debug=True, ssl_context="adhoc")