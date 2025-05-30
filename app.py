from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3
import pyotp
import qrcode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import bcrypt

app = Flask(__name__)
app.secret_key = "supersecretkey123"  # Change for production
AES_KEY = get_random_bytes(32)

def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT,
        totp_secret TEXT
    )''')
    conn.commit()
    conn.close()

def encrypt_secret(secret):
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(secret.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_secret(encrypted_secret):
    encrypted_bytes = base64.b64decode(encrypted_secret)
    nonce, tag, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:]
    cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        secret = pyotp.random_base32()
        encrypted_secret = encrypt_secret(secret)
        
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)",
                      (username, hashed_password, encrypted_secret))
            conn.commit()
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Tanzania E-Service")
            qr = qrcode.make(totp_uri)
            qr.save("static/qrcode.png")
            session["username"] = username
            return render_template("totp_setup.html", qr_image="qrcode.png")
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists!"
        finally:
            conn.close()
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        totp_code = request.form["totp_code"]
        
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT password, totp_secret FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode(), user[0].encode()):
            secret = decrypt_secret(user[1])
            totp = pyotp.TOTP(secret)
            if totp.verify(totp_code):
                session["username"] = username
                return redirect(url_for("dashboard"))
            else:
                return "Invalid TOTP code!"
        else:
            return "Invalid username or password!"
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "username" in session:
        return render_template("dashboard.html", username=session["username"])
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True, ssl_context="adhoc")