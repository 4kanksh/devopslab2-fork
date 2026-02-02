# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
from argon2 import PasswordHasher
from base64 import b64encode, b64decode

# ---------- Configuration ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'data.db')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
ph = PasswordHasher()  # Argon2 default params

# ---------- Models ----------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    # store wrapped (RSA-encrypted) AES key used to encrypt the user's secret
    wrapped_aes_key = db.Column(db.Text, nullable=True)
    nonce = db.Column(db.Text, nullable=True)
    ciphertext = db.Column(db.Text, nullable=True)
    # insecure plaintext for demo only (DO NOT DO THIS IN REAL APPS)
    secret_plaintext = db.Column(db.Text, nullable=True)

# ---------- Login helpers ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- RSA key helpers ----------
# For demo: default key files. In a real system keep private key in a secure HSM/KEK.
PRIVATE_KEY_PATH = os.environ.get('PRIVATE_KEY_PATH', os.path.join(BASE_DIR, 'keys', 'private_key.pem'))
PUBLIC_KEY_PATH = os.environ.get('PUBLIC_KEY_PATH', os.path.join(BASE_DIR, 'keys', 'public_key.pem'))

def generate_rsa_keys():
    os.makedirs(os.path.join(BASE_DIR, 'keys'), exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()
    # write private key (PEM, encrypted with no password for demo only)
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Generated RSA keypair at:", PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)

def load_public_key():
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key():
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# ---------- Crypto helpers ----------
def generate_aes_key():
    # AES-256 key (32 bytes)
    return os.urandom(32)

def encrypt_with_aes_gcm(aes_key: bytes, plaintext: bytes):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct

def decrypt_with_aes_gcm(aes_key: bytes, nonce: bytes, ciphertext: bytes):
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)

def wrap_key_rsa(public_key, key_to_wrap: bytes) -> bytes:
    # Use OAEP for RSA encryption (secure padding)
    wrapped = public_key.encrypt(
        key_to_wrap,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped

def unwrap_key_rsa(private_key, wrapped_key: bytes) -> bytes:
    key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return key

# ---------- Routes ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        if User.query.filter_by(username=u).first():
            flash("User exists", "error"); return redirect(url_for('register'))
        hash_pw = ph.hash(p)
        user = User(username=u, password_hash=hash_pw)
        db.session.add(user)
        db.session.commit()
        flash("Registered. Please login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']; p = request.form['password']
        user = User.query.filter_by(username=u).first()
        if not user:
            flash("Invalid credentials", "error"); return redirect(url_for('login'))
        try:
            ph.verify(user.password_hash, p)
            login_user(user)
            flash("Logged in", "success")
            return redirect(url_for('dashboard'))
        except Exception:
            flash("Invalid credentials", "error")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/store_secret', methods=['GET','POST'])
@login_required
def store_secret():
    # Secure flow: encrypt with AES-GCM, wrap AES key with RSA public key
    if request.method == 'POST':
        secret = request.form['secret'].encode('utf-8')
        aes_key = generate_aes_key()
        nonce, ciphertext = encrypt_with_aes_gcm(aes_key, secret)
        # wrap aes key with RSA public key
        public_key = load_public_key()
        wrapped_key = wrap_key_rsa(public_key, aes_key)
        # store base64-encoded pieces
        current_user.wrapped_aes_key = b64encode(wrapped_key).decode('utf-8')
        current_user.nonce = b64encode(nonce).decode('utf-8')
        current_user.ciphertext = b64encode(ciphertext).decode('utf-8')
        # clear insecure field if any
        current_user.secret_plaintext = None
        db.session.commit()
        flash("Secret securely stored (AES-GCM + RSA key-wrap).", "success")
        return redirect(url_for('dashboard'))
    return render_template('store_secret.html')

@app.route('/view_secret')
@login_required
def view_secret():
    if not current_user.ciphertext or not current_user.wrapped_aes_key:
        flash("No stored secret.", "info"); return redirect(url_for('dashboard'))
    try:
        wrapped = b64decode(current_user.wrapped_aes_key)
        nonce = b64decode(current_user.nonce)
        ciphertext = b64decode(current_user.ciphertext)
        private_key = load_private_key()
        aes_key = unwrap_key_rsa(private_key, wrapped)
        plaintext = decrypt_with_aes_gcm(aes_key, nonce, ciphertext)
        return render_template('view_secret.html', secret=plaintext.decode('utf-8'))
    except Exception as e:
        flash("Decryption failed: " + str(e), "error")
        return redirect(url_for('dashboard'))

# Insecure route for demonstration (show before/after)
@app.route('/store_plaintext', methods=['GET','POST'])
@login_required
def store_plaintext():
    if request.method == 'POST':
        secret = request.form['secret']
        # insecure: store plaintext (for demo only)
        current_user.secret_plaintext = secret
        # wipe secure storage to show contrast
        current_user.wrapped_aes_key = None
        current_user.nonce = None
        current_user.ciphertext = None
        db.session.commit()
        flash("Secret stored AS PLAINTEXT (insecure) — demo only.", "warning")
        return redirect(url_for('dashboard'))
    return render_template('store_plaintext.html')

@app.route('/view_plaintext')
@login_required
def view_plaintext():
    if not current_user.secret_plaintext:
        flash("No plaintext secret stored.", "info"); return redirect(url_for('dashboard'))
    return render_template('view_plaintext.html', secret=current_user.secret_plaintext)

# ---------- CLI helpers ----------
@app.cli.command('initdb')
def initdb():
    """Initialize DB and RSA keys (for demo)."""
    db.create_all()
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        generate_rsa_keys()
    print("Initialized DB and ensured RSA keys exist.")

if __name__ == '__main__':
    app.run(debug=True)
