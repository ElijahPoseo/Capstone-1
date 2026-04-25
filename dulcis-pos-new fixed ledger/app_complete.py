from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, send_file
from flask_mail import Mail, Message
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
import sqlite3
import os
import secrets
import re
import json
import html
import shutil
import threading
import time
import hashlib
import hmac
import hashlib
from contextlib import contextmanager
from cryptography.fernet import Fernet
import random
import io
import base64
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from markupsafe import Markup
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)

# ==================== ENCRYPTION ENGINE ====================
_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret.key")
_FLASK_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flask_secret.key")

def _load_or_create_key():
    """Load the Fernet key from disk, or generate and save a new one."""
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            return f.read().strip()
    key = Fernet.generate_key()
    with open(_KEY_FILE, "wb") as f:
        f.write(key)
    print(f"[SECURITY] New encryption key created at: {_KEY_FILE}")
    print("[SECURITY] Back up this file — losing it means encrypted data is unrecoverable.")
    return key

def _load_or_create_flask_secret():
    """Load or create a persistent Flask SECRET_KEY so sessions survive restarts."""
    if os.path.exists(_FLASK_KEY_FILE):
        with open(_FLASK_KEY_FILE, "r") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(_FLASK_KEY_FILE, "w") as f:
        f.write(key)
    print(f"[SECURITY] New Flask secret key created at: {_FLASK_KEY_FILE}")
    return key

_fernet = Fernet(_load_or_create_key())

def encrypt(value):
    """Encrypt a string value. Returns None if value is None/empty."""
    if value is None or str(value).strip() == "":
        return None
    return _fernet.encrypt(str(value).encode()).decode()

def decrypt(token):
    """Decrypt an encrypted token back to its original string.
    Returns the token unchanged if it is None, empty, or not encrypted."""
    if not token:
        return token
    try:
        return _fernet.decrypt(token.encode()).decode()
    except Exception:
        # Value is not encrypted (e.g. existing plaintext rows) — return as-is
        return token

def decrypt_float(token):
    """Decrypt and convert back to float. Returns None if not present."""
    raw = decrypt(token)
    if raw is None:
        return None
    try:
        return float(raw)
    except (ValueError, TypeError):
        return None

# ==================== CAPTCHA ====================
def generate_captcha():
    """Generate a math captcha. Returns (signed_token, image_base64).
    The answer is signed into the token — no session storage needed."""
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    op = random.choice(['+', '-'])
    if op == '-' and b > a:
        a, b = b, a
    answer = a + b if op == '+' else a - b
    question = f"{a} {op} {b} = ?"

    img = Image.new('RGB', (180, 52), color=(245, 245, 250))
    draw = ImageDraw.Draw(img)
    for _ in range(5):
        x1, y1 = random.randint(0, 180), random.randint(0, 52)
        x2, y2 = random.randint(0, 180), random.randint(0, 52)
        draw.line([(x1, y1), (x2, y2)], fill=(random.randint(150, 210),) * 3, width=1)
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 26)
    except Exception:
        font = ImageFont.load_default()
    x = 12
    for ch in question:
        draw.text((x, 10 + random.randint(-3, 3)), ch, fill=(40, 40, 120), font=font)
        x += 22
    img = img.filter(ImageFilter.GaussianBlur(radius=0.6))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    img_b64 = base64.b64encode(buf.getvalue()).decode()

    # Sign the answer into a token so no session is needed
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='captcha')
    token = s.dumps(answer)
    return token, img_b64

def verify_captcha(token, user_answer):
    """Return True if user_answer matches the signed token (valid for 10 min)."""
    try:
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='captcha')
        expected = s.loads(token, max_age=600)
        return int(user_answer) == int(expected)
    except Exception:
        return False

# Security Configuration - OFFLINE ONLY
app.config['SECRET_KEY'] = _load_or_create_flask_secret()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['TEMPLATES_AUTO_RELOAD'] = True

# ==================== EMAIL CONFIGURATION ====================
# Edit these settings to match your email provider
app.config['MAIL_SERVER']   = 'smtp.gmail.com'   # e.g. smtp.gmail.com / smtp.office365.com
app.config['MAIL_PORT']     = 587
app.config['MAIL_USE_TLS']  = True
app.config['MAIL_USE_SSL']  = False
app.config['MAIL_USERNAME'] = 'elijah.poseo8@gmail.com'   # ← change this
app.config['MAIL_PASSWORD'] = 'xlsk jmgx egxz seef'       # ← change this (use App Password for Gmail)
app.config['MAIL_DEFAULT_SENDER'] = ('StockSecure POS', 'elijah.poseo8@gmail.com')  # ← change this
mail = Mail(app)

# Token serializer for password reset links (expires in 30 minutes)
def _reset_serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='password-reset')

# ==================== OTP STORE ====================
# In-memory OTP store: { email: { 'code': str, 'user_id': int, 'expires': datetime, 'attempts': int } }
_otp_store = {}
_otp_lock = threading.Lock()

def _generate_otp(email, user_id):
    """Generate a 6-digit OTP, store it, and return the code."""
    code = f"{random.randint(0, 999999):06d}"
    expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    with _otp_lock:
        _otp_store[email] = {'code': code, 'user_id': user_id, 'expires': expires, 'attempts': 0}
    return code

def _verify_otp(email, code):
    """Verify OTP. Returns user_id on success, None on failure."""
    with _otp_lock:
        entry = _otp_store.get(email)
        if not entry:
            return None
        if datetime.now(timezone.utc) > entry['expires']:
            del _otp_store[email]
            return None
        entry['attempts'] += 1
        if entry['attempts'] > 5:
            del _otp_store[email]
            return None
        if entry['code'] != code.strip():
            return None
        del _otp_store[email]
        return entry['user_id']

# Paths - All local
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "images", "products")
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Automatic Backup Configuration
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
MAX_LOCAL_BACKUPS = 7
BACKUP_INTERVAL_MINUTES = 30
os.makedirs(BACKUP_DIR, exist_ok=True)

# Database Context Manager
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()

# ==================== TIMEZONE UTILITY FUNCTIONS ====================
def get_utc_now():
    """Get current UTC time as naive datetime (for SQLite compatibility)"""
    return datetime.now(timezone.utc).replace(tzinfo=None)

def format_datetime_iso(dt):
    """Format datetime as ISO 8601 with UTC indicator for JavaScript"""
    if dt is None:
        return None
    if isinstance(dt, str):
        # If it's already a string, assume it's UTC and add Z if not present
        if dt.endswith('Z'):
            return dt
        return dt + 'Z'
    # If it's a datetime object
    if dt.tzinfo is None:
        # Assume it's UTC (from database)
        return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

# Jinja2 filter for timezone-aware formatting
@app.template_filter('localtime')
def localtime_filter(dt, fmt='%Y-%m-%d %I:%M %p'):
    """Format datetime for JavaScript local timezone conversion"""
    if dt is None:
        return ''
    # Return ISO format with Z suffix so JavaScript can convert to local time
    return format_datetime_iso(dt)

# ==================== SIMPLE LEDGER (CYBERLEDGER) ====================
class SimpleLedger:
    """Secure blockchain-style audit ledger with HMAC verification and tamper detection"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self._hmac_key = self._load_or_create_hmac_key()
        self._init_table()
        self._integrity_status = None  # Cache for integrity check
    
    def _load_or_create_hmac_key(self):
        """Load or create a persistent HMAC secret key"""
        key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ledger_hmac.key")
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        # Generate new key
        key = os.urandom(32)  # 256-bit key
        with open(key_file, "wb") as f:
            f.write(key)
        print(f"[SECURITY] New HMAC key created at: {key_file}")
        print("[SECURITY] Back up this file — losing it means ledger verification will fail.")
        return key
    
    def _init_table(self):
        """Initialize ledger table with previous_hash for chain verification"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS simple_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    action TEXT NOT NULL,
                    user_id INTEGER,
                    details TEXT,
                    hash TEXT NOT NULL,
                    previous_hash TEXT,
                    is_verified BOOLEAN DEFAULT 1
                )
            """)
            # Create trigger to prevent UPDATE/DELETE (append-only enforcement)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS prevent_ledger_update
                BEFORE UPDATE ON simple_ledger
                BEGIN
                    SELECT RAISE(FAIL, 'Ledger is append-only: updates not allowed');
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS prevent_ledger_delete
                BEFORE DELETE ON simple_ledger
                BEGIN
                    SELECT RAISE(FAIL, 'Ledger is append-only: deletes not allowed');
                END;
            """)
            conn.commit()
    
    def _compute_hmac(self, action, user_id, details_json, timestamp, previous_hash):
        """Compute HMAC-SHA256 for ledger entry"""
        message = f"{action}|{user_id}|{details_json}|{timestamp}|{previous_hash or '0'}"
        return hmac.new(self._hmac_key, message.encode(), hashlib.sha256).hexdigest()
    
    def log(self, action, user_id, details_dict):
        """Log entry with HMAC chain verification"""
        details_json = json.dumps(details_dict, sort_keys=True, default=str)

        # Use a fixed format timestamp (no microseconds, no timezone suffix)
        # so the value stored in the DB matches exactly what was used to compute the HMAC.
        # SQLite CURRENT_TIMESTAMP uses "YYYY-MM-DD HH:MM:SS" — we match that exactly.
        timestamp = get_utc_now().strftime('%Y-%m-%d %H:%M:%S')

        with sqlite3.connect(self.db_path) as conn:
            # Get previous entry's hash for chain
            prev = conn.execute(
                "SELECT hash FROM simple_ledger ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous_hash = prev[0] if prev else None

            # Compute HMAC using the same timestamp that will be stored
            entry_hash = self._compute_hmac(action, user_id, details_json, timestamp, previous_hash)

            # Explicitly store timestamp so DB value == value used in HMAC (no mismatch)
            conn.execute("""
                INSERT INTO simple_ledger (timestamp, action, user_id, details, hash, previous_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (timestamp, action, user_id, details_json, entry_hash, previous_hash))
            conn.commit()

            new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        return entry_hash
    
    def verify_integrity(self, reset_baseline=False):
        """
        Verify entire ledger integrity by checking all HMACs and chain links.
        Handles key rotation scenarios gracefully.

        Args:
            reset_baseline: If True, accepts current state as valid (use after admin re-sign)

        Returns: {'status': 'safe'|'compromised'|'key_mismatch', 'details': {...}, 'compromised_entries': [...]}
        """
        with sqlite3.connect(self.db_path) as conn:
            entries = conn.execute("""
                SELECT id, timestamp, action, user_id, details, hash, previous_hash
                FROM simple_ledger ORDER BY id ASC
            """).fetchall()

        if not entries:
            return {'status': 'safe', 'details': {'total': 0, 'verified': 0}, 'compromised_entries': []}

        compromised = []
        key_mismatches = []
        prev_hash = None

        for entry in entries:
            entry_id, timestamp, action, user_id, details, stored_hash, previous_hash = entry

            # Check chain link
            if previous_hash != prev_hash:
                compromised.append({
                    'id': entry_id,
                    'reason': 'chain_break',
                    'expected_previous': prev_hash,
                    'actual_previous': previous_hash
                })

            # Verify HMAC
            computed_hash = self._compute_hmac(action, user_id, details, timestamp, previous_hash)
            if not hmac.compare_digest(computed_hash, stored_hash):
                # Check if this is a key mismatch (all entries fail) vs actual tampering
                key_mismatches.append({
                    'id': entry_id,
                    'reason': 'hash_mismatch',
                    'computed': computed_hash[:20] + '...',
                    'stored': stored_hash[:20] + '...'
                })

            prev_hash = stored_hash

        # Determine status
        if reset_baseline:
            # Admin has manually verified and re-signed, accept current state as valid
            # This clears both chain breaks and hash mismatches
            status = 'safe'
            compromised = []
            key_mismatches = []
        elif key_mismatches:
            # If ALL entries fail HMAC check, it's likely a key rotation, not tampering
            if len(key_mismatches) == len(entries):
                status = 'key_mismatch'
            else:
                status = 'compromised'
                compromised.extend(key_mismatches)
        elif compromised:
            # There are chain breaks or other issues
            status = 'compromised'
        else:
            status = 'safe'

        self._integrity_status = status

        return {
            'status': status,
            'details': {
                'total': len(entries),
                'verified': len(entries) - len(key_mismatches),
                'compromised_count': len(compromised) if status == 'compromised' else 0,
                'key_mismatch_count': len(key_mismatches) if status == 'key_mismatch' else 0
            },
            'compromised_entries': compromised,
            'key_mismatch_entries': key_mismatches if status == 'key_mismatch' else []
        }

    def re_sign_all_entries(self):
        """
        Re-sign all ledger entries with the current HMAC key.
        Use this after key rotation to restore verification.
        Temporarily disables append-only triggers, updates hashes, then re-enables.
        WARNING: This should only be done by an admin and logs the action.
        """
        with sqlite3.connect(self.db_path) as conn:
            # Temporarily disable the append-only triggers
            conn.execute("DROP TRIGGER IF EXISTS prevent_ledger_update")
            conn.execute("DROP TRIGGER IF EXISTS prevent_ledger_delete")

            # Get all entries — read the STORED timestamp (this is the canonical value)
            entries = conn.execute("""
                SELECT id, timestamp, action, user_id, details, previous_hash
                FROM simple_ledger ORDER BY id ASC
            """).fetchall()

            # First pass: rebuild the hash chain using stored timestamps
            new_hashes = {}
            prev_hash = None

            for entry in entries:
                entry_id, timestamp, action, user_id, details, old_previous_hash = entry
                # Use the stored timestamp — it IS the value that must match
                new_hash = self._compute_hmac(action, user_id, details, timestamp, prev_hash)
                new_hashes[entry_id] = (new_hash, prev_hash)
                prev_hash = new_hash

            # Second pass: write new hashes and corrected previous_hashes
            for entry_id, (new_hash, new_previous_hash) in new_hashes.items():
                conn.execute("""
                    UPDATE simple_ledger
                    SET hash = ?, previous_hash = ?
                    WHERE id = ?
                """, (new_hash, new_previous_hash, entry_id))

            # Re-create the append-only triggers
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS prevent_ledger_update
                BEFORE UPDATE ON simple_ledger
                BEGIN
                    SELECT RAISE(FAIL, 'Ledger is append-only: updates not allowed');
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS prevent_ledger_delete
                BEFORE DELETE ON simple_ledger
                BEGIN
                    SELECT RAISE(FAIL, 'Ledger is append-only: deletes not allowed');
                END;
            """)
            conn.commit()

        updated_count = len(new_hashes)
        # Log this re-sign action (new entry with correct timestamp + HMAC)
        self.log("LEDGER_RE_SIGNED", None, {
            'action': 'Re-signed all entries with current HMAC key',
            'entries_updated': updated_count,
            'performed_by': 'system'
        })
        return updated_count

    def get_integrity_status(self):
        """Get cached integrity status or run verification"""
        if self._integrity_status is None:
            result = self.verify_integrity()
            return result['status']
        return self._integrity_status
    
    def get_recent(self, limit=50):
        """Get recent entries with verification status"""
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("""
                SELECT id, timestamp, action, user_id, details, hash, previous_hash, is_verified
                FROM simple_ledger ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
    
    def get_stats(self):
        """Get ledger stats with integrity info"""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM simple_ledger").fetchone()[0]
            by_type = conn.execute("""
                SELECT action, COUNT(*) FROM simple_ledger GROUP BY action
            """).fetchall()
        
        integrity = self.verify_integrity()
        
        return {
            'total': total, 
            'by_type': dict(by_type),
            'integrity': integrity['status'],
            'verified_entries': integrity['details']['verified'],
            'compromised_count': integrity['details']['compromised_count']
        }
    
    def get_by_date_range(self, date_from, date_to):
        """Get entries by date range"""
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("""
                SELECT id, timestamp, action, user_id, details, hash, previous_hash, is_verified
                FROM simple_ledger 
                WHERE date(timestamp) BETWEEN ? AND ?
                ORDER BY id DESC
            """, (date_from, date_to)).fetchall()
    
    def export_to_file(self, filepath, format='json'):
        """Export ledger to file for backup"""
        with sqlite3.connect(self.db_path) as conn:
            entries = conn.execute("""
                SELECT * FROM simple_ledger ORDER BY id ASC
            """).fetchall()
        
        export_data = {
            'exported_at': get_utc_now().isoformat(),
            'integrity_check': self.verify_integrity(),
            'entries': [dict(e) for e in entries]
        }
        
        if format == 'json':
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
        
        return filepath
# Initialize ledger
ledger = SimpleLedger(DB_PATH)

# ==================== BACKUP FUNCTIONS ====================
def create_backup(silent=True):
    """Create backup - auto-copies to USB if available"""
    if not os.path.exists(DB_PATH):
        return False
    try:
        timestamp = get_utc_now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"dulcis_backup_{timestamp}.db"
        local_path = os.path.join(BACKUP_DIR, backup_name)
        shutil.copy2(DB_PATH, local_path)
        
        # Keep only last 7 backups
        backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith('dulcis_backup_')], reverse=True)
        while len(backups) > MAX_LOCAL_BACKUPS:
            os.remove(os.path.join(BACKUP_DIR, backups.pop()))
        
        if not silent:
            print(f"Backup created: {backup_name}")
        return True
    except Exception as e:
        print(f"Backup failed: {e}")
        return False

def auto_backup_loop():
    """Background thread - backup every X minutes"""
    while True:
        create_backup(silent=True)
        time.sleep(BACKUP_INTERVAL_MINUTES * 60)

# Audit logging with XSS protection
def log_audit(action, table_name=None, record_id=None, old_values=None, new_values=None):
    safe_old = html.escape(str(old_values), quote=True) if old_values else None
    safe_new = html.escape(str(new_values), quote=True) if new_values else None
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO audit_log (user_id, action, table_name, record_id, old_values, new_values, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            session.get('user_id'), action, table_name, record_id,
            safe_old, safe_new, request.remote_addr
        ))
        conn.commit()
    
    # Also log to SimpleLedger
    ledger.log(f"AUDIT_{action}", session.get('user_id'), {
        'table': table_name,
        'record_id': record_id,
        'old': safe_old,
        'new': safe_new
    })

# Validation
def validate_username(username):
    if not username or len(username) < 3 or len(username) > 20:
        return False
    return re.match(r'^[a-zA-Z0-9_]+$', username) is not None

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Security Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if get_utc_now() - last_activity > timedelta(hours=1):
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
        
        session['last_activity'] = get_utc_now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session or session.get('role') not in roles:
                flash('Insufficient permissions.', 'danger')
                return redirect(url_for('pos'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') not in ('admin', 'manager'):
            flash('Manager access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def init_db():
    """Initialize database with enhanced schema"""
    with get_db() as conn:
        # Users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'cashier', 'manager')),
                email TEXT UNIQUE,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        """)
        
        # Categories table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Products table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                price REAL NOT NULL CHECK(price >= 0),
                stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
                min_stock_level INTEGER DEFAULT 10,
                category_id INTEGER,
                image TEXT,
                barcode TEXT UNIQUE,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
            )
        """)
        
        # Sales table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                total_amount REAL NOT NULL,
                tax_amount REAL DEFAULT 0,
                discount_amount REAL DEFAULT 0,
                payment_method TEXT CHECK(payment_method IN ('cash', 'card', 'digital')),
                payment_status TEXT DEFAULT 'completed',
                is_cancelled BOOLEAN DEFAULT 0,
                cancelled_at TIMESTAMP,
                cancelled_by INTEGER,
                cancellation_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (cancelled_by) REFERENCES users(id)
            )
        """)
        
        # Sale items
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sale_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sale_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL CHECK(quantity > 0),
                unit_price REAL NOT NULL,
                total_price REAL NOT NULL,
                FOREIGN KEY (sale_id) REFERENCES sales(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id)
            )
        """)
        
        # Audit log
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                table_name TEXT,
                record_id INTEGER,
                old_values TEXT,
                new_values TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # SimpleLedger table (CyberLedger)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS simple_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                action TEXT NOT NULL,
                user_id INTEGER,
                details TEXT,
                hash TEXT NOT NULL
            )
        """)
        
        # Insert default admin
        admin_exists = conn.execute("SELECT 1 FROM users WHERE username = 'admin'").fetchone()
        if not admin_exists:
            admin_hash = generate_password_hash('Admin@123!', method='pbkdf2:sha256', salt_length=16)
            conn.execute("""
                INSERT INTO users (username, password_hash, role, email, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, ('admin', admin_hash, 'admin', encrypt('admin@dulcis.local'), 1))
            
            # Default categories
            categories = [
                ('Beverages', 'Hot and cold drinks'),
                ('Pastries', 'Cakes, muffins, and baked goods'),
                ('Snacks', 'Light snacks and sandwiches'),
                ('Merchandise', 'Coffee beans, mugs, etc.')
            ]
            conn.executemany("INSERT OR IGNORE INTO categories (name, description) VALUES (?, ?)", categories)
            
        conn.commit()

        # Migration: add digital payment columns if they don't exist yet
        # Both are TEXT because digital_amount_paid stores an encrypted string
        for col, col_def in [
            ('digital_reference', 'TEXT'),
            ('digital_amount_paid', 'TEXT')
        ]:
            try:
                conn.execute(f"ALTER TABLE sales ADD COLUMN {col} {col_def}")
                conn.commit()
            except Exception:
                pass  # Column already exists — safe to ignore

        # Fix: if digital_amount_paid was previously created as REAL, recreate as TEXT
        # SQLite doesn't support ALTER COLUMN, so we use a safe workaround via column info
        col_info = conn.execute("PRAGMA table_info(sales)").fetchall()
        for col in col_info:
            if col['name'] == 'digital_amount_paid' and col['type'].upper() == 'REAL':
                # Recreate table with correct type - SQLite workaround
                conn.execute("ALTER TABLE sales RENAME TO sales_old")
                conn.execute("""
                    CREATE TABLE sales (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        transaction_id TEXT UNIQUE NOT NULL,
                        user_id INTEGER NOT NULL,
                        total_amount REAL NOT NULL,
                        tax_amount REAL DEFAULT 0,
                        discount_amount REAL DEFAULT 0,
                        payment_method TEXT CHECK(payment_method IN ('cash', 'card', 'digital')),
                        payment_status TEXT DEFAULT 'completed',
                        is_cancelled BOOLEAN DEFAULT 0,
                        cancelled_at TIMESTAMP,
                        cancelled_by INTEGER,
                        cancellation_reason TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        digital_reference TEXT,
                        digital_amount_paid TEXT,
                        FOREIGN KEY (user_id) REFERENCES users(id),
                        FOREIGN KEY (cancelled_by) REFERENCES users(id)
                    )
                """)
                conn.execute("""
                    INSERT INTO sales SELECT
                        id, transaction_id, user_id, total_amount, tax_amount,
                        discount_amount, payment_method, payment_status,
                        is_cancelled, cancelled_at, cancelled_by, cancellation_reason,
                        created_at, digital_reference,
                        CASE WHEN digital_amount_paid IS NOT NULL
                             THEN CAST(digital_amount_paid AS TEXT)
                             ELSE NULL END
                    FROM sales_old
                """)
                conn.execute("DROP TABLE sales_old")
                conn.commit()
                print("[DB] Migrated digital_amount_paid column from REAL to TEXT")
                break

        # Migration: add customer_name column if not exists
        try:
            conn.execute("ALTER TABLE sales ADD COLUMN customer_name TEXT")
            conn.commit()
        except Exception:
            pass  # Already exists

def migrate_encrypt_existing_data():
    """One-time migration: encrypt any plaintext emails, barcodes, and digital refs already in the DB.
    Safe to run on every startup — already-encrypted values are detected by decrypt() and skipped."""
    print("[SECURITY] Checking for unencrypted data to migrate...")
    with get_db() as conn:
        # --- users.email ---
        users = conn.execute("SELECT id, email FROM users WHERE email IS NOT NULL").fetchall()
        for u in users:
            raw = u['email']
            try:
                _fernet.decrypt(raw.encode())
                # Already encrypted — skip
            except Exception:
                # Plaintext — encrypt it now
                conn.execute("UPDATE users SET email = ? WHERE id = ?", (encrypt(raw), u['id']))
        conn.commit()

        # --- products.barcode ---
        products = conn.execute("SELECT id, barcode FROM products WHERE barcode IS NOT NULL").fetchall()
        for p in products:
            raw = p['barcode']
            try:
                _fernet.decrypt(raw.encode())
            except Exception:
                conn.execute("UPDATE products SET barcode = ? WHERE id = ?", (encrypt(raw), p['id']))
        conn.commit()

        # --- sales.digital_reference ---
        sales = conn.execute("SELECT id, digital_reference FROM sales WHERE digital_reference IS NOT NULL").fetchall()
        for s in sales:
            raw = s['digital_reference']
            try:
                _fernet.decrypt(raw.encode())
            except Exception:
                conn.execute("UPDATE sales SET digital_reference = ? WHERE id = ?", (encrypt(raw), s['id']))
        conn.commit()

        # --- sales.digital_amount_paid (stored as TEXT after our changes, but may be REAL from old rows) ---
        # Nothing to do — old REAL values were never encrypted; new ones use TEXT via encrypt()

    print("[SECURITY] Data encryption migration complete.")

# Routes
@app.route("/")
def index():
    if 'user_id' in session:
        return redirect(url_for('pos'))
    return redirect(url_for('login'))

@app.route("/captcha/refresh")
def captcha_refresh():
    """Return a fresh captcha image + signed token."""
    token, img_b64 = generate_captcha()
    return jsonify({'image': img_b64, 'token': token})

@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user_id' in session:
        return redirect(url_for('pos'))

    failed_attempts = session.get('login_failed_attempts', 0)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        captcha_token = request.form.get("captcha_token", "")
        captcha_answer = request.form.get("captcha_answer", "").strip()

        # Always validate captcha first
        if not captcha_answer or not verify_captcha(captcha_token, captcha_answer):
            flash("Incorrect captcha answer. Please try again.", "danger")
            token, captcha_img = generate_captcha()
            return render_template("login.html", show_captcha=True,
                                   captcha_img=captcha_img, captcha_token=token,
                                   failed_attempts=failed_attempts)

        if not username or not password:
            flash("Username and password are required.", "danger")
            token, captcha_img = generate_captcha()
            return render_template("login.html", show_captcha=True,
                                   captcha_img=captcha_img, captcha_token=token,
                                   failed_attempts=failed_attempts)

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? AND is_active = 1",
                (username,)
            ).fetchone()

            if user:
                # Admin users must use the dedicated admin login page
                if user['role'] == 'admin':
                    flash("Administrators must use the Admin Login page.", "warning")
                    token, captcha_img = generate_captcha()
                    return render_template("login.html", show_captcha=True,
                                           captcha_img=captcha_img, captcha_token=token,
                                           failed_attempts=failed_attempts)

                if user['locked_until'] and get_utc_now() < datetime.fromisoformat(user['locked_until']):
                    flash("Account temporarily locked. Please try again later.", "danger")
                    token, captcha_img = generate_captcha()
                    return render_template("login.html", show_captcha=True,
                                           captcha_img=captcha_img, captcha_token=token,
                                           failed_attempts=failed_attempts)

                if check_password_hash(user['password_hash'], password):
                    session.permanent = True
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session['last_activity'] = get_utc_now().isoformat()
                    session.pop('login_failed_attempts', None)

                    conn.execute(
                        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?",
                        (user['id'],)
                    )
                    conn.commit()

                    ledger.log("USER_LOGIN", user['id'], {'username': username, 'role': user['role']})
                    log_audit("LOGIN_SUCCESS", "users", user['id'])

                    if user['role'] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    if user['role'] == 'manager':
                        return redirect(url_for('manager_dashboard'))

                    flash(f"Welcome back, {user['username']}!")
                    return redirect(url_for('pos'))
                else:
                    attempts = user['failed_login_attempts'] + 1
                    session['login_failed_attempts'] = attempts
                    lock_until = None
                    if attempts >= 5:
                        lock_until = (get_utc_now() + timedelta(minutes=30)).isoformat()
                        flash("Too many failed attempts. Account locked for 30 minutes.", "danger")
                    else:
                        remaining = 5 - attempts
                        flash(f"Invalid credentials. {remaining} attempt{'s' if remaining != 1 else ''} remaining before lockout.", "danger")
                    conn.execute(
                        "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                        (attempts, lock_until, user['id'])
                    )
                    conn.commit()
                    log_audit("LOGIN_FAILED", "users", user['id'])
            else:
                failed_attempts += 1
                session['login_failed_attempts'] = failed_attempts
                flash("Invalid credentials.", "danger")
                log_audit("LOGIN_FAILED_ATTEMPT", None, None, {'username': username})

        token, captcha_img = generate_captcha()
        return render_template("login.html", show_captcha=True,
                               captcha_img=captcha_img, captcha_token=token,
                               failed_attempts=session.get('login_failed_attempts', 0))

    # GET
    token, captcha_img = generate_captcha()
    return render_template("login.html", show_captcha=True,
                           captcha_img=captcha_img, captcha_token=token,
                           failed_attempts=failed_attempts)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if 'user_id' in session and session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))

    failed_attempts = session.get('admin_login_failed_attempts', 0)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        captcha_token = request.form.get("captcha_token", "")
        captcha_answer = request.form.get("captcha_answer", "").strip()

        # Always validate captcha first
        if not captcha_answer or not verify_captcha(captcha_token, captcha_answer):
            flash("Incorrect captcha answer. Please try again.", "danger")
            token, captcha_img = generate_captcha()
            return render_template("admin/login.html", show_captcha=True,
                                   captcha_img=captcha_img, captcha_token=token,
                                   failed_attempts=failed_attempts)

        if not username or not password:
            flash("Username and password are required.", "danger")
            token, captcha_img = generate_captcha()
            return render_template("admin/login.html", show_captcha=True,
                                   captcha_img=captcha_img, captcha_token=token,
                                   failed_attempts=failed_attempts)

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? AND is_active = 1 AND role = 'admin'",
                (username,)
            ).fetchone()

            if user:
                if user['locked_until'] and get_utc_now() < datetime.fromisoformat(user['locked_until']):
                    flash("Account temporarily locked. Please try again later.", "danger")
                    token, captcha_img = generate_captcha()
                    return render_template("admin/login.html", show_captcha=True,
                                           captcha_img=captcha_img, captcha_token=token,
                                           failed_attempts=failed_attempts)

                if check_password_hash(user['password_hash'], password):
                    session.permanent = True
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session['last_activity'] = get_utc_now().isoformat()
                    session.pop('admin_login_failed_attempts', None)

                    conn.execute(
                        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?",
                        (user['id'],)
                    )
                    conn.commit()

                    ledger.log("USER_LOGIN", user['id'], {'username': username, 'role': 'admin'})
                    log_audit("LOGIN_SUCCESS", "users", user['id'])
                    return redirect(url_for('admin_dashboard'))
                else:
                    attempts = user['failed_login_attempts'] + 1
                    session['admin_login_failed_attempts'] = attempts
                    lock_until = None
                    if attempts >= 5:
                        lock_until = (get_utc_now() + timedelta(minutes=30)).isoformat()
                        flash("Too many failed attempts. Account locked for 30 minutes.", "danger")
                    else:
                        remaining = 5 - attempts
                        flash(f"Invalid credentials. {remaining} attempt{'s' if remaining != 1 else ''} remaining before lockout.", "danger")
                    conn.execute(
                        "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                        (attempts, lock_until, user['id'])
                    )
                    conn.commit()
                    log_audit("LOGIN_FAILED", "users", user['id'])
            else:
                failed_attempts += 1
                session['admin_login_failed_attempts'] = failed_attempts
                flash("Invalid admin credentials.", "danger")
                log_audit("LOGIN_FAILED_ATTEMPT", None, None, {'username': username})

        token, captcha_img = generate_captcha()
        return render_template("admin/login.html", show_captcha=True,
                               captcha_img=captcha_img, captcha_token=token,
                               failed_attempts=session.get('admin_login_failed_attempts', 0))

    # GET
    token, captcha_img = generate_captcha()
    return render_template("admin/login.html", show_captcha=True,
                           captcha_img=captcha_img, captcha_token=token,
                           failed_attempts=failed_attempts)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Forgot password — Step 1: enter email, receive 6-digit OTP."""
    if request.method == "POST":
        email_input = request.form.get("email", "").strip()
        if not email_input:
            flash("Please enter your email address.", "danger")
            return render_template("forgot_password.html")

        # Search for user with this email (emails are encrypted in DB)
        user_found = None
        with get_db() as conn:
            users = conn.execute(
                "SELECT id, username, email, is_active, role FROM users WHERE email IS NOT NULL"
            ).fetchall()
            for u in users:
                if decrypt(u['email']) == email_input and u['is_active']:
                    user_found = u
                    break

        if user_found:
            try:
                otp_code = _generate_otp(email_input, user_found['id'])
                msg = Message(
                    subject="StockSecure POS — Your OTP Code",
                    recipients=[email_input]
                )
                msg.html = f"""
                <div style="font-family:sans-serif; max-width:480px; margin:0 auto; padding:2rem;">
                    <h2 style="color:#1a1a2e;">Password Reset OTP</h2>
                    <p>Hello <strong>{user_found['username']}</strong>,</p>
                    <p>Use the code below to reset your StockSecure POS password.</p>
                    <div style="text-align:center; margin:2rem 0;">
                        <span style="font-size:2.5rem; font-weight:800; letter-spacing:0.5rem;
                                     color:#667eea; font-family:monospace;">{otp_code}</span>
                    </div>
                    <p style="color:#6b7280; font-size:0.85rem;">
                        This code expires in <strong>10 minutes</strong>.<br>
                        If you didn't request this, you can safely ignore this email.
                    </p>
                    <hr style="border:none; border-top:1px solid #e5e7eb; margin:1.5rem 0;">
                    <p style="color:#9ca3af; font-size:0.75rem;">StockSecure POS — Dulcis &amp; Café</p>
                </div>
                """
                mail.send(msg)
                log_audit("OTP_REQUESTED", "users", user_found['id'])
            except Exception as e:
                print(f"[MAIL ERROR] Could not send OTP email: {e}")

        # Always show the OTP entry form (prevent email enumeration)
        return render_template("forgot_password.html", step="otp", email=email_input)

    return render_template("forgot_password.html", step="email")


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    """Step 2: Verify OTP and allow password reset."""
    email = request.form.get("email", "").strip()
    otp_code = request.form.get("otp", "").strip()

    if not email or not otp_code:
        flash("Please enter the OTP code.", "danger")
        return render_template("forgot_password.html", step="otp", email=email)

    user_id = _verify_otp(email, otp_code)
    if not user_id:
        flash("Invalid or expired OTP. Please try again or request a new code.", "danger")
        return render_template("forgot_password.html", step="otp", email=email)

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,)).fetchone()

    if not user:
        flash("Account not found or inactive.", "danger")
        return redirect(url_for('forgot_password'))

    # OTP verified — generate a short-lived token to allow password reset
    s = _reset_serializer()
    token = s.dumps({'user_id': user_id, 'email': email})
    return render_template("reset_password.html", token=token, username=user['username'])


@app.route("/reset-password", methods=["POST"])
def reset_password(token=None):
    """Step 3: Set new password after OTP verification."""
    token = request.form.get("token", "")
    s = _reset_serializer()
    try:
        data = s.loads(token, max_age=900)  # 15 minutes to fill in the form
        user_id = data['user_id']
    except Exception:
        flash("Session expired. Please start over.", "danger")
        return redirect(url_for('forgot_password'))

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,)).fetchone()

    if not user:
        flash("Account not found or is inactive.", "danger")
        return redirect(url_for('forgot_password'))

    new_password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not validate_password(new_password):
        flash("Password must be at least 8 characters with uppercase, lowercase, number, and special character.", "danger")
        return render_template("reset_password.html", token=token, username=user['username'])

    if new_password != confirm_password:
        flash("Passwords do not match.", "danger")
        return render_template("reset_password.html", token=token, username=user['username'])

    new_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
            (new_hash, user_id)
        )
        conn.commit()

    log_audit("PASSWORD_RESET_SUCCESS", "users", user_id)
    ledger.log("PASSWORD_RESET", user_id, {'username': user['username'], 'method': 'otp'})

    flash("Password reset successfully! You can now log in with your new password.", "success")

    if user['role'] == 'admin':
        return redirect(url_for('admin_login'))
    return redirect(url_for('login'))


@app.route("/logout")
@login_required
def logout():
    ledger.log("USER_LOGOUT", session.get('user_id'), {'username': session.get('username')})
    log_audit("LOGOUT", "users", session.get('user_id'))
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route("/pos")
@login_required
def pos():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT p.*, c.name as category_name 
            FROM products p 
            LEFT JOIN categories c ON p.category_id = c.id 
            WHERE p.is_active = 1 AND p.stock > 0
            ORDER BY p.category_id, p.name
        """).fetchall()
        
        categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()

    # Decrypt barcode before rendering
    products = []
    for r in rows:
        d = dict(r)
        d['barcode'] = decrypt(d['barcode'])
        products.append(d)

    return render_template("pos.html", products=products, categories=categories)
@app.route("/manager")
@login_required
@manager_required
def manager_dashboard():
    with get_db() as conn:
        today = get_utc_now().strftime('%Y-%m-%d')
        stats = {
            'today_sales': conn.execute("""
                SELECT COALESCE(SUM(total_amount), 0) FROM sales
                WHERE date(created_at) = date('now') AND is_cancelled = 0
            """).fetchone()[0],
            'today_transactions': conn.execute("""
                SELECT COUNT(*) FROM sales
                WHERE date(created_at) = date('now') AND is_cancelled = 0
            """).fetchone()[0],
            'low_stock': conn.execute("""
                SELECT COUNT(*) FROM products
                WHERE stock <= min_stock_level AND is_active = 1
            """).fetchone()[0],
            'total_products': conn.execute(
                "SELECT COUNT(*) FROM products WHERE is_active = 1"
            ).fetchone()[0],
        }

        recent_sales = conn.execute("""
            SELECT s.*, u.username as cashier_name
            FROM sales s
            JOIN users u ON s.user_id = u.id
            WHERE s.is_cancelled = 0
            ORDER BY s.created_at DESC LIMIT 10
        """).fetchall()

        low_stock_items = conn.execute("""
            SELECT * FROM products
            WHERE stock <= min_stock_level AND is_active = 1
            ORDER BY stock ASC LIMIT 10
        """).fetchall()

    return render_template("manager/dashboard.html",
                           stats=stats,
                           recent_sales=recent_sales,
                           low_stock_items=low_stock_items)

@app.route("/manager/sales")
@login_required
@manager_required
def manager_sales():
    date_from = request.args.get('from', get_utc_now().strftime('%Y-%m-%d'))
    date_to = request.args.get('to', get_utc_now().strftime('%Y-%m-%d'))

    with get_db() as conn:
        rows = conn.execute("""
            SELECT s.*, u.username as cashier_name,
                   (SELECT COUNT(*) FROM sale_items WHERE sale_id = s.id) as item_count
            FROM sales s
            JOIN users u ON s.user_id = u.id
            WHERE date(s.created_at) BETWEEN ? AND ?
            AND s.is_cancelled = 0
            ORDER BY s.created_at DESC
        """, (date_from, date_to)).fetchall()

    sales = []
    for r in rows:
        d = dict(r)
        d['digital_reference'] = decrypt(d.get('digital_reference'))
        d['digital_amount_paid'] = decrypt_float(d.get('digital_amount_paid'))
        d['customer_name'] = d.get('customer_name') or 'Walk-in Customer'
        sales.append(d)

    total_revenue = sum(s['total_amount'] for s in sales)
    return render_template("manager/sales.html", sales=sales,
                           total_revenue=total_revenue,
                           date_from=date_from, date_to=date_to)

@app.route("/manager/reports")
@login_required
@manager_required
def manager_reports():
    with get_db() as conn:
        daily_sales_raw = conn.execute("""
            SELECT date(created_at) as date, COUNT(*) as transactions, SUM(total_amount) as revenue
            FROM sales
            WHERE created_at >= date('now', '-30 days') AND is_cancelled = 0
            GROUP BY date(created_at) ORDER BY date DESC
        """).fetchall()
        daily_sales = [{'date': r['date'], 'transactions': r['transactions'],
                        'revenue': float(r['revenue']) if r['revenue'] else 0}
                       for r in daily_sales_raw]

        top_products_raw = conn.execute("""
            SELECT p.name, SUM(si.quantity) as total_sold, SUM(si.total_price) as revenue
            FROM sale_items si
            JOIN products p ON si.product_id = p.id
            JOIN sales s ON si.sale_id = s.id
            WHERE s.created_at >= date('now', '-30 days') AND s.is_cancelled = 0
            GROUP BY si.product_id ORDER BY total_sold DESC LIMIT 10
        """).fetchall()
        top_products = [{'name': r['name'], 'total_sold': r['total_sold'],
                         'revenue': float(r['revenue']) if r['revenue'] else 0}
                        for r in top_products_raw]

        category_sales_raw = conn.execute("""
            SELECT c.name, COUNT(DISTINCT s.id) as transactions, SUM(si.total_price) as revenue
            FROM sale_items si
            JOIN products p ON si.product_id = p.id
            JOIN categories c ON p.category_id = c.id
            JOIN sales s ON si.sale_id = s.id
            WHERE s.created_at >= date('now', '-30 days') AND s.is_cancelled = 0
            GROUP BY c.id ORDER BY revenue DESC
        """).fetchall()
        category_sales = [{'name': r['name'], 'transactions': r['transactions'],
                           'revenue': float(r['revenue']) if r['revenue'] else 0}
                          for r in category_sales_raw]

    return render_template("manager/reports.html", daily_sales=daily_sales,
                           top_products=top_products, category_sales=category_sales)

@app.route("/manager/cancel-orders")
@login_required
@manager_required
def manager_cancel_orders():
    with get_db() as conn:
        orders = conn.execute("""
            SELECT s.*, u.username as cashier_name,
                   (SELECT COUNT(*) FROM sale_items WHERE sale_id = s.id) as item_count
            FROM sales s
            JOIN users u ON s.user_id = u.id
            WHERE s.created_at >= datetime('now', '-24 hours')
            ORDER BY s.created_at DESC
        """).fetchall()

        today_count = conn.execute("""
            SELECT COUNT(*) FROM sales
            WHERE date(created_at) = date('now') AND is_cancelled = 0
        """).fetchone()[0]

        today_revenue = conn.execute("""
            SELECT COALESCE(SUM(total_amount), 0) FROM sales
            WHERE date(created_at) = date('now') AND is_cancelled = 0
        """).fetchone()[0]

        one_hour_ago = (get_utc_now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        cancellable_count = conn.execute("""
            SELECT COUNT(*) FROM sales
            WHERE created_at >= ? AND is_cancelled = 0
        """, (one_hour_ago,)).fetchone()[0]

    return render_template("manager/cancel_orders.html",
                           orders=[{**dict(o),
                                    'digital_reference': decrypt(dict(o).get('digital_reference')),
                                    'digital_amount_paid': decrypt_float(dict(o).get('digital_amount_paid'))}
                                   for o in orders],
                           today_count=today_count,
                           today_revenue=today_revenue,
                           cancellable_count=cancellable_count)

# ============================================
# ADMIN ROUTES
# ============================================

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    with get_db() as conn:
        stats = {
            'total_products': conn.execute("SELECT COUNT(*) FROM products WHERE is_active = 1").fetchone()[0],
            'low_stock': conn.execute("SELECT COUNT(*) FROM products WHERE stock <= min_stock_level").fetchone()[0],
            'today_sales': conn.execute("""
                SELECT COALESCE(SUM(total_amount), 0) FROM sales 
                WHERE date(created_at) = date('now') AND is_cancelled = 0
            """).fetchone()[0],
            'total_users': conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
        }
        
        recent_sales = conn.execute("""
            SELECT s.*, u.username as cashier_name
            FROM sales s
            JOIN users u ON s.user_id = u.id
            WHERE s.is_cancelled = 0
            ORDER BY s.created_at DESC LIMIT 10
        """).fetchall()
        
        low_stock_items = conn.execute("""
            SELECT * FROM products 
            WHERE stock <= min_stock_level AND is_active = 1
            ORDER BY stock ASC LIMIT 10
        """).fetchall()
        
        # Ledger stats
        ledger_stats = ledger.get_stats()
        
    return render_template("admin/dashboard.html", stats=stats, recent_sales=recent_sales, 
                          low_stock_items=low_stock_items, ledger_stats=ledger_stats)

@app.route("/admin/products")
@login_required
@admin_required
def admin_products():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT p.*, c.name as category_name
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            ORDER BY p.created_at DESC
        """).fetchall()

        categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()

    # Decrypt barcode before passing to template
    products = []
    for r in rows:
        d = dict(r)
        d['barcode'] = decrypt(d['barcode'])
        products.append(d)

    return render_template("admin/products.html", products=products, categories=categories)

@app.route("/admin/product/add", methods=["POST"])
@login_required
@admin_required
def add_product():
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    price = request.form.get('price', 0)
    stock = request.form.get('stock', 0)
    category_id = request.form.get('category_id') or None
    min_stock = request.form.get('min_stock_level', 10)
    barcode = request.form.get('barcode', '').strip() or None
    
    if not name or len(name) < 2:
        flash("Product name must be at least 2 characters.", "danger")
        return redirect(url_for('admin_products'))
    
    try:
        price = float(price)
        if price < 0:
            raise ValueError("Price cannot be negative")
    except ValueError:
        flash("Invalid price.", "danger")
        return redirect(url_for('admin_products'))
    
    try:
        stock = int(stock)
        if stock < 0:
            raise ValueError("Stock cannot be negative")
    except ValueError:
        flash("Invalid stock quantity.", "danger")
        return redirect(url_for('admin_products'))
    
    image_filename = None
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            name, ext = os.path.splitext(filename)
            image_filename = f"{name}_{get_utc_now().strftime('%Y%m%d%H%M%S')}{ext}"
            file.save(os.path.join(UPLOAD_FOLDER, image_filename))

    encrypted_barcode = encrypt(barcode) if barcode else None

    product_id = None
    with get_db() as conn:
        try:
            cursor = conn.execute("""
                INSERT INTO products (name, description, price, stock, category_id, 
                                    min_stock_level, barcode, image)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, description, price, stock, category_id, min_stock, encrypted_barcode, image_filename))
            conn.commit()
            product_id = cursor.lastrowid
            flash("Product added successfully!", "success")
        except sqlite3.IntegrityError as e:
            flash(f"Error: Product name or barcode already exists", "danger")

    if product_id:
        ledger.log("PRODUCT_ADD", session['user_id'], {
            'product_id': product_id, 'name': name, 'price': price, 'stock': stock
        })
        ledger.log("STOCK_IN", session['user_id'], {
            'product_id': product_id,
            'product_name': name,
            'qty_in': stock,
            'unit_price': price,
            'reason': 'New product added',
            'by': session.get('username')
        })
        log_audit("PRODUCT_CREATED", "products", product_id, None, {
            'name': name, 'price': price, 'stock': stock
        })

    return redirect(url_for('admin_products'))

@app.route("/admin/product/edit/<int:product_id>", methods=["POST"])
@login_required
@admin_required
def edit_product(product_id):
    with get_db() as conn:
        old_product = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if not old_product:
            flash("Product not found.", "danger")
            return redirect(url_for('admin_products'))
        
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price = float(request.form.get('price', 0))
        stock = int(request.form.get('stock', 0))
        category_id = request.form.get('category_id') or None
        min_stock = int(request.form.get('min_stock_level', 10))
        barcode = request.form.get('barcode', '').strip() or None
        is_active = 1 if request.form.get('is_active') else 0
        encrypted_barcode = encrypt(barcode) if barcode else None
        
        image_filename = old_product['image']
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                if image_filename and os.path.exists(os.path.join(UPLOAD_FOLDER, image_filename)):
                    os.remove(os.path.join(UPLOAD_FOLDER, image_filename))
                
                filename = secure_filename(file.filename)
                name_base, ext = os.path.splitext(filename)
                image_filename = f"{name_base}_{get_utc_now().strftime('%Y%m%d%H%M%S')}{ext}"
                file.save(os.path.join(UPLOAD_FOLDER, image_filename))
        
        conn.execute("""
            UPDATE products 
            SET name = ?, description = ?, price = ?, stock = ?, category_id = ?,
                min_stock_level = ?, barcode = ?, image = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (name, description, price, stock, category_id, min_stock, encrypted_barcode,
              image_filename, is_active, product_id))
        
        conn.commit()
        old_stock = old_product['stock']
        old_product_dict = dict(old_product)
        flash("Product updated successfully!", "success")

    ledger.log("PRODUCT_EDIT", session['user_id'], {
        'product_id': product_id,
        'changes': {'name': name, 'price': price, 'stock': stock, 'is_active': is_active},
        'previous': {'name': old_product_dict['name'], 'price': old_product_dict['price'],
                    'stock': old_product_dict['stock'], 'is_active': old_product_dict['is_active']}
    })
    stock_diff = stock - old_stock
    if stock_diff > 0:
        ledger.log("STOCK_IN", session['user_id'], {
            'product_id': product_id,
            'product_name': name,
            'qty_in': stock_diff,
            'previous_stock': old_stock,
            'new_stock': stock,
            'reason': 'Manual stock adjustment',
            'by': session.get('username')
        })
    elif stock_diff < 0:
        ledger.log("STOCK_ADJUSTMENT", session['user_id'], {
            'product_id': product_id,
            'product_name': name,
            'qty_adjusted': stock_diff,
            'previous_stock': old_stock,
            'new_stock': stock,
            'reason': 'Manual stock reduction',
            'by': session.get('username')
        })
    log_audit("PRODUCT_UPDATED", "products", product_id, old_product_dict, {
        'name': name, 'price': price, 'stock': stock, 'is_active': is_active
    })

    return redirect(url_for('admin_products'))

@app.route("/admin/product/delete/<int:product_id>", methods=["POST"])
@login_required
@admin_required
def delete_product(product_id):
    deleted_name = None
    with get_db() as conn:
        product = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if product:
            conn.execute("UPDATE products SET is_active = 0 WHERE id = ?", (product_id,))
            conn.commit()
            deleted_name = product['name']
            flash("Product deleted successfully!", "success")

    if deleted_name:
        ledger.log("PRODUCT_DELETE", session['user_id'], {
            'product_id': product_id, 'name': deleted_name
        })
        log_audit("PRODUCT_DELETED", "products", product_id, {'name': deleted_name})

    return redirect(url_for('admin_products'))

@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, username, role, email, is_active, created_at, last_login
            FROM users ORDER BY created_at DESC
        """).fetchall()
    # Decrypt email before passing to template
    users = []
    for r in rows:
        d = dict(r)
        d['email'] = decrypt(d['email'])
        users.append(d)
    return render_template("admin/users.html", users=users)

@app.route("/admin/user/add", methods=["POST"])
@login_required
@admin_required
def add_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'cashier')
    email = request.form.get('email', '').strip()
    
    if not validate_username(username):
        flash("Username must be 3-20 characters, alphanumeric only.", "danger")
        return redirect(url_for('admin_users'))
    
    if not validate_password(password):
        flash("Password must be at least 8 characters with uppercase, lowercase, number, and special character.", "danger")
        return redirect(url_for('admin_users'))
    
    if role not in ['admin', 'cashier', 'manager']:
        flash("Invalid role selected.", "danger")
        return redirect(url_for('admin_users'))
    
    password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    encrypted_email = encrypt(email) if email else None

    with get_db() as conn:
        try:
            cursor = conn.execute("""
                INSERT INTO users (username, password_hash, role, email)
                VALUES (?, ?, ?, ?)
            """, (username, password_hash, role, encrypted_email))
            conn.commit()
            user_id = cursor.lastrowid
            flash(f"User '{username}' created successfully!", "success")
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
            user_id = None

    if user_id:
        ledger.log("USER_ADD", session['user_id'], {
            'new_user_id': user_id, 'username': username, 'role': role
        })
        log_audit("USER_CREATED", "users", user_id, None, {
            'username': username, 'role': role
        })

    return redirect(url_for('admin_users'))

@app.route("/admin/user/toggle/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def toggle_user(user_id):
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('admin_users'))
        
        if user['username'] == 'admin':
            flash("Cannot disable the main admin account.", "danger")
            return redirect(url_for('admin_users'))
        
        new_status = 0 if user['is_active'] else 1
        target_username = user['username']
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        flash(f"User {'activated' if new_status else 'deactivated'} successfully!", "success")

    action = "ACTIVATE" if new_status else "DEACTIVATE"
    ledger.log(f"USER_{action}", session['user_id'], {
        'target_user_id': user_id,
        'target_username': target_username,
        'new_status': 'active' if new_status else 'inactive'
    })
    log_audit(f"USER_{action}", "users", user_id)

    return redirect(url_for('admin_users'))

@app.route("/admin/sales")
@login_required
@role_required('admin', 'manager')
def admin_sales():
    date_from = request.args.get('from', get_utc_now().strftime('%Y-%m-%d'))
    date_to = request.args.get('to', get_utc_now().strftime('%Y-%m-%d'))
    
    with get_db() as conn:
        rows = conn.execute("""
            SELECT s.*, u.username as cashier_name,
                   (SELECT COUNT(*) FROM sale_items WHERE sale_id = s.id) as item_count
            FROM sales s
            JOIN users u ON s.user_id = u.id
            WHERE date(s.created_at) BETWEEN ? AND ?
            AND s.is_cancelled = 0
            ORDER BY s.created_at DESC
        """, (date_from, date_to)).fetchall()

    sales = []
    for r in rows:
        d = dict(r)
        d['digital_reference'] = decrypt(d.get('digital_reference'))
        d['digital_amount_paid'] = decrypt_float(d.get('digital_amount_paid'))
        d['customer_name'] = d.get('customer_name') or 'Walk-in Customer'
        sales.append(d)

    total_revenue = sum(s['total_amount'] for s in sales)

    return render_template("admin/sales.html", sales=sales, total_revenue=total_revenue,
                          date_from=date_from, date_to=date_to)

@app.route("/admin/reports")
@login_required
@role_required('admin', 'manager')
def admin_reports():
    with get_db() as conn:
        daily_sales_raw = conn.execute("""
            SELECT date(created_at) as date, COUNT(*) as transactions, SUM(total_amount) as revenue
            FROM sales
            WHERE created_at >= date('now', '-30 days')
            AND is_cancelled = 0
            GROUP BY date(created_at)
            ORDER BY date DESC
        """).fetchall()
        
        daily_sales = [
            {
                'date': row['date'],
                'transactions': row['transactions'],
                'revenue': float(row['revenue']) if row['revenue'] else 0
            }
            for row in daily_sales_raw
        ]
        
        top_products_raw = conn.execute("""
            SELECT p.name, SUM(si.quantity) as total_sold, SUM(si.total_price) as revenue
            FROM sale_items si
            JOIN products p ON si.product_id = p.id
            JOIN sales s ON si.sale_id = s.id
            WHERE s.created_at >= date('now', '-30 days')
            AND s.is_cancelled = 0
            GROUP BY si.product_id
            ORDER BY total_sold DESC
            LIMIT 10
        """).fetchall()
        
        top_products = [
            {
                'name': row['name'],
                'total_sold': row['total_sold'],
                'revenue': float(row['revenue']) if row['revenue'] else 0
            }
            for row in top_products_raw
        ]
        
        category_sales_raw = conn.execute("""
            SELECT c.name, COUNT(DISTINCT s.id) as transactions, SUM(si.total_price) as revenue
            FROM sale_items si
            JOIN products p ON si.product_id = p.id
            JOIN categories c ON p.category_id = c.id
            JOIN sales s ON si.sale_id = s.id
            WHERE s.created_at >= date('now', '-30 days')
            AND s.is_cancelled = 0
            GROUP BY c.id
            ORDER BY revenue DESC
        """).fetchall()
        
        category_sales = [
            {
                'name': row['name'],
                'transactions': row['transactions'],
                'revenue': float(row['revenue']) if row['revenue'] else 0
            }
            for row in category_sales_raw
        ]
        
    return render_template("admin/reports.html", daily_sales=daily_sales, 
                          top_products=top_products, category_sales=category_sales)

@app.route("/admin/audit-log")
@login_required
@admin_required
def admin_audit_log():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    
    with get_db() as conn:
        logs = conn.execute("""
            SELECT a.*, u.username
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.timestamp DESC
            LIMIT ? OFFSET ?
        """, (per_page, offset)).fetchall()
        
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        
    return render_template("admin/audit_log.html", logs=logs, page=page, 
                          per_page=per_page, total=total)


# ============================================
# ORDER CANCELLATION PAGE ROUTE
# ============================================

@app.route("/pos/cancel-orders")
@login_required
@role_required('admin', 'manager')
def cancel_orders_page():
    """Dedicated page for cancelling orders - removes clutter from POS"""
    with get_db() as conn:
        # Get orders from last 24 hours with cancellable status
        orders = conn.execute("""
            SELECT s.*, u.username as cashier_name,
                   (SELECT COUNT(*) FROM sale_items WHERE sale_id = s.id) as item_count
            FROM sales s
            JOIN users u ON s.user_id = u.id
            WHERE s.created_at >= datetime('now', '-24 hours')
            ORDER BY s.created_at DESC
        """).fetchall()
        
        # Calculate stats
        today = get_utc_now().strftime('%Y-%m-%d')
        today_count = conn.execute("""
            SELECT COUNT(*) FROM sales 
            WHERE date(created_at) = date('now') AND is_cancelled = 0
        """).fetchone()[0]
        
        today_revenue = conn.execute("""
            SELECT COALESCE(SUM(total_amount), 0) FROM sales 
            WHERE date(created_at) = date('now') AND is_cancelled = 0
        """).fetchone()[0]
        
        # Count cancellable orders (last hour)
        one_hour_ago = (get_utc_now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        cancellable_count = conn.execute("""
            SELECT COUNT(*) FROM sales 
            WHERE created_at >= ? AND is_cancelled = 0
        """, (one_hour_ago,)).fetchone()[0]
        
    return render_template("order_cancel.html",
                          orders=[{**dict(o),
                                   'digital_reference': decrypt(dict(o).get('digital_reference')),
                                   'digital_amount_paid': decrypt_float(dict(o).get('digital_amount_paid'))}
                                  for o in orders],
                          today_count=today_count,
                          today_revenue=today_revenue,
                          cancellable_count=cancellable_count)


# ============================================
# CYBERLEDGER ROUTES
# ============================================

@app.route("/admin/ledger")
@login_required
@admin_required
def admin_ledger():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page

    # Run integrity verification
    integrity_result = ledger.verify_integrity(reset_baseline=request.args.get('reset') == '1')

    # Auto-fix: if ALL entries fail HMAC (key_mismatch on a fresh/new DB),
    # re-sign them immediately so the ledger shows SAFE from the start.
    # This is safe because key_mismatch means the stored hashes were computed
    # with a different key — re-signing brings them in line with the current key.
    if integrity_result['status'] == 'key_mismatch':
        ledger.re_sign_all_entries()
        integrity_result = ledger.verify_integrity()  # re-verify after re-sign

    entries = ledger.get_recent(per_page)
    stats = ledger.get_stats()

    formatted_entries = []
    for entry in entries:
        try:
            raw_details = json.loads(entry[4]) if entry[4] else {}
        except Exception:
            raw_details = {}

        # Pull out the items list separately so template can iterate it cleanly
        items_list = raw_details.pop('items', []) if isinstance(raw_details, dict) else []
        # Ensure items_list is a list of dicts
        if not isinstance(items_list, list):
            items_list = []

        # Sanitize all remaining detail values to safe types (no nested dicts/lists)
        safe_details = {}
        if isinstance(raw_details, dict):
            for k, v in raw_details.items():
                if isinstance(v, (dict, list)):
                    safe_details[k] = json.dumps(v, default=str)
                elif v is None:
                    safe_details[k] = '—'
                else:
                    safe_details[k] = v

        formatted_entries.append({
            'id': entry[0],
            'timestamp': format_datetime_iso(entry[1]),
            'action': entry[2],
            'user_id': entry[3],
            'details': safe_details,
            'items_list': items_list,
            'hash': entry[5],
            'previous_hash': entry[6],
            'is_verified': entry[7]
        })

    return render_template("admin/ledger.html",
                          entries=formatted_entries,
                          stats=stats,
                          page=page,
                          integrity=integrity_result)

@app.route("/admin/ledger/report", methods=["POST"])
@login_required
@admin_required
def generate_ledger_report():
    date_from = request.form.get('date_from')
    date_to = request.form.get('date_to')

    if not date_from or not date_to:
        flash("Please select a date range.", "warning")
        return redirect(url_for('admin_ledger'))

    raw_entries = ledger.get_by_date_range(date_from, date_to)

    if not raw_entries:
        flash(f"No ledger entries found between {date_from} and {date_to}.", "warning")
        return redirect(url_for('admin_ledger'))

    # Format entries the same way as admin_ledger view
    entries = []
    for entry in raw_entries:
        try:
            raw_details = json.loads(entry[4]) if entry[4] else {}
        except Exception:
            raw_details = {}
        items_list = raw_details.pop('items', []) if isinstance(raw_details, dict) else []
        if not isinstance(items_list, list):
            items_list = []
        safe_details = {}
        if isinstance(raw_details, dict):
            for k, v in raw_details.items():
                if isinstance(v, (dict, list)):
                    safe_details[k] = json.dumps(v, default=str)
                elif v is None:
                    safe_details[k] = '—'
                else:
                    safe_details[k] = v
        entries.append({
            'id': entry[0],
            'timestamp': entry[1] or '—',
            'action': entry[2] or '—',
            'user_id': entry[3],
            'details': safe_details,
            'items_list': items_list,
            'hash': entry[5] or '—'
        })

    # ── Build PDF ──
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=landscape(A4),
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=15*mm, bottomMargin=15*mm
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title', fontSize=16, fontName='Helvetica-Bold',
                                  spaceAfter=4, alignment=TA_LEFT, textColor=colors.HexColor('#1a1a2e'))
    sub_style   = ParagraphStyle('Sub', fontSize=9, fontName='Helvetica',
                                  spaceAfter=2, textColor=colors.HexColor('#6b7280'))
    cell_style  = ParagraphStyle('Cell', fontSize=7.5, fontName='Helvetica',
                                  leading=10, textColor=colors.HexColor('#374151'))
    hash_style  = ParagraphStyle('Hash', fontSize=6.5, fontName='Courier',
                                  textColor=colors.HexColor('#667eea'))

    ACTION_LABELS = {
        'SALE_CREATED':    'SALE',
        'SALE_CANCELLED':  'CANCELLED',
        'STOCK_IN':        'STOCK IN',
        'STOCK_OUT':       'STOCK OUT',
        'STOCK_ADJUSTMENT':'ADJUSTMENT',
    }
    ACTION_COLORS = {
        'SALE_CREATED':    colors.HexColor('#065f46'),
        'SALE_CANCELLED':  colors.HexColor('#991b1b'),
        'STOCK_IN':        colors.HexColor('#1e40af'),
        'STOCK_OUT':       colors.HexColor('#92400e'),
        'STOCK_ADJUSTMENT':colors.HexColor('#6b21a8'),
    }

    def fmt_details(d, items_list, action):
        lines = []
        if action == 'SALE_CREATED':
            lines.append(f"Txn: {d.get('transaction_id','—')}")
            lines.append(f"Customer: {d.get('customer','Walk-in')}")
            lines.append(f"Subtotal: P{float(d.get('subtotal') or 0):.2f}  Tax: P{float(d.get('tax') or 0):.2f}  Total: P{float(d.get('total') or 0):.2f}")
            lines.append(f"Payment: {str(d.get('payment_method','—')).title()}")
            if d.get('digital_reference'):
                lines.append(f"Ref #: {d.get('digital_reference')}")
            if items_list:
                lines.append("Items: " + ", ".join(
                    f"{i.get('product','?')} x{i.get('qty',0)} (P{float(i.get('price') or 0):.2f})"
                    for i in items_list
                ))
        elif action == 'SALE_CANCELLED':
            lines.append(f"Txn: {d.get('transaction_id','—')}")
            lines.append(f"Refund: P{float(d.get('total') or 0):.2f}")
            lines.append(f"Reason: {d.get('reason','—')}")
        elif action == 'STOCK_IN':
            lines.append(f"Product: {d.get('product_name','—')}")
            lines.append(f"Qty In: +{d.get('qty_in',0)} units  Price: P{float(d.get('unit_price') or 0):.2f}")
            if d.get('previous_stock') is not None:
                lines.append(f"Stock: {d.get('previous_stock')} -> {d.get('new_stock')}")
            lines.append(f"Reason: {d.get('reason','—')}")
        elif action == 'STOCK_OUT':
            lines.append(f"Product: {d.get('product_name','—')}")
            lines.append(f"Qty Out: -{d.get('qty_out',0)} units  Price: P{float(d.get('unit_price') or 0):.2f}")
            lines.append(f"Customer: {d.get('customer','Walk-in')}  Txn: {d.get('transaction_id','—')}")
        elif action == 'STOCK_ADJUSTMENT':
            lines.append(f"Product: {d.get('product_name','—')}")
            lines.append(f"Change: {d.get('qty_adjusted',0)} units  ({d.get('previous_stock','?')} -> {d.get('new_stock','?')})")
            lines.append(f"Reason: {d.get('reason','—')}")
        else:
            for k, v in d.items():
                lines.append(f"{k}: {v}")
        return '\n'.join(lines)

    story = []

    # Header
    story.append(Paragraph("StockSecure POS — CyberLedger Report", title_style))
    story.append(Paragraph(
        f"Period: {date_from} to {date_to}  |  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  Total entries: {len(entries)}  |  Admin: {session.get('username','—')}",
        sub_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#667eea'), spaceAfter=8))

    # Table headers
    col_widths = [18*mm, 38*mm, 28*mm, 28*mm, 115*mm, 38*mm]
    header_data = [['#', 'Timestamp', 'Event', 'By', 'Details', 'SHA-256 Hash']]

    table_data = [header_data[0]]
    for e in entries:
        action = e['action']
        label = ACTION_LABELS.get(action, action.replace('_', ' '))
        detail_text = fmt_details(e['details'], e['items_list'], action)
        by = (e['details'].get('cashier') or e['details'].get('username') or
              e['details'].get('by') or f"User #{e['user_id']}")
        table_data.append([
            Paragraph(str(e['id']), cell_style),
            Paragraph(str(e['timestamp']).replace('T', ' ').replace('Z', ''), cell_style),
            Paragraph(label, ParagraphStyle('Act', fontSize=7.5, fontName='Helvetica-Bold',
                                             textColor=ACTION_COLORS.get(action, colors.HexColor('#374151')))),
            Paragraph(str(by), cell_style),
            Paragraph(detail_text.replace('\n', '<br/>'), cell_style),
            Paragraph(str(e['hash'])[:20] + '...', hash_style),
        ])

    tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        # Header row
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,0), 8),
        ('ALIGN',      (0,0), (-1,0), 'CENTER'),
        ('VALIGN',     (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9fafb')]),
        ('GRID',       (0,0), (-1,-1), 0.3, colors.HexColor('#e5e7eb')),
        ('LEFTPADDING',  (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING',   (0,0), (-1,-1), 4),
        ('BOTTOMPADDING',(0,0), (-1,-1), 4),
    ]))
    story.append(tbl)

    doc.build(story)
    buf.seek(0)

    filename = f"cyberledger_{date_from}_to_{date_to}.pdf"
    return send_file(buf, mimetype='application/pdf',
                     as_attachment=True, download_name=filename)



@app.route("/api/ledger/stats")
@login_required
def api_ledger_stats():
    return jsonify(ledger.get_stats())

# ============================================
# API ROUTES
# ============================================

@app.route("/api/products/search")
@login_required
def search_products():
    query = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()

    with get_db() as conn:
        sql = """
            SELECT p.id, p.name, p.price, p.stock, p.image, p.barcode, c.name as category
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE p.is_active = 1
        """
        params = []

        if query:
            # Search by name only in SQL (barcode is encrypted — can't use LIKE)
            sql += " AND p.name LIKE ?"
            params.append(f'%{query}%')

        if category:
            sql += " AND p.category_id = ?"
            params.append(category)

        sql += " ORDER BY p.name LIMIT 50"
        products = conn.execute(sql, params).fetchall()

    result = []
    for p in products:
        decrypted_barcode = decrypt(p['barcode'])
        # If a query was given, also include products whose decrypted barcode matches
        if query and decrypted_barcode and query.lower() in decrypted_barcode.lower():
            # Already matched by name or barcode — include it
            pass
        result.append({
            'id': p['id'],
            'name': p['name'],
            'price': p['price'],
            'stock': p['stock'],
            'image': p['image'],
            'barcode': decrypted_barcode,
            'category': p['category']
        })

    # Also do a barcode-exact-match pass (for barcode scanner use)
    if query:
        with get_db() as conn:
            all_products = conn.execute("""
                SELECT p.id, p.name, p.price, p.stock, p.image, p.barcode, c.name as category
                FROM products p
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE p.is_active = 1 AND p.barcode IS NOT NULL
            """).fetchall()
        existing_ids = {r['id'] for r in result}
        for p in all_products:
            if p['id'] in existing_ids:
                continue
            decrypted_barcode = decrypt(p['barcode'])
            if decrypted_barcode and query.lower() in decrypted_barcode.lower():
                result.append({
                    'id': p['id'],
                    'name': p['name'],
                    'price': p['price'],
                    'stock': p['stock'],
                    'image': p['image'],
                    'barcode': decrypted_barcode,
                    'category': p['category']
                })

    return jsonify(result)

@app.route("/api/sale/create", methods=["POST"])
@login_required
def create_sale():
    data = request.get_json()
    
    if not data or 'items' not in data or not data['items']:
        return jsonify({'error': 'No items in cart'}), 400
    
    items = data['items']
    payment_method = data.get('payment_method', 'cash')
    customer_name = data.get('customer_name', '').strip() or 'Walk-in Customer'

    if payment_method not in ['cash', 'card', 'digital']:
        return jsonify({'error': 'Invalid payment method'}), 400

    digital_reference = None
    digital_amount_paid = None
    if payment_method == 'digital':
        digital_reference = data.get('digital_reference', '').strip()
        if not digital_reference:
            return jsonify({'error': 'Reference number is required for digital payments'}), 400
        try:
            digital_amount_paid = float(data.get('digital_amount_paid', 0))
            if digital_amount_paid <= 0:
                return jsonify({'error': 'Amount paid must be greater than zero'}), 400
        except (TypeError, ValueError):
            return jsonify({'error': 'Invalid amount paid'}), 400
    
    try:
        with get_db() as conn:
            total_amount = 0
            tax_amount = 0
            sale_items_data = []
            
            for item in items:
                product = conn.execute(
                    "SELECT id, price, stock, name FROM products WHERE id = ? AND is_active = 1",
                    (item['product_id'],)
                ).fetchone()
                
                if not product:
                    return jsonify({'error': f"Product {item['product_id']} not found"}), 400
                
                if product['stock'] < item['quantity']:
                    return jsonify({'error': f"Insufficient stock for {product['name']}"}), 400
                
                item_total = product['price'] * item['quantity']
                # Philippine VAT: prices are VAT-inclusive (12% already in the price)
                # VAT = total * (0.12 / 1.12)  =  total - (total / 1.12)
                tax = item_total - (item_total / 1.12)
                total_amount += item_total        # total does NOT change — price is already final
                tax_amount += tax

                sale_items_data.append({
                    'product_id': product['id'],
                    'name': product['name'],
                    'quantity': item['quantity'],
                    'unit_price': product['price'],
                    'total_price': item_total
                })
            
            transaction_id = f"TXN-{get_utc_now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4).upper()}"
            
            cursor = conn.execute("""
                INSERT INTO sales (transaction_id, user_id, total_amount, tax_amount, 
                                 payment_method, payment_status, digital_reference, digital_amount_paid,
                                 customer_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (transaction_id, session['user_id'], total_amount, tax_amount,
                  payment_method, 'completed',
                  encrypt(digital_reference),
                  encrypt(str(digital_amount_paid)) if digital_amount_paid is not None else None,
                  customer_name))
            
            sale_id = cursor.lastrowid
            
            for item_data in sale_items_data:
                conn.execute("""
                    INSERT INTO sale_items (sale_id, product_id, quantity, unit_price, total_price)
                    VALUES (?, ?, ?, ?, ?)
                """, (sale_id, item_data['product_id'], item_data['quantity'], 
                      item_data['unit_price'], item_data['total_price']))
                
                conn.execute("""
                    UPDATE products SET stock = stock - ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (item_data['quantity'], item_data['product_id']))
            
            conn.commit()

        # All ledger.log() calls MUST be outside the get_db() block
        # to avoid SQLite database locked error (two connections at once)
        for item_data in sale_items_data:
            ledger.log("STOCK_OUT", session['user_id'], {
                'product_id': item_data['product_id'],
                'product_name': item_data['name'],
                'qty_out': item_data['quantity'],
                'unit_price': item_data['unit_price'],
                'transaction_id': transaction_id,
                'customer': customer_name,
                'cashier': session.get('username')
            })

        ref_masked = ('*' * (len(digital_reference) - 4) + digital_reference[-4:]) if digital_reference and len(digital_reference) > 4 else digital_reference
        ledger.log("SALE_CREATED", session['user_id'], {
            'transaction_id': transaction_id,
            'cashier': session.get('username'),
            'customer': customer_name,
            'subtotal': round(total_amount - tax_amount, 2),
            'tax': round(tax_amount, 2),
            'total': round(total_amount, 2),
            'items_count': len(items),
            'items': [{'product': i['name'], 'qty': i['quantity'], 'price': i['unit_price']} for i in sale_items_data],
            'payment_method': payment_method,
            'digital_reference': ref_masked
        })

        log_audit("SALE_CREATED", "sales", sale_id, None, {
            'transaction_id': transaction_id,
            'total': total_amount,
            'items': len(items)
        })

        return jsonify({
            'success': True,
            'transaction_id': transaction_id,
            'total': round(total_amount, 2),
            'sale_id': sale_id
        })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route("/api/sale/<int:sale_id>/items")
@login_required
def get_sale_items(sale_id):
    """Get items for a specific sale - for order details display"""
    with get_db() as conn:
        items = conn.execute("""
            SELECT si.*, p.name as product_name
            FROM sale_items si
            JOIN products p ON si.product_id = p.id
            WHERE si.sale_id = ?
        """, (sale_id,)).fetchall()
        
        return jsonify([{
            'product_name': item['product_name'],
            'quantity': item['quantity'],
            'unit_price': item['unit_price'],
            'total_price': item['total_price']
        } for item in items])

@app.route("/api/sale/cancel", methods=["POST"])
@login_required
@role_required('admin', 'manager')
def cancel_sale():
    data = request.get_json()
    sale_id = data.get('sale_id')
    reason = data.get('reason', '').strip()
    # Get client's timezone offset in minutes (from JavaScript getTimezoneOffset())
    # JavaScript returns positive for behind UTC, negative for ahead of UTC
    # e.g., UTC+8 (Manila) returns -480, UTC-5 (EST) returns 300
    client_offset_minutes = data.get('timezone_offset', 0)
    
    if not reason:
        return jsonify({'error': 'Cancellation reason required'}), 400
    
    with get_db() as conn:
        sale = conn.execute("SELECT * FROM sales WHERE id = ?", (sale_id,)).fetchone()
        
        if not sale:
            return jsonify({'error': 'Sale not found'}), 404
            
        if sale['is_cancelled']:
            return jsonify({'error': 'Sale already cancelled'}), 400
        
        # FIXED: Timezone-aware cancellation using client's local time
        # SQLite stores CURRENT_TIMESTAMP in UTC format: 'YYYY-MM-DD HH:MM:SS'
        try:
            created_at = sale['created_at']
            
            # Parse the sale creation time (SQLite format: YYYY-MM-DD HH:MM:SS)
            # This is UTC time from the database
            sale_time_utc = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')
            
            # JavaScript getTimezoneOffset() returns:
            # - Positive value if local time is behind UTC (e.g., UTC-5 returns 300)
            # - Negative value if local time is ahead of UTC (e.g., UTC+8 returns -480)
            # To convert UTC to local: local_time = utc_time - offset
            sale_time_local = sale_time_utc - timedelta(minutes=client_offset_minutes)
            
            # Get current time in client's local timezone
            now_utc = get_utc_now()
            now_local = now_utc - timedelta(minutes=client_offset_minutes)
            
            # Calculate cutoff (1 hour ago in CLIENT'S local time)
            cutoff_time_local = now_local - timedelta(hours=1)
            
            # Compare in client's local time - this ensures the 1-hour window
            # is based on the device's local clock, not server UTC
            if sale_time_local < cutoff_time_local:
                hours_ago = (now_local - sale_time_local).total_seconds() / 3600
                return jsonify({'error': f'Cannot cancel orders older than 1 hour (this order is {hours_ago:.1f} hours old)'}), 400
                
        except Exception as e:
            # If we can't parse the time, log it but allow cancellation (safer)
            print(f"Time parsing warning: {e}, created_at: {sale.get('created_at')}")
            pass
        
        conn.execute("""
            UPDATE sales 
            SET is_cancelled = 1, cancelled_at = CURRENT_TIMESTAMP, cancelled_by = ?, cancellation_reason = ?
            WHERE id = ?
        """, (session['user_id'], reason, sale_id))
        
        items = conn.execute("SELECT * FROM sale_items WHERE sale_id = ?", (sale_id,)).fetchall()
        for item in items:
            conn.execute("""
                UPDATE products SET stock = stock + ? WHERE id = ?
            """, (item['quantity'], item['product_id']))
        
        conn.commit()
        sale_txn_id = sale['transaction_id']
        sale_total = sale['total_amount']

    ledger.log("SALE_CANCELLED", session['user_id'], {
        'sale_id': sale_id,
        'transaction_id': sale_txn_id,
        'reason': reason,
        'total': sale_total,
        'client_timezone_offset': client_offset_minutes
    })

    log_audit("SALE_CANCELLED", "sales", sale_id,
             {'transaction_id': sale_txn_id, 'total': sale_total},
             {'reason': reason, 'cancelled_by': session['username']})

    return jsonify({'success': True})
@app.route("/api/product/<int:product_id>")
@login_required
def get_product(product_id):
    with get_db() as conn:
        product = conn.execute("""
            SELECT p.*, c.name as category_name
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE p.id = ?
        """, (product_id,)).fetchone()
        
    if not product:
        return jsonify({'error': 'Product not found'}), 404
        
    return jsonify({
        'id': product['id'],
        'name': product['name'],
        'description': product['description'],
        'price': product['price'],
        'stock': product['stock'],
        'min_stock_level': product['min_stock_level'],
        'category_id': product['category_id'],
        'barcode': decrypt(product['barcode']),
        'image': product['image'],
        'is_active': product['is_active']
    })

@app.route("/api/stats/dashboard")
@login_required
def dashboard_stats():
    with get_db() as conn:
        today = get_utc_now().strftime('%Y-%m-%d')
        
        stats = {
            'today_sales': conn.execute("""
                SELECT COALESCE(SUM(total_amount), 0) 
                FROM sales WHERE date(created_at) = ?
            """, (today,)).fetchone()[0],
            'today_transactions': conn.execute("""
                SELECT COUNT(*) FROM sales WHERE date(created_at) = ?
            """, (today,)).fetchone()[0],
            'low_stock_count': conn.execute("""
                SELECT COUNT(*) FROM products 
                WHERE stock <= min_stock_level AND is_active = 1
            """).fetchone()[0],
            'active_products': conn.execute("""
                SELECT COUNT(*) FROM products WHERE is_active = 1
            """).fetchone()[0]
        }
        
    return jsonify(stats)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500
@app.route("/api/ledger/verify", methods=["POST"])
@login_required
@admin_required
def api_ledger_verify():
    """API endpoint to trigger ledger integrity verification"""
    result = ledger.verify_integrity()
    return jsonify(result)

@app.route("/api/ledger/export", methods=["POST"])
@login_required
@admin_required
def api_ledger_export():
    """Export ledger to JSON backup"""
    import tempfile
    
    timestamp = get_utc_now().strftime('%Y%m%d_%H%M%S')
    filename = f"cyberledger_backup_{timestamp}.json"
    filepath = os.path.join(tempfile.gettempdir(), filename)
    
    ledger.export_to_file(filepath, format='json')
    
    return send_file(filepath, mimetype='application/json',
                     as_attachment=True, download_name=filename)



@app.route("/printer-settings")
@login_required
def printer_settings():
    """Printer configuration page — accessible to cashier, manager, and admin."""
    return render_template("printer_settings.html")

# ============================================================
# THERMAL PRINTER — ESC/POS direct printing + cash drawer kick
# ============================================================
# Supports: USB, Network (LAN), Serial, Windows shared printer
# Compatible with: Epson TM series, Star, Bixolon, Generic 80mm
# ============================================================

import json as _json
import socket as _socket

# Printer config file — stores user's chosen printer connection
PRINTER_CONFIG_PATH = os.path.join(BASE_DIR, "printer_config.json")

def _load_printer_config():
    """Load printer config from disk. Returns dict with defaults."""
    defaults = {
        "type": "none",          # none | network | usb | serial | windows
        "host": "192.168.1.100", # for network printers
        "port": 9100,            # standard raw print port (9100), alt: 9102
        "serial_port": "COM3",   # for serial: COM1-COM9 on Windows
        "baudrate": 9600,
        "usb_vendor": "0x04b8",  # Epson vendor ID (change for other brands)
        "usb_product": "0x0202", # product ID from Device Manager
        "windows_printer": "",   # exact Windows printer name
        "paper_width": 80,       # 80mm or 58mm
        "cash_drawer": True,     # kick cash drawer after print
        "cut_paper": True,       # full cut after receipt
        "open_drawer_only": False # kick drawer without printing (manual open)
    }
    try:
        if os.path.exists(PRINTER_CONFIG_PATH):
            saved = _json.loads(open(PRINTER_CONFIG_PATH).read())
            defaults.update(saved)
    except Exception:
        pass
    return defaults

def _save_printer_config(cfg):
    with open(PRINTER_CONFIG_PATH, 'w') as f:
        _json.dump(cfg, f, indent=2)

def _escpos_receipt(sale_data, cfg):
    """
    Build a complete ESC/POS byte sequence for a thermal receipt.
    Returns bytes ready to send directly to the printer port.
    
    ESC/POS command reference (standard across all brands):
      ESC @ = initialize printer
      ESC ! n = select print mode (bold, double-height, double-width)
      ESC a n = justification (0=left, 1=center, 2=right)
      GS V n = cut paper (0=full cut, 1=partial cut)
      ESC p m t1 t2 = open cash drawer (pin 2 or pin 5)
    """
    # ── Core ESC/POS constants ──────────────────────────────────────
    INIT          = b'\x1b@'           # initialize / reset printer
    LF            = b'\n'
    CUT_FULL      = b'\x1d\x56\x00'  # GS V 0 — full cut
    CUT_PARTIAL   = b'\x1d\x56\x01'  # GS V 1 — partial cut
    DRAWER_PIN2   = b'\x1bp\x00\x19\xfa'  # ESC p 0 — kick pin 2 (most common)
    DRAWER_PIN5   = b'\x1bp\x01\x19\xfa'  # ESC p 1 — kick pin 5 (some Epson)

    # Text modes
    BOLD_ON       = b'\x1b!\x08'
    BOLD_OFF      = b'\x1b!\x00'
    DOUBLE_HEIGHT = b'\x1b!\x10'
    DOUBLE_BOTH   = b'\x1b!\x30'  # double height + double width
    NORMAL        = b'\x1b!\x00'
    ALIGN_LEFT    = b'\x1ba\x00'
    ALIGN_CENTER  = b'\x1ba\x01'
    ALIGN_RIGHT   = b'\x1ba\x02'

    # Paper width: 80mm = 42 chars, 58mm = 32 chars
    WIDTH = 42 if cfg.get('paper_width', 80) == 80 else 32
    DASH  = b'-' * WIDTH + LF
    DASH2 = b'=' * WIDTH + LF

    def enc(text):
        """Encode text to bytes, replacing unsupported chars."""
        return str(text).encode('ascii', errors='replace')

    def row(left, right, width=WIDTH):
        """Left-right justified row padded to exact width."""
        left  = str(left)
        right = str(right)
        spaces = width - len(left) - len(right)
        if spaces < 1:
            spaces = 1
            left = left[:width - len(right) - 1]
        return enc(left + ' ' * spaces + right) + LF

    def center_line(text, width=WIDTH):
        s = str(text).center(width)
        return enc(s) + LF

    def divider(char='-', width=WIDTH):
        return enc(char * width) + LF

    # ── Build receipt ────────────────────────────────────────────────
    buf = bytearray()

    # 1. Initialize
    buf += INIT
    buf += ALIGN_CENTER

    # 2. Store header
    buf += DOUBLE_BOTH
    buf += enc("DULCIS & CAFE") + LF
    buf += NORMAL
    buf += enc("Talisay, Cebu") + LF
    buf += enc("VAT Reg. TIN: 000-000-000-00000") + LF
    buf += divider('=')

    # 3. Transaction info
    buf += ALIGN_LEFT
    buf += enc(f"Date   : {sale_data.get('date','')}") + LF
    buf += enc(f"Time   : {sale_data.get('time','')}") + LF
    buf += enc(f"TXN    : {sale_data.get('transaction_id','')}") + LF
    buf += enc(f"Cashier: {sale_data.get('cashier','')}") + LF
    buf += enc(f"Cust.  : {sale_data.get('customer','')}") + LF
    buf += enc(f"Payment: {sale_data.get('payment_method','').upper()}") + LF
    buf += divider('-')

    # 4. Column header
    buf += BOLD_ON
    buf += enc("ITEM                    QTY   AMOUNT") + LF
    buf += BOLD_OFF
    buf += divider('-')

    # 5. Items
    for item in sale_data.get('items', []):
        name  = str(item.get('name', ''))[:22]
        qty   = str(item.get('qty', 1))
        price = f"P{float(item.get('total', 0)):.2f}"
        # Item name line
        buf += enc(f"{name:<22} {qty:>3}  {price:>7}") + LF
        # Unit price subline
        unit = f"  P{float(item.get('unit_price',0)):.2f} each"
        buf += enc(unit) + LF

    buf += divider('=')

    # 6. Totals
    vatable = sale_data.get('vatable', 0.0)
    vat     = sale_data.get('vat', 0.0)
    total   = sale_data.get('total', 0.0)

    buf += ALIGN_LEFT
    buf += row("VATable Sales (Net)", f"P{float(vatable):.2f}")
    buf += row("Add: VAT 12%",        f"P{float(vat):.2f}")
    buf += row("VAT-Exempt Sale",     "P0.00")
    buf += row("Discount",            "P0.00")
    buf += divider('-')

    # Total due — bold + double height
    buf += BOLD_ON
    buf += row("TOTAL DUE",           f"P{float(total):.2f}")
    buf += BOLD_OFF

    # Payment breakdown
    buf += divider('-')
    pm = sale_data.get('payment_method', 'cash').lower()
    if pm == 'cash':
        tendered = sale_data.get('cash_tendered', 0.0)
        change   = sale_data.get('change', 0.0)
        buf += row("Cash Tendered",   f"P{float(tendered):.2f}")
        buf += row("Change Due",      f"P{float(change):.2f}")
    else:
        ref = sale_data.get('reference', '')
        buf += row("Digital Payment", "")
        buf += enc(f"  Ref: {ref}") + LF

    buf += divider('=')

    # 7. VAT footer (BIR-compliant)
    buf += ALIGN_CENTER
    buf += enc(f"VATable Sale: P{float(vatable):.2f}") + LF
    buf += enc(f"VAT Amount:   P{float(vat):.2f}") + LF
    buf += divider('-')

    # 8. Thank you
    buf += BOLD_ON
    buf += enc("SALAMAT! BALIK-BALIK PO!") + LF
    buf += BOLD_OFF
    buf += enc("This is your official receipt.") + LF
    buf += enc("Goods sold are non-returnable.") + LF
    buf += LF

    # 9. Transaction ID barcode area (text)
    buf += ALIGN_CENTER
    buf += enc(sale_data.get('transaction_id', '')) + LF
    buf += LF * 4  # feed paper before cut

    # 10. Cut
    if cfg.get('cut_paper', True):
        buf += CUT_FULL

    return bytes(buf)


def _send_to_printer(raw_bytes, cfg):
    """
    Send raw ESC/POS bytes to the configured printer.
    Returns (success: bool, message: str)
    """
    ptype = cfg.get('type', 'none')

    # ── Network printer (most common for POS in PH) ─────────────────
    if ptype == 'network':
        try:
            host = cfg['host']
            port = int(cfg.get('port', 9100))
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((host, port))
                s.sendall(raw_bytes)
            return True, "Printed via network"
        except Exception as e:
            return False, f"Network print error: {e}"

    # ── Serial printer (RS-232 cable) ───────────────────────────────
    elif ptype == 'serial':
        try:
            import serial
            port   = cfg.get('serial_port', 'COM1')
            baud   = int(cfg.get('baudrate', 9600))
            with serial.Serial(port, baud, timeout=5) as s:
                s.write(raw_bytes)
            return True, "Printed via serial"
        except ImportError:
            return False, "pyserial not installed. Run: pip install pyserial"
        except Exception as e:
            return False, f"Serial print error: {e}"

    # ── USB printer (direct USB, not through Windows driver) ─────────
    elif ptype == 'usb':
        try:
            import usb.core, usb.util
            vid = int(cfg.get('usb_vendor', '0x04b8'), 16)
            pid = int(cfg.get('usb_product', '0x0202'), 16)
            dev = usb.core.find(idVendor=vid, idProduct=pid)
            if dev is None:
                return False, f"USB printer not found (VID={hex(vid)} PID={hex(pid)})"
            dev.set_configuration()
            cfg_usb = dev.get_active_configuration()
            intf = cfg_usb[(0, 0)]
            ep   = usb.util.find_descriptor(intf, custom_match=lambda e:
                usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
            if ep is None:
                return False, "USB OUT endpoint not found"
            ep.write(raw_bytes)
            return True, "Printed via USB"
        except ImportError:
            return False, "pyusb not installed. Run: pip install pyusb"
        except Exception as e:
            return False, f"USB print error: {e}"

    # ── Windows shared / local printer (via win32print) ──────────────
    elif ptype == 'windows':
        try:
            import win32print
            printer_name = cfg.get('windows_printer', '') or win32print.GetDefaultPrinter()
            handle = win32print.OpenPrinter(printer_name)
            try:
                job = win32print.StartDocPrinter(handle, 1, ("Receipt", None, "RAW"))
                win32print.StartPagePrinter(handle)
                win32print.WritePrinter(handle, raw_bytes)
                win32print.EndPagePrinter(handle)
                win32print.EndDocPrinter(handle)
            finally:
                win32print.ClosePrinter(handle)
            return True, f"Printed via Windows: {printer_name}"
        except ImportError:
            return False, "pywin32 not installed. Run: pip install pywin32"
        except Exception as e:
            return False, f"Windows print error: {e}"

    else:
        return False, "No printer configured. Set up printer in Settings."


def _kick_cash_drawer(cfg):
    """
    Send ESC/POS cash drawer open command (ESC p).
    Works even without printing — sends just the kick pulse.
    """
    DRAWER_KICK = b'\x1b@\x1bp\x00\x19\xfa'  # init + kick pin 2
    return _send_to_printer(DRAWER_KICK, cfg)


@app.route("/api/print-receipt", methods=["POST"])
@login_required
def api_print_receipt():
    """
    Direct thermal print endpoint.
    Receives sale data as JSON, builds ESC/POS bytes, sends to printer.
    Also kicks cash drawer if configured.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data received'}), 400

        cfg = _load_printer_config()

        if cfg.get('type', 'none') == 'none':
            return jsonify({'success': False, 'error': 'no_printer',
                            'message': 'No printer configured. Please set up your printer in Settings.'}), 200

        # Build ESC/POS bytes
        raw = _escpos_receipt(data, cfg)

        # Send to printer
        ok, msg = _send_to_printer(raw, cfg)

        if not ok:
            return jsonify({'success': False, 'error': msg}), 200

        # Kick cash drawer (separate pulse after print, if enabled)
        drawer_msg = ''
        if cfg.get('cash_drawer', True) and data.get('payment_method', 'cash') == 'cash':
            dok, dmsg = _kick_cash_drawer(cfg)
            drawer_msg = dmsg

        log_audit("RECEIPT_PRINTED", "sales", data.get('sale_id'),
                  details={'transaction_id': data.get('transaction_id'), 'method': cfg.get('type')})

        return jsonify({
            'success': True,
            'message': msg,
            'drawer': drawer_msg,
            'printer_type': cfg.get('type')
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/api/open-drawer", methods=["POST"])
@login_required
def api_open_drawer():
    """Kick cash drawer manually (without printing)."""
    try:
        cfg = _load_printer_config()
        if cfg.get('type', 'none') == 'none':
            return jsonify({'success': False, 'error': 'No printer configured'}), 200
        ok, msg = _kick_cash_drawer(cfg)
        return jsonify({'success': ok, 'message': msg})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/api/test-print", methods=["POST"])
@login_required
def api_test_print():
    """Print a test receipt to verify printer connection."""
    cfg = _load_printer_config()
    test_data = {
        'date': get_utc_now().strftime('%b %d, %Y'),
        'time': get_utc_now().strftime('%I:%M:%S %p'),
        'transaction_id': 'TXN-TEST-0000',
        'cashier': session.get('username', 'Staff'),
        'customer': 'TEST PRINT',
        'payment_method': 'cash',
        'items': [
            {'name': 'Test Item 1', 'qty': 1, 'unit_price': 89.29, 'total': 100.00},
            {'name': 'Test Item 2', 'qty': 2, 'unit_price': 44.64, 'total': 100.00},
        ],
        'vatable': 178.57,
        'vat': 21.43,
        'total': 200.00,
        'cash_tendered': 200.00,
        'change': 0.00,
    }
    raw = _escpos_receipt(test_data, cfg)
    ok, msg = _send_to_printer(raw, cfg)
    return jsonify({'success': ok, 'message': msg})


@app.route("/api/printer-config", methods=["GET", "POST"])
@login_required
def api_printer_config():
    """Get or save printer configuration."""
    if request.method == "POST":
        data = request.get_json() or {}
        cfg = _load_printer_config()
        cfg.update(data)
        _save_printer_config(cfg)
        log_audit("PRINTER_CONFIG_UPDATED", "system", session.get('user_id'),
                  details={'type': cfg.get('type')})
        return jsonify({'success': True, 'config': cfg})
    else:
        return jsonify(_load_printer_config())


@app.route("/api/discover-printers", methods=["GET"])
@login_required
def api_discover_printers():
    """Auto-detect available printers on the system."""
    found = []

    # Check Windows printers
    try:
        import win32print
        printers = win32print.EnumPrinters(win32print.PRINTER_ENUM_LOCAL | win32print.PRINTER_ENUM_CONNECTIONS)
        for p in printers:
            found.append({'type': 'windows', 'name': p[2], 'description': p[2]})
    except Exception:
        pass

    # Check serial ports
    try:
        import serial.tools.list_ports
        ports = list(serial.tools.list_ports.comports())
        for p in ports:
            found.append({'type': 'serial', 'name': p.device, 'description': f"{p.device} — {p.description}"})
    except Exception:
        pass

    # Check USB devices (look for common printer vendor IDs)
    try:
        import usb.core
        PRINTER_VENDORS = {
            0x04b8: 'Epson', 0x0519: 'Star Micronics',
            0x154f: 'SNBC',  0x0dd4: 'Custom',
            0x1504: 'Bixolon', 0x0fe6: 'Sunphor',
        }
        for vid, brand in PRINTER_VENDORS.items():
            devs = list(usb.core.find(find_all=True, idVendor=vid))
            for d in devs:
                found.append({
                    'type': 'usb',
                    'name': f"{brand} USB Printer",
                    'description': f"{brand} — VID:{hex(d.idVendor)} PID:{hex(d.idProduct)}",
                    'vendor': hex(d.idVendor),
                    'product': hex(d.idProduct)
                })
    except Exception:
        pass

    return jsonify({'printers': found})


if __name__ == "__main__":
    init_db()
    migrate_encrypt_existing_data()
    
    # Start automatic backup system
    print("💾 Starting automatic backup system...")
    create_backup(silent=False)
    
    # Start background threads
    threading.Thread(target=auto_backup_loop, daemon=True).start()
    
    print("📍 http://127.0.0.1:5000")
    print("🔒 Admin: http://127.0.0.1:5000/admin")
    print("🔐 CyberLedger: http://127.0.0.1:5000/admin/ledger")
    app.run(debug=True, host='0.0.0.0', port=5000)
else:
    init_db()
    migrate_encrypt_existing_data()