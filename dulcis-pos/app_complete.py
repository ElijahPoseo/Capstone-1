from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, g
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import sqlite3
import os
import secrets
import re
import json
import html
import shutil
import threading
import time
import winsound
from contextlib import contextmanager


app = Flask(__name__)

# Security Configuration - OFFLINE ONLY
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
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
        
        # Insert default admin
        admin_exists = conn.execute("SELECT 1 FROM users WHERE username = 'admin'").fetchone()
        if not admin_exists:
            admin_hash = generate_password_hash('Admin@123!', method='pbkdf2:sha256', salt_length=16)
            conn.execute("""
                INSERT INTO users (username, password_hash, role, email, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, ('admin', admin_hash, 'admin', 'admin@dulcis.local', 1))
            
            # Default categories
            categories = [
                ('Beverages', 'Hot and cold drinks'),
                ('Pastries', 'Cakes, muffins, and baked goods'),
                ('Snacks', 'Light snacks and sandwiches'),
                ('Merchandise', 'Coffee beans, mugs, etc.')
            ]
            conn.executemany("INSERT INTO categories (name, description) VALUES (?, ?)", categories)
            
        conn.commit()

def get_usb_drives():
    """Auto-detect USB drives on Windows"""
    usb_drives = []
    for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                volume_name = ctypes.create_unicode_buffer(1024)
                if kernel32.GetVolumeInformationW(ctypes.c_wchar_p(drive), volume_name, 1024, None, None, None, None, 0):
                    usb_drives.append(drive)
            except:
                continue
    return usb_drives

def create_backup(silent=True):
    """Create backup - auto-copies to USB if available"""
    if not os.path.exists(DB_PATH):
        return False
    
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"dulcis_backup_{timestamp}.db"
        local_path = os.path.join(BACKUP_DIR, backup_name)
        
        # Copy to local backups folder
        shutil.copy2(DB_PATH, local_path)
        
        # Auto-copy to USB drive
        usb_drives = get_usb_drives()
        usb_success = False
        
        for drive in usb_drives:
            try:
                usb_dir = os.path.join(drive, "DulcisPOS_Backup")
                os.makedirs(usb_dir, exist_ok=True)
                if shutil.disk_usage(drive).free > 10 * 1024 * 1024:
                    shutil.copy2(local_path, os.path.join(usb_dir, backup_name))
                    usb_success = True
                    if not silent:
                        try:
                            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
                        except:
                            pass
                    break
            except:
                continue
        
        # Delete old backups (keep only 7)
        backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith('dulcis_backup_')], reverse=True)
        while len(backups) > MAX_LOCAL_BACKUPS:
            os.remove(os.path.join(BACKUP_DIR, backups.pop()))
        
        if not silent:
            status = "USB + Local" if usb_success else "Local only"
            print(f"✅ Backup created: {backup_name} ({status})")
        
        return True
        
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return False

def auto_backup_loop():
    """Background thread - backup every X minutes"""
    while True:
        create_backup(silent=True)
        time.sleep(BACKUP_INTERVAL_MINUTES * 60)

def usb_watcher():
    """Background thread - detect USB insertion"""
    last_drives = set()
    while True:
        try:
            current_drives = set(get_usb_drives())
            new_drives = current_drives - last_drives
            if new_drives:
                print(f"🔌 USB detected: {new_drives}")
                time.sleep(2)
                create_backup(silent=False)
                print("💾 Backup copied to USB automatically!")
            last_drives = current_drives
            time.sleep(5)
        except:
            time.sleep(10)

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
            if datetime.now() - last_activity > timedelta(hours=1):
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
        
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required. Please login as administrator.', 'danger')
            return redirect(url_for('admin_login'))
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

# MIDDLEWARE: Block non-admin users from admin routes
@app.before_request
def check_admin_access():
    """Block non-admin users from accessing admin routes"""
    if request.path.startswith('/admin'):
        if request.path == '/admin/login':
            return None
        
        if 'user_id' not in session:
            flash('Please login first.', 'warning')
            return redirect(url_for('login'))
        
        if session.get('role') != 'admin':
            flash('Admin access required. Insufficient privileges.', 'danger')
            return redirect(url_for('pos'))

# Routes
@app.route("/")
def index():
    if 'user_id' in session:
        return redirect(url_for('pos'))
    return redirect(url_for('login'))

# ============================================
# STAFF LOGIN (Cashier/Manager)
# ============================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user_id' in session:
        return redirect(url_for('pos'))
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html")
        
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? AND is_active = 1", 
                (username,)
            ).fetchone()
            
            if user:
                if user['locked_until'] and datetime.now() < datetime.fromisoformat(user['locked_until']):
                    flash("Account temporarily locked. Please try again later.", "danger")
                    return render_template("login.html")
                
                if check_password_hash(user['password_hash'], password):
                    session.permanent = True
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session['last_activity'] = datetime.now().isoformat()
                    
                    conn.execute(
                        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
                        (datetime.now().isoformat(), user['id'])
                    )
                    conn.commit()
                    
                    log_audit("LOGIN_SUCCESS", "users", user['id'])
                    
                    if user['role'] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    
                    flash(f"Welcome back, {user['username']}!")
                    return redirect(url_for('pos'))
                else:
                    attempts = user['failed_login_attempts'] + 1
                    lock_until = None
                    
                    if attempts >= 5:
                        lock_until = (datetime.now() + timedelta(minutes=30)).isoformat()
                        flash("Too many failed attempts. Account locked for 30 minutes.", "danger")
                    else:
                        flash("Invalid credentials.", "danger")
                    
                    conn.execute(
                        "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                        (attempts, lock_until, user['id'])
                    )
                    conn.commit()
                    
                    log_audit("LOGIN_FAILED", "users", user['id'])
            else:
                flash("Invalid credentials.", "danger")
                log_audit("LOGIN_FAILED_ATTEMPT", None, None, {'username': username})
    
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    log_audit("LOGOUT", "users", session.get('user_id'))
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))

# ============================================
# ADMIN LOGIN (Separate for extra security)
# ============================================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Dedicated admin login page"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? AND role = 'admin' AND is_active = 1", 
                (username,)
            ).fetchone()
            
            if user and check_password_hash(user['password_hash'], password):
                session.permanent = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = 'admin'
                session['last_activity'] = datetime.now().isoformat()
                
                conn.execute(
                    "UPDATE users SET last_login = ? WHERE id = ?",
                    (datetime.now().isoformat(), user['id'])
                )
                conn.commit()
                
                log_audit("ADMIN_LOGIN_SUCCESS", "users", user['id'])
                flash(f"Welcome Administrator, {user['username']}!")
                return redirect(url_for('admin_dashboard'))
            else:
                flash("Invalid admin credentials or insufficient privileges.", "danger")
                log_audit("ADMIN_LOGIN_FAILED", None, None, {'username': username})
    
    return render_template("admin/login.html")

@app.route("/admin/logout")
def admin_logout():
    """Admin logout - clears session completely"""
    session.clear()
    flash("Admin logged out successfully.", "info")
    return redirect(url_for('admin_login'))

# ============================================
# POS ROUTES (Cashier/Manager/Admin)
# ============================================
@app.route("/pos")
@login_required
def pos():
    with get_db() as conn:
        products = conn.execute("""
            SELECT p.*, c.name as category_name 
            FROM products p 
            LEFT JOIN categories c ON p.category_id = c.id 
            WHERE p.is_active = 1 AND p.stock > 0
            ORDER BY p.category_id, p.name
        """).fetchall()
        
        categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
        
    return render_template("pos.html", products=products, categories=categories)

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
            sql += " AND (p.name LIKE ? OR p.barcode LIKE ?)"
            params.extend([f'%{query}%', f'%{query}%'])
        
        if category:
            sql += " AND p.category_id = ?"
            params.append(category)
        
        sql += " ORDER BY p.name LIMIT 50"
        
        products = conn.execute(sql, params).fetchall()
        
    return jsonify([{
        'id': p['id'],
        'name': p['name'],
        'price': p['price'],
        'stock': p['stock'],
        'image': p['image'],
        'barcode': p['barcode'],
        'category': p['category']
    } for p in products])

@app.route("/api/sale/create", methods=["POST"])
@login_required
def create_sale():
    data = request.get_json()
    
    if not data or 'items' not in data or not data['items']:
        return jsonify({'error': 'No items in cart'}), 400
    
    items = data['items']
    payment_method = data.get('payment_method', 'cash')
    
    if payment_method not in ['cash', 'card', 'digital']:
        return jsonify({'error': 'Invalid payment method'}), 400
    
    try:
        with get_db() as conn:
            total_amount = 0
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
                total_amount += item_total
                
                sale_items_data.append({
                    'product_id': product['id'],
                    'quantity': item['quantity'],
                    'unit_price': product['price'],
                    'total_price': item_total
                })
            
            transaction_id = f"TXN-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4).upper()}"
            
            cursor = conn.execute("""
                INSERT INTO sales (transaction_id, user_id, total_amount, payment_method, payment_status)
                VALUES (?, ?, ?, ?, ?)
            """, (transaction_id, session['user_id'], total_amount, payment_method, 'completed'))
            
            sale_id = cursor.lastrowid
            
            for item_data in sale_items_data:
                conn.execute("""
                    INSERT INTO sale_items (sale_id, product_id, quantity, unit_price, total_price)
                    VALUES (?, ?, ?, ?, ?)
                """, (sale_id, item_data['product_id'], item_data['quantity'], 
                      item_data['unit_price'], item_data['total_price']))
                
                conn.execute("""
                    UPDATE products SET stock = stock - ?, updated_at = ?
                    WHERE id = ?
                """, (item_data['quantity'], datetime.now().isoformat(), item_data['product_id']))
            
            conn.commit()
            
            log_audit("SALE_CREATED", "sales", sale_id, None, {
                'transaction_id': transaction_id,
                'total': total_amount,
                'items': len(items)
            })
            
            return jsonify({
                'success': True,
                'transaction_id': transaction_id,
                'total': total_amount,
                'sale_id': sale_id
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# ADMIN ROUTES (Admin Only)
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
                WHERE date(created_at) = date('now')
            """).fetchone()[0],
            'total_users': conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
        }
        
        recent_sales = conn.execute("""
            SELECT s.*, u.username as cashier_name
            FROM sales s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC LIMIT 10
        """).fetchall()
        
        low_stock_items = conn.execute("""
            SELECT * FROM products 
            WHERE stock <= min_stock_level AND is_active = 1
            ORDER BY stock ASC LIMIT 10
        """).fetchall()
        
    return render_template("admin/dashboard.html", stats=stats, recent_sales=recent_sales, 
                          low_stock_items=low_stock_items)

@app.route("/admin/products")
@login_required
@admin_required
def admin_products():
    with get_db() as conn:
        products = conn.execute("""
            SELECT p.*, c.name as category_name
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            ORDER BY p.created_at DESC
        """).fetchall()
        
        categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
        
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
            image_filename = f"{name}_{datetime.now().strftime('%Y%m%d%H%M%S')}{ext}"
            file.save(os.path.join(UPLOAD_FOLDER, image_filename))
    
    with get_db() as conn:
        try:
            cursor = conn.execute("""
                INSERT INTO products (name, description, price, stock, category_id, 
                                    min_stock_level, barcode, image)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, description, price, stock, category_id, min_stock, barcode, image_filename))
            
            conn.commit()
            product_id = cursor.lastrowid
            
            log_audit("PRODUCT_CREATED", "products", product_id, None, {
                'name': name, 'price': price, 'stock': stock
            })
            
            flash("Product added successfully!", "success")
        except sqlite3.IntegrityError as e:
            flash(f"Error: {str(e)}", "danger")
    
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
        
        image_filename = old_product['image']
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                if image_filename and os.path.exists(os.path.join(UPLOAD_FOLDER, image_filename)):
                    os.remove(os.path.join(UPLOAD_FOLDER, image_filename))
                
                filename = secure_filename(file.filename)
                name_base, ext = os.path.splitext(filename)
                image_filename = f"{name_base}_{datetime.now().strftime('%Y%m%d%H%M%S')}{ext}"
                file.save(os.path.join(UPLOAD_FOLDER, image_filename))
        
        conn.execute("""
            UPDATE products 
            SET name = ?, description = ?, price = ?, stock = ?, category_id = ?,
                min_stock_level = ?, barcode = ?, image = ?, is_active = ?, updated_at = ?
            WHERE id = ?
        """, (name, description, price, stock, category_id, min_stock, barcode, 
              image_filename, is_active, datetime.now().isoformat(), product_id))
        
        conn.commit()
        
        log_audit("PRODUCT_UPDATED", "products", product_id, dict(old_product), {
            'name': name, 'price': price, 'stock': stock, 'is_active': is_active
        })
        
        flash("Product updated successfully!", "success")
    
    return redirect(url_for('admin_products'))

@app.route("/admin/product/delete/<int:product_id>", methods=["POST"])
@login_required
@admin_required
def delete_product(product_id):
    with get_db() as conn:
        conn.execute("UPDATE products SET is_active = 0 WHERE id = ?", (product_id,))
        conn.commit()
        
        log_audit("PRODUCT_DELETED", "products", product_id)
        flash("Product deleted successfully!", "success")
    
    return redirect(url_for('admin_products'))

@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    with get_db() as conn:
        users = conn.execute("""
            SELECT id, username, role, email, is_active, created_at, last_login
            FROM users ORDER BY created_at DESC
        """).fetchall()
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
    
    with get_db() as conn:
        try:
            cursor = conn.execute("""
                INSERT INTO users (username, password_hash, role, email)
                VALUES (?, ?, ?, ?)
            """, (username, password_hash, role, email))
            conn.commit()
            
            log_audit("USER_CREATED", "users", cursor.lastrowid, None, {
                'username': username, 'role': role
            })
            
            flash(f"User '{username}' created successfully!", "success")
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
    
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
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        
        action = "activated" if new_status else "deactivated"
        log_audit(f"USER_{action.upper()}", "users", user_id)
        
        flash(f"User {action} successfully!", "success")
    
    return redirect(url_for('admin_users'))

@app.route("/admin/sales")
@login_required
@role_required('admin', 'manager')
def admin_sales():
    date_from = request.args.get('from', datetime.now().strftime('%Y-%m-%d'))
    date_to = request.args.get('to', datetime.now().strftime('%Y-%m-%d'))
    
    with get_db() as conn:
        sales = conn.execute("""
            SELECT s.*, u.username as cashier_name,
                   (SELECT COUNT(*) FROM sale_items WHERE sale_id = s.id) as item_count
            FROM sales s
            JOIN users u ON s.user_id = u.id
            WHERE date(s.created_at) BETWEEN ? AND ?
            ORDER BY s.created_at DESC
        """, (date_from, date_to)).fetchall()
        
        total_revenue = sum(sale['total_amount'] for sale in sales)
        
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
        'barcode': product['barcode'],
        'image': product['image'],
        'is_active': product['is_active']
    })

@app.route("/api/stats/dashboard")
@login_required
def dashboard_stats():
    with get_db() as conn:
        today = datetime.now().strftime('%Y-%m-%d')
        
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
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

if __name__ == "__main__":
    init_db()
    
    # Start automatic backup system
    print("💾 Starting automatic backup system...")
    create_backup(silent=False)  # First backup immediately
    
    # Start background threads
    threading.Thread(target=auto_backup_loop, daemon=True).start()
    threading.Thread(target=usb_watcher, daemon=True).start()
    
    print(f"⏰ Auto-backup: Every {BACKUP_INTERVAL_MINUTES} minutes")
    print("🔌 USB watcher: Active (backup copies immediately when USB inserted)")
    print()
    print("🚀 Starting Dulcis POS...")
    print("📍 http://127.0.0.1:5000")
    print("🔒 Admin: http://127.0.0.1:5000/admin/login")
    app.run(debug=False, host='0.0.0.0', port=5000)
else:
    init_db()