import os
import sys
import json
import time
import hashlib
import hmac
import secrets
import base64
import sqlite3
import uuid
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, session, redirect, url_for, render_template_string, jsonify, make_response, g

# ============================================================================
# KONFIGURASI FORTRESS - HIGH SECURITY SETTINGS
# ============================================================================

class FortressConfig:
    # WHID System - Single Session Only
    WHID_ENABLED = True
    WHID_FORCE_LOGOUT_PREVIOUS = True
    
    # Password Policy - Military Grade
    PASSWORD_MIN_LENGTH = 14
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_NUMBERS = True
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_HISTORY_COUNT = 5
    
    # Anti-Brute Force
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_MINUTES = 30
    
    # Session Security
    SESSION_TIMEOUT_MINUTES = 30
    IP_BINDING_ENABLED = True
    DEVICE_FINGERPRINTING = True
    
    # Rate Limiting
    RATE_LIMIT_LOGIN = "5/15m"
    RATE_LIMIT_REGISTER = "3/60m"
    
    # Encryption
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    PEPPER = os.environ.get('PEPPER', secrets.token_hex(16))

# ============================================================================
# DATABASE CORE - WITH IP TRACKING
# ============================================================================

class FortressDatabase:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.login_attempts = {}
        self.password_history = {}
        self.ip_blacklist = {}
        self.builds = []
        self.reports = []
        self.activity_logs = []
        self.user_counter = 1
        self.session_counter = 1
        self.build_counter = 1
        
        # Create default owner (for first run)
        self._create_default_owner()
    
    def _create_default_owner(self):
        """Create default owner account if not exists"""
        owner_pass = self._hash_password("Fortress@Admin2024")
        owner = {
            'id': self.user_counter,
            'username': 'owner',
            'password': owner_pass,
            'email': 'owner@oxyx.com',
            'role': 'owner',
            'ip_registration': '127.0.0.1',
            'ip_last': '127.0.0.1',
            'join_date': datetime.now().isoformat(),
            'is_banned': False,
            'failed_attempts': 0,
            'locked_until': None,
            'active_session': None
        }
        self.users[self.user_counter] = owner
        self.password_history[self.user_counter] = [owner_pass]
        self.user_counter += 1
    
    def _hash_password(self, password):
        """Secure password hashing with pepper and salt"""
        peppered = password + FortressConfig.PEPPER
        salt = secrets.token_bytes(32)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            peppered.encode('utf-8'),
            salt,
            100000,  # 100k iterations
            dklen=64
        )
        return base64.b64encode(salt + key).decode('ascii')
    
    def verify_password(self, password, hashed):
        """Constant-time password verification"""
        try:
            decoded = base64.b64decode(hashed.encode('ascii'))
            salt = decoded[:32]
            key = decoded[32:]
            peppered = password + FortressConfig.PEPPER
            new_key = hashlib.pbkdf2_hmac(
                'sha256',
                peppered.encode('utf-8'),
                salt,
                100000,
                dklen=64
            )
            return hmac.compare_digest(key, new_key)
        except:
            return False
    
    def validate_password_strength(self, password):
        """Validate password against fortress policy"""
        errors = []
        if len(password) < FortressConfig.PASSWORD_MIN_LENGTH:
            errors.append(f"Password minimal {FortressConfig.PASSWORD_MIN_LENGTH} karakter")
        if FortressConfig.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Harus mengandung huruf BESAR")
        if FortressConfig.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Harus mengandung huruf kecil")
        if FortressConfig.PASSWORD_REQUIRE_NUMBERS and not re.search(r'\d', password):
            errors.append("Harus mengandung angka")
        if FortressConfig.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Harus mengandung karakter spesial")
        
        common = ['password', 'admin', '123456', 'qwerty', 'letmein']
        if any(p in password.lower() for p in common):
            errors.append("Password terlalu umum")
        
        return errors
    
    def get_user_by_username(self, username):
        for uid, user in self.users.items():
            if user['username'].lower() == username.lower():
                return user
        return None
    
    def get_user_by_id(self, uid):
        return self.users.get(uid)
    
    def get_all_users(self):
        return list(self.users.values())
    
    def create_user(self, username, password, email, ip):
        """Create new user with IP tracking"""
        if self.get_user_by_username(username):
            return None
        
        password_hash = self._hash_password(password)
        
        user = {
            'id': self.user_counter,
            'username': username,
            'password': password_hash,
            'email': email,
            'role': 'user',
            'ip_registration': ip,
            'ip_last': ip,
            'join_date': datetime.now().isoformat(),
            'is_banned': False,
            'ban_reason': None,
            'banned_by': None,
            'ban_date': None,
            'failed_attempts': 0,
            'locked_until': None,
            'active_session': None
        }
        
        self.users[self.user_counter] = user
        self.password_history[self.user_counter] = [password_hash]
        self.user_counter += 1
        
        self.log_activity(user['id'], 'REGISTER', f'User registered from IP: {ip}')
        return user
    
    def create_session(self, user_id, ip, user_agent):
        """Create new session with WHID enforcement"""
        # WHID System: Invalidate previous sessions
        if FortressConfig.WHID_FORCE_LOGOUT_PREVIOUS:
            self.invalidate_user_sessions(user_id)
        
        session_id = self.session_counter
        self.session_counter += 1
        
        # Generate device fingerprint
        fingerprint = hashlib.sha256(
            f"{ip}|{user_agent}|{secrets.token_hex(8)}".encode()
        ).hexdigest()
        
        session = {
            'id': session_id,
            'user_id': user_id,
            'ip': ip,
            'user_agent': user_agent,
            'fingerprint': fingerprint,
            'created': datetime.now().isoformat(),
            'last_active': datetime.now().isoformat(),
            'expires': (datetime.now() + timedelta(minutes=FortressConfig.SESSION_TIMEOUT_MINUTES)).isoformat()
        }
        
        self.sessions[session_id] = session
        
        # Update user's active session
        user = self.users.get(user_id)
        if user:
            user['active_session'] = session_id
            user['ip_last'] = ip
        
        self.log_activity(user_id, 'LOGIN', f'New session created from IP: {ip}')
        return session_id, fingerprint
    
    def validate_session(self, session_id, ip, user_agent, fingerprint):
        """Validate session with IP binding and fingerprint"""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        # Check expiration
        if datetime.now() > datetime.fromisoformat(session['expires']):
            self.invalidate_session(session_id)
            return None
        
        # IP Binding
        if FortressConfig.IP_BINDING_ENABLED and session['ip'] != ip:
            return None
        
        # Fingerprint
        if FortressConfig.DEVICE_FINGERPRINTING and session['fingerprint'] != fingerprint:
            return None
        
        # Check if user still exists and not banned
        user = self.users.get(session['user_id'])
        if not user or user.get('is_banned'):
            self.invalidate_session(session_id)
            return None
        
        # Update last active
        session['last_active'] = datetime.now().isoformat()
        session['expires'] = (datetime.now() + timedelta(minutes=FortressConfig.SESSION_TIMEOUT_MINUTES)).isoformat()
        
        return session
    
    def invalidate_session(self, session_id):
        """Invalidate a single session"""
        if session_id in self.sessions:
            user_id = self.sessions[session_id]['user_id']
            del self.sessions[session_id]
            
            user = self.users.get(user_id)
            if user and user.get('active_session') == session_id:
                user['active_session'] = None
    
    def invalidate_user_sessions(self, user_id):
        """Invalidate all sessions for a user (WHID System)"""
        to_delete = []
        for sid, sess in self.sessions.items():
            if sess['user_id'] == user_id:
                to_delete.append(sid)
        
        for sid in to_delete:
            del self.sessions[sid]
        
        user = self.users.get(user_id)
        if user:
            user['active_session'] = None
    
    def check_login_attempts(self, ip, username):
        """Anti-brute force check"""
        key = f"{ip}:{username}"
        now = time.time()
        
        if key not in self.login_attempts:
            return True
        
        # Clean old attempts
        self.login_attempts[key] = [
            a for a in self.login_attempts[key] 
            if now - a < 900  # 15 minutes
        ]
        
        return len(self.login_attempts[key]) < FortressConfig.MAX_LOGIN_ATTEMPTS
    
    def record_login_attempt(self, ip, username, success):
        """Record login attempt for rate limiting"""
        key = f"{ip}:{username}"
        if key not in self.login_attempts:
            self.login_attempts[key] = []
        
        self.login_attempts[key].append(time.time())
        
        if not success:
            user = self.get_user_by_username(username)
            if user:
                user['failed_attempts'] = user.get('failed_attempts', 0) + 1
                if user['failed_attempts'] >= FortressConfig.MAX_LOGIN_ATTEMPTS:
                    user['locked_until'] = (
                        datetime.now() + timedelta(minutes=FortressConfig.ACCOUNT_LOCKOUT_MINUTES)
                    ).isoformat()
    
    def log_activity(self, user_id, action, details):
        """Log all activities for audit trail"""
        log = {
            'id': len(self.activity_logs) + 1,
            'user_id': user_id,
            'username': self.users.get(user_id, {}).get('username', 'unknown'),
            'action': action,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.activity_logs.append(log)
        return log
    
    # ========================================================================
    # OWNER ONLY FUNCTIONS - IP TRACKING & BLACKLIST
    # ========================================================================
    
    def blacklist_ip(self, ip, reason, admin_id):
        """Owner function: Blacklist IP address"""
        if ip not in self.ip_blacklist:
            self.ip_blacklist[ip] = {
                'ip': ip,
                'reason': reason,
                'blacklisted_by': admin_id,
                'blacklisted_at': datetime.now().isoformat()
            }
            self.log_activity(admin_id, 'IP_BLACKLIST', f'Blacklisted IP: {ip} - Reason: {reason}')
            return True
        return False
    
    def unblacklist_ip(self, ip, admin_id):
        """Owner function: Remove IP from blacklist"""
        if ip in self.ip_blacklist:
            del self.ip_blacklist[ip]
            self.log_activity(admin_id, 'IP_UNBLACKLIST', f'Removed IP from blacklist: {ip}')
            return True
        return False
    
    def is_ip_blacklisted(self, ip):
        """Check if IP is blacklisted"""
        return ip in self.ip_blacklist
    
    def ban_user(self, user_id, reason, admin_id):
        """Owner function: Ban user"""
        user = self.users.get(user_id)
        if user:
            user['is_banned'] = True
            user['ban_reason'] = reason
            user['banned_by'] = admin_id
            user['ban_date'] = datetime.now().isoformat()
            self.invalidate_user_sessions(user_id)
            self.log_activity(admin_id, 'USER_BAN', f'Banned user {user["username"]} - Reason: {reason}')
            return True
        return False
    
    def unban_user(self, user_id, admin_id):
        """Owner function: Unban user"""
        user = self.users.get(user_id)
        if user:
            user['is_banned'] = False
            user['ban_reason'] = None
            user['banned_by'] = None
            user['ban_date'] = None
            self.log_activity(admin_id, 'USER_UNBAN', f'Unbanned user {user["username"]}')
            return True
        return False
    
    def get_user_ip_info(self, user_id):
        """Owner function: Get complete IP info for user"""
        user = self.users.get(user_id)
        if user:
            return {
                'username': user['username'],
                'registration_ip': user['ip_registration'],
                'last_ip': user['ip_last'],
                'join_date': user['join_date'],
                'active_session': user.get('active_session')
            }
        return None
    
    def get_all_staff_sessions(self):
        """Owner function: Get all active staff sessions with IPs"""
        active_staff = []
        for uid, user in self.users.items():
            if user['role'] in ['staff', 'owner'] and user.get('active_session'):
                session = self.sessions.get(user['active_session'])
                if session:
                    active_staff.append({
                        'username': user['username'],
                        'role': user['role'],
                        'ip': session['ip'],
                        'last_active': session['last_active'],
                        'user_agent': session['user_agent'][:50]
                    })
        return active_staff
    
    # ========================================================================
    # STAFF FUNCTIONS
    # ========================================================================
    
    def staff_view_user_ips(self, staff_id):
        """Staff function: View all user IPs (non-staff only)"""
        users_ips = []
        for uid, user in self.users.items():
            if user['role'] == 'user':  # Staff only see regular users
                users_ips.append({
                    'username': user['username'],
                    'last_ip': user['ip_last'],
                    'join_date': user['join_date'],
                    'build_count': len([b for b in self.builds if b['user_id'] == uid])
                })
        return users_ips
    
    def staff_hide_build(self, build_id, staff_id, reason):
        """Staff function: Hide inappropriate build"""
        for build in self.builds:
            if build['id'] == build_id:
                build['is_hidden'] = True
                build['hidden_by'] = staff_id
                build['hide_reason'] = reason
                build['hidden_date'] = datetime.now().isoformat()
                self.log_activity(staff_id, 'BUILD_HIDE', f'Hidden build {build_id} - Reason: {reason}')
                return True
        return False
    
    def create_build(self, user_id, title, description, filename):
        """Create new build"""
        build = {
            'id': self.build_counter,
            'user_id': user_id,
            'title': title,
            'description': description,
            'filename': filename,
            'upload_date': datetime.now().isoformat(),
            'downloads': 0,
            'is_hidden': False,
            'hidden_by': None,
            'hide_reason': None
        }
        self.builds.append(build)
        self.build_counter += 1
        return build
    
    def get_builds(self, include_hidden=False, user_id=None):
        """Get builds with filtering"""
        results = []
        for build in self.builds:
            if build.get('is_hidden') and not include_hidden:
                continue
            if user_id and build['user_id'] != user_id:
                continue
            results.append(build)
        return results

# Initialize database
db = FortressDatabase()

# ============================================================================
# FLASK APPLICATION WITH 3D EFFECTS
# ============================================================================

app = Flask(__name__, 
            static_folder='../public',
            static_url_path='')

app.secret_key = FortressConfig.SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=FortressConfig.SESSION_TIMEOUT_MINUTES)

# ============================================================================
# DECORATORS - ACCESS CONTROL
# ============================================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        
        # Validate session with WHID
        session_id = session.get('session_id')
        ip = request.headers.get('x-forwarded-for', request.remote_addr).split(',')[0].strip()
        user_agent = request.headers.get('User-Agent', '')
        fingerprint = session.get('fingerprint')
        
        valid_session = db.validate_session(session_id, ip, user_agent, fingerprint)
        if not valid_session:
            session.clear()
            return redirect(url_for('login_page'))
        
        # Check if user is banned
        user = db.get_user_by_id(session['user_id'])
        if not user or user.get('is_banned'):
            session.clear()
            return redirect(url_for('login_page'))
        
        g.user = user
        return f(*args, **kwargs)
    return decorated

def owner_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        
        user = db.get_user_by_id(session['user_id'])
        if not user or user['role'] != 'owner':
            return "Access Denied - Owner Only", 403
        
        return f(*args, **kwargs)
    return decorated

def staff_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        
        user = db.get_user_by_id(session['user_id'])
        if not user or user['role'] not in ['staff', 'owner']:
            return "Access Denied - Staff Only", 403
        
        return f(*args, **kwargs)
    return decorated

# ============================================================================
# HTML TEMPLATES WITH 3D EFFECTS
# ============================================================================

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OXYX FORTRESS - Build a Boat Repository</title>
    <link rel="stylesheet" href="/css/style.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
</head>
<body>
    <div id="particles-js"></div>
    <div class="container">
        <nav class="glass-nav">
            <div class="logo">OXYX<span>FORTRESS</span></div>
            <div class="nav-links">
                <a href="/">Home</a>
                {% if session.get('user_id') %}
                    <a href="/dashboard">Dashboard</a>
                    {% if session.get('role') == 'owner' %}
                        <a href="/owner-panel">Owner Panel</a>
                    {% elif session.get('role') == 'staff' %}
                        <a href="/staff-panel">Staff Panel</a>
                    {% endif %}
                    <a href="/builds">Builds</a>
                    <a href="/logout">Logout</a>
                {% else %}
                    <a href="/login">Login</a>
                    <a href="/register">Register</a>
                {% endif %}
            </div>
        </nav>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <main>
            {{ content|safe }}
        </main>
    </div>
    
    <script src="/js/effects.js"></script>
    <script src="/js/main.js"></script>
    <script>
        // Initialize particles
        particlesJS.load('particles-js', '/js/particles-config.json', function() {
            console.log('Particles loaded');
        });
    </script>
</body>
</html>
'''

INDEX_PAGE = '''
<div class="hero-section">
    <div id="three-canvas"></div>
    <div class="hero-content glass-card">
        <h1 class="glitch-text">OXYX FORTRESS</h1>
        <p class="typing-effect">Secure Build Repository for Build a Boat</p>
        <div class="hero-buttons">
            {% if not session.get('user_id') %}
                <a href="/login" class="btn btn-primary glow-effect">Enter Fortress</a>
                <a href="/register" class="btn btn-secondary">Create Account</a>
            {% else %}
                <a href="/builds" class="btn btn-primary glow-effect">View Builds</a>
                <a href="/dashboard" class="btn btn-secondary">Dashboard</a>
            {% endif %}
        </div>
    </div>
</div>

<div class="stats-section">
    <div class="stat-card glass-card" data-aos="fade-up">
        <div class="stat-number">{{ stats.total_users }}</div>
        <div class="stat-label">Fortress Members</div>
    </div>
    <div class="stat-card glass-card" data-aos="fade-up" data-aos-delay="100">
        <div class="stat-number">{{ stats.total_builds }}</div>
        <div class="stat-label">Protected Builds</div>
    </div>
    <div class="stat-card glass-card" data-aos="fade-up" data-aos-delay="200">
        <div class="stat-number">{{ stats.active_staff }}</div>
        <div class="stat-label">Guardians Online</div>
    </div>
</div>

<div class="features-grid">
    <div class="feature-card glass-card" data-aos="zoom-in">
        <div class="feature-icon">🛡️</div>
        <h3>WHID Protection</h3>
        <p>Single session only - Maximum security</p>
    </div>
    <div class="feature-card glass-card" data-aos="zoom-in" data-aos-delay="100">
        <div class="feature-icon">👁️</div>
        <h3>IP Tracking</h3>
        <p>Complete visibility for owners</p>
    </div>
    <div class="feature-card glass-card" data-aos="zoom-in" data-aos-delay="200">
        <div class="feature-icon">⚔️</div>
        <h3>Anti-Brute Force</h3>
        <p>Military grade protection</p>
    </div>
    <div class="feature-card glass-card" data-aos="zoom-in" data-aos-delay="300">
        <div class="feature-icon">🔮</div>
        <h3>3D Visualization</h3>
        <p>Interactive fortress experience</p>
    </div>
</div>
'''

LOGIN_PAGE = '''
<div class="auth-container">
    <div class="auth-card glass-card">
        <h2 class="glitch-text">Enter The Fortress</h2>
        <form method="POST" class="auth-form">
            <div class="input-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required 
                       class="glass-input" placeholder="Enter your username">
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required 
                       class="glass-input" placeholder="Enter your password">
            </div>
            <button type="submit" class="btn btn-primary btn-block glow-effect">
                Access Fortress
            </button>
        </form>
        <p class="auth-link">Not a member? <a href="/register">Create account</a></p>
    </div>
</div>
'''

REGISTER_PAGE = '''
<div class="auth-container">
    <div class="auth-card glass-card">
        <h2 class="glitch-text">Join The Fortress</h2>
        <div class="password-requirements glass-card">
            <h4>Fortress Requirements:</h4>
            <ul>
                <li>Minimal 14 characters</li>
                <li>Uppercase & lowercase letters</li>
                <li>Numbers & special characters</li>
                <li>No common passwords</li>
            </ul>
        </div>
        <form method="POST" class="auth-form">
            <div class="input-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required class="glass-input">
            </div>
            <div class="input-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required class="glass-input">
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required class="glass-input">
                <div class="password-strength" id="password-strength"></div>
            </div>
            <div class="input-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required class="glass-input">
            </div>
            <button type="submit" class="btn btn-primary btn-block glow-effect">
                Join Fortress
            </button>
        </form>
        <p class="auth-link">Already a member? <a href="/login">Enter Fortress</a></p>
    </div>
</div>
'''

OWNER_PANEL = '''
<div class="owner-panel">
    <h1 class="glitch-text">👑 Owner Command Center</h1>
    
    <div class="stats-grid">
        <div class="stat-card glass-card">
            <div class="stat-number">{{ stats.total_users }}</div>
            <div class="stat-label">Total Members</div>
        </div>
        <div class="stat-card glass-card">
            <div class="stat-number">{{ stats.active_staff }}</div>
            <div class="stat-label">Staff Online</div>
        </div>
        <div class="stat-card glass-card">
            <div class="stat-number">{{ stats.blacklisted_ips }}</div>
            <div class="stat-label">Blacklisted IPs</div>
        </div>
    </div>
    
    <div class="panel-sections">
        <div class="section glass-card">
            <h2>🔍 IP Tracking - All Members</h2>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Registration IP</th>
                            <th>Last IP</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for user in users %}
                        <tr>
                            <td>{{ user.username }}</td>
                            <td><span class="role-badge role-{{ user.role }}">{{ user.role }}</span></td>
                            <td><span class="ip-address">{{ user.ip_registration }}</span></td>
                            <td><span class="ip-address">{{ user.ip_last }}</span></td>
                            <td>
                                {% if user.is_banned %}
                                    <span class="status-banned">BANNED</span>
                                {% else %}
                                    <span class="status-active">ACTIVE</span>
                                {% endif %}
                            </td>
                            <td>
                                {% if user.role != 'owner' %}
                                    <button onclick="banUser({{ user.id }})" class="btn-small btn-danger">Ban</button>
                                    <button onclick="viewIPHistory({{ user.id }})" class="btn-small btn-info">IP History</button>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="section glass-card">
            <h2>🛡️ Active Staff Sessions</h2>
            <div class="staff-grid">
                {% for staff in active_staff %}
                <div class="staff-card glass-card pulse-effect">
                    <div class="staff-avatar">{{ staff.username[0]|upper }}</div>
                    <div class="staff-info">
                        <div class="staff-name">{{ staff.username }}</div>
                        <div class="staff-role">{{ staff.role }}</div>
                        <div class="staff-ip">IP: {{ staff.ip }}</div>
                        <div class="staff-time">Last: {{ staff.last_active }}</div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="section glass-card">
            <h2>⚫ IP Blacklist Management</h2>
            <form class="blacklist-form" onsubmit="blacklistIP(event)">
                <input type="text" id="ip-address" placeholder="IP Address to blacklist" class="glass-input" required>
                <input type="text" id="ban-reason" placeholder="Reason" class="glass-input" required>
                <button type="submit" class="btn btn-danger">Blacklist IP</button>
            </form>
            
            <div class="blacklist-table">
                <h3>Current Blacklist</h3>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Reason</th>
                            <th>Blacklisted By</th>
                            <th>Date</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for ip, data in blacklist.items() %}
                        <tr>
                            <td>{{ ip }}</td>
                            <td>{{ data.reason }}</td>
                            <td>{{ data.blacklisted_by }}</td>
                            <td>{{ data.blacklisted_at }}</td>
                            <td>
                                <button onclick="unblacklistIP('{{ ip }}')" class="btn-small btn-success">Remove</button>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="section glass-card">
            <h2>📊 Activity Logs</h2>
            <div class="logs-container">
                {% for log in logs %}
                <div class="log-entry">
                    <span class="log-time">{{ log.timestamp }}</span>
                    <span class="log-user">{{ log.username }}</span>
                    <span class="log-action">{{ log.action }}</span>
                    <span class="log-details">{{ log.details }}</span>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
</div>

<script>
function banUser(userId) {
    if(confirm('Ban this user?')) {
        fetch('/api/owner/ban/' + userId, {method: 'POST'})
        .then(r => r.json())
        .then(d => location.reload());
    }
}

function blacklistIP(e) {
    e.preventDefault();
    const ip = document.getElementById('ip-address').value;
    const reason = document.getElementById('ban-reason').value;
    
    fetch('/api/owner/blacklist', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip: ip, reason: reason})
    }).then(r => r.json()).then(d => location.reload());
}

function unblacklistIP(ip) {
    if(confirm('Remove IP from blacklist?')) {
        fetch('/api/owner/unblacklist/' + ip, {method: 'POST'})
        .then(r => r.json())
        .then(d => location.reload());
    }
}
</script>
'''

STAFF_PANEL = '''
<div class="staff-panel">
    <h1 class="glitch-text">🛡️ Staff Command Center</h1>
    
    <div class="section glass-card">
        <h2>👁️ Member IP Monitoring</h2>
        <div class="table-container">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Last IP</th>
                        <th>Join Date</th>
                        <th>Builds</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for member in members %}
                    <tr>
                        <td>{{ member.username }}</td>
                        <td><span class="ip-address">{{ member.last_ip }}</span></td>
                        <td>{{ member.join_date }}</td>
                        <td>{{ member.build_count }}</td>
                        <td><span class="status-active">ACTIVE</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    
    <div class="section glass-card">
        <h2>⚔️ Build Moderation</h2>
        <div class="builds-grid">
            {% for build in builds %}
            <div class="build-card glass-card">
                <h3>{{ build.title }}</h3>
                <p>{{ build.description }}</p>
                <div class="build-meta">
                    <span>By: User #{{ build.user_id }}</span>
                    <span>Downloads: {{ build.downloads }}</span>
                </div>
                {% if not build.is_hidden %}
                <button onclick="hideBuild({{ build.id }})" class="btn-small btn-danger">Hide Build</button>
                {% endif %}
            </div>
            {% endfor %}
        </div>
    </div>
</div>

<script>
function hideBuild(buildId) {
    const reason = prompt('Reason for hiding this build:');
    if(reason) {
        fetch('/api/staff/hide-build/' + buildId, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({reason: reason})
        }).then(r => r.json()).then(d => location.reload());
    }
}
</script>
'''

# ============================================================================
# ROUTES - AUTHENTICATION
# ============================================================================

@app.route('/')
def index():
    """Home page with 3D effects"""
    stats = {
        'total_users': len(db.users),
        'total_builds': len(db.builds),
        'active_staff': len(db.get_all_staff_sessions())
    }
    
    content = render_template_string(
        INDEX_PAGE, 
        stats=stats,
        session=session
    )
    
    return render_template_string(BASE_TEMPLATE, content=content, session=session)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """Login page with WHID system"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip = request.headers.get('x-forwarded-for', request.remote_addr).split(',')[0].strip()
        
        # Check IP blacklist
        if db.is_ip_blacklisted(ip):
            return render_template_string(BASE_TEMPLATE, 
                content='<div class="alert alert-error">Access denied from this IP</div>', 
                session=session)
        
        # Anti-brute force check
        if not db.check_login_attempts(ip, username):
            return render_template_string(BASE_TEMPLATE,
                content='<div class="alert alert-error">Too many attempts. Try again later.</div>',
                session=session)
        
        user = db.get_user_by_username(username)
        
        if user and db.verify_password(password, user['password']):
            # Check if account is locked
            if user.get('locked_until'):
                if datetime.now() < datetime.fromisoformat(user['locked_until']):
                    return render_template_string(BASE_TEMPLATE,
                        content='<div class="alert alert-error">Account locked. Try again later.</div>',
                        session=session)
            
            # Check if banned
            if user.get('is_banned'):
                return render_template_string(BASE_TEMPLATE,
                    content='<div class="alert alert-error">Account has been banned.</div>',
                    session=session)
            
            # Reset failed attempts
            user['failed_attempts'] = 0
            user['locked_until'] = None
            
            # WHID System - Create new session
            user_agent = request.headers.get('User-Agent', '')
            session_id, fingerprint = db.create_session(user['id'], ip, user_agent)
            
            # Set session
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['session_id'] = session_id
            session['fingerprint'] = fingerprint
            
            db.log_activity(user['id'], 'LOGIN_SUCCESS', f'Logged in from {ip}')
            
            # Redirect based on role
            if user['role'] == 'owner':
                return redirect(url_for('owner_panel'))
            elif user['role'] == 'staff':
                return redirect(url_for('staff_panel'))
            else:
                return redirect(url_for('dashboard'))
        else:
            db.record_login_attempt(ip, username, False)
            db.log_activity(None, 'LOGIN_FAILED', f'Failed login for {username} from {ip}')
            
            return render_template_string(BASE_TEMPLATE,
                content='<div class="alert alert-error">Invalid credentials</div>',
                session=session)
    
    content = render_template_string(LOGIN_PAGE)
    return render_template_string(BASE_TEMPLATE, content=content, session=session)

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    """Registration page with password validation"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm_password']
        email = request.form['email']
        ip = request.headers.get('x-forwarded-for', request.remote_addr).split(',')[0].strip()
        
        # Check IP blacklist
        if db.is_ip_blacklisted(ip):
            return render_template_string(BASE_TEMPLATE,
                content='<div class="alert alert-error">Registration from this IP is blocked</div>',
                session=session)
        
        # Validate password strength
        errors = db.validate_password_strength(password)
        if errors:
            error_html = '<div class="alert alert-error"><ul>' + ''.join([f'<li>{e}</li>' for e in errors]) + '</ul></div>'
            return render_template_string(BASE_TEMPLATE,
                content=error_html + REGISTER_PAGE,
                session=session)
        
        if password != confirm:
            return render_template_string(BASE_TEMPLATE,
                content='<div class="alert alert-error">Passwords do not match</div>' + REGISTER_PAGE,
                session=session)
        
        user = db.create_user(username, password, email, ip)
        if user:
            db.log_activity(user['id'], 'REGISTER_SUCCESS', f'New user registered from {ip}')
            return render_template_string(BASE_TEMPLATE,
                content='<div class="alert alert-success">Registration successful! Please login.</div>',
                session=session)
        else:
            return render_template_string(BASE_TEMPLATE,
                content='<div class="alert alert-error">Username already exists</div>' + REGISTER_PAGE,
                session=session)
    
    content = render_template_string(REGISTER_PAGE)
    return render_template_string(BASE_TEMPLATE, content=content, session=session)

@app.route('/logout')
def logout():
    """Logout and invalidate session"""
    session_id = session.get('session_id')
    if session_id:
        db.invalidate_session(session_id)
    
    session.clear()
    return redirect(url_for('index'))

# ============================================================================
# PROTECTED ROUTES
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user = g.user
    user_builds = db.get_builds(user_id=user['id'])
    
    dashboard_html = f'''
    <div class="dashboard">
        <h1 class="glitch-text">Welcome, {user['username']}!</h1>
        
        <div class="dashboard-stats">
            <div class="stat-card glass-card">
                <div class="stat-number">{len(user_builds)}</div>
                <div class="stat-label">Your Builds</div>
            </div>
            <div class="stat-card glass-card">
                <div class="stat-number">{user['join_date'][:10]}</div>
                <div class="stat-label">Member Since</div>
            </div>
            <div class="stat-card glass-card">
                <div class="stat-number">🛡️</div>
                <div class="stat-label">WHID Protected</div>
            </div>
        </div>
        
        <div class="section glass-card">
            <h2>Your Builds</h2>
            <div class="builds-grid">
    '''
    
    for build in user_builds:
        dashboard_html += f'''
        <div class="build-card glass-card">
            <h3>{build['title']}</h3>
            <p>{build['description']}</p>
            <div class="build-meta">
                <span>Downloads: {build['downloads']}</span>
                <span>{build['upload_date'][:10]}</span>
            </div>
        </div>
        '''
    
    dashboard_html += '''
            </div>
        </div>
    </div>
    '''
    
    return render_template_string(BASE_TEMPLATE, content=dashboard_html, session=session)

@app.route('/owner-panel')
@owner_required
def owner_panel():
    """Owner panel with IP tracking and blacklist"""
    users = db.get_all_users()
    active_staff = db.get_all_staff_sessions()
    blacklist = db.ip_blacklist
    logs = db.activity_logs[-100:]  # Last 100 logs
    
    stats = {
        'total_users': len(users),
        'active_staff': len(active_staff),
        'blacklisted_ips': len(blacklist)
    }
    
    content = render_template_string(
        OWNER_PANEL,
        users=users,
        active_staff=active_staff,
        blacklist=blacklist,
        logs=logs,
        stats=stats
    )
    
    return render_template_string(BASE_TEMPLATE, content=content, session=session)

@app.route('/staff-panel')
@staff_required
def staff_panel():
    """Staff panel with IP viewing and moderation"""
    members = db.staff_view_user_ips(session['user_id'])
    builds = db.get_builds()
    
    content = render_template_string(
        STAFF_PANEL,
        members=members,
        builds=builds
    )
    
    return render_template_string(BASE_TEMPLATE, content=content, session=session)

# ============================================================================
# API ROUTES - OWNER
# ============================================================================

@app.route('/api/owner/blacklist', methods=['POST'])
@owner_required
def api_blacklist():
    """API to blacklist IP"""
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason')
    
    if db.blacklist_ip(ip, reason, session['user_id']):
        return jsonify({'success': True})
    return jsonify({'success': False}), 400

@app.route('/api/owner/unblacklist/<path:ip>', methods=['POST'])
@owner_required
def api_unblacklist(ip):
    """API to remove IP from blacklist"""
    if db.unblacklist_ip(ip, session['user_id']):
        return jsonify({'success': True})
    return jsonify({'success': False}), 400

@app.route('/api/owner/ban/<int:user_id>', methods=['POST'])
@owner_required
def api_ban(user_id):
    """API to ban user"""
    data = request.json or {}
    reason = data.get('reason', 'Violating terms')
    
    if db.ban_user(user_id, reason, session['user_id']):
        return jsonify({'success': True})
    return jsonify({'success': False}), 400

@app.route('/api/owner/unban/<int:user_id>', methods=['POST'])
@owner_required
def api_unban(user_id):
    """API to unban user"""
    if db.unban_user(user_id, session['user_id']):
        return jsonify({'success': True})
    return jsonify({'success': False}), 400

@app.route('/api/owner/ip-info/<int:user_id>')
@owner_required
def api_ip_info(user_id):
    """API to get user IP info"""
    info = db.get_user_ip_info(user_id)
    if info:
        return jsonify(info)
    return jsonify({'error': 'User not found'}), 404

# ============================================================================
# API ROUTES - STAFF
# ============================================================================

@app.route('/api/staff/hide-build/<int:build_id>', methods=['POST'])
@staff_required
def api_hide_build(build_id):
    """API to hide inappropriate build"""
    data = request.json
    reason = data.get('reason', 'No reason')
    
    if db.staff_hide_build(build_id, session['user_id'], reason):
        return jsonify({'success': True})
    return jsonify({'success': False}), 400

# ============================================================================
# API ROUTES - PUBLIC
# ============================================================================

@app.route('/api/stats')
def api_stats():
    """Public stats API"""
    return jsonify({
        'total_users': len(db.users),
        'total_builds': len(db.builds),
        'active_sessions': len(db.sessions)
    })

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    content = '<div class="error-page"><h1>404 - Not Found</h1><p>The fortress section you seek does not exist.</p></div>'
    return render_template_string(BASE_TEMPLATE, content=content, session=session), 404

@app.errorhandler(500)
def server_error(e):
    content = '<div class="error-page"><h1>500 - Internal Fortress Error</h1><p>The guardians are investigating.</p></div>'
    return render_template_string(BASE_TEMPLATE, content=content, session=session), 500

# ============================================================================
# VERCEL HANDLER
# ============================================================================

def handler(request):
    """Vercel serverless function handler"""
    with app.request_context(request):
        try:
            response = app.full_dispatch_request()
            return response
        except Exception as e:
            return {
                'statusCode': 500,
                'body': str(e)
            }
