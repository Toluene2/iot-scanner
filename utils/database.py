import sqlite3
import hashlib
import os
import json
from datetime import datetime

class ScannerDB:
    def __init__(self, db_path="scanner.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    must_change_password BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Check if must_change_password exists (for legacy DBs)
            cursor.execute("PRAGMA table_info(users)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'must_change_password' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 1")
            if 'email' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
                
            # Seed admin user if no users exist
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                admin_hash = self.hash_password("admin")
                cursor.execute("INSERT INTO users (username, password_hash, must_change_password, email) VALUES (?, ?, ?, ?)", 
                               ("admin", admin_hash, 1, "admin@iotguard.com"))
            # Ensure there is always an admin user
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
            if cursor.fetchone()[0] == 0:
                admin_hash = self.hash_password("admin")
                cursor.execute("INSERT INTO users (username, password_hash, must_change_password, email) VALUES (?, ?, ?, ?)", 
                               ("admin", admin_hash, 1, "admin@iotguard.com"))
            # Ensure admin user has settings row
            cursor.execute("SELECT id FROM users WHERE username = 'admin'")
            admin_row = cursor.fetchone()
            if admin_row:
                admin_id = admin_row[0]
                cursor.execute("SELECT COUNT(*) FROM settings WHERE user_id = ?", (admin_id,))
                if cursor.fetchone()[0] == 0:
                    cursor.execute("INSERT INTO settings (user_id) VALUES (?)", (admin_id,))
            # Scan history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    scan_type TEXT, -- 'WiFi' or 'Subnet'
                    target TEXT, -- SSID or CIDR
                    device_count INTEGER,
                    vuln_high INTEGER,
                    vuln_med INTEGER,
                    vuln_low INTEGER,
                    results_json TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            # Settings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    user_id INTEGER PRIMARY KEY,
                    default_subnet TEXT DEFAULT '192.168.1.0/24',
                    auto_scan_wifi BOOLEAN DEFAULT 0,
                    report_email TEXT,
                    enable_email_reset BOOLEAN DEFAULT 1,
                    enable_security_questions BOOLEAN DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            # Add columns if they are missing for backwards compatibility
            cursor.execute("PRAGMA table_info(settings)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'enable_email_reset' not in columns:
                cursor.execute("ALTER TABLE settings ADD COLUMN enable_email_reset BOOLEAN DEFAULT 1")
            if 'enable_security_questions' not in columns:
                cursor.execute("ALTER TABLE settings ADD COLUMN enable_security_questions BOOLEAN DEFAULT 1")
            # Security questions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_questions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    question_text TEXT UNIQUE NOT NULL
                )
            """)
            # Seed default security questions if empty
            cursor.execute("SELECT COUNT(*) FROM security_questions")
            if cursor.fetchone()[0] == 0:
                default_questions = [
                    "What is the name of your first pet?",
                    "What is your mother's maiden name?",
                    "In what city were you born?",
                    "What is the name of your best friend from childhood?",
                    "What is your favorite book?",
                    "What is the name of your elementary school?",
                    "What is your favorite movie?",
                    "What is the street name of your childhood home?",
                    "What is your favorite sports team?",
                    "What is your favorite food?"
                ]
                for question in default_questions:
                    cursor.execute("INSERT INTO security_questions (question_text) VALUES (?)", (question,))
            
            # User security answers table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_security_answers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    question_id INTEGER,
                    answer_hash TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (question_id) REFERENCES security_questions(id),
                    UNIQUE(user_id, question_id)
                )
            """)
            # Password reset tokens table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    token TEXT UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Support messages table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS support_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    subject TEXT NOT NULL,
                    message TEXT NOT NULL,
                    status TEXT DEFAULT 'Open',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            conn.commit()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def create_user(self, username, password, email=None):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                pwd_hash = self.hash_password(password)
                cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, pwd_hash, email))
                user_id = cursor.lastrowid
                # Initialize settings for user
                cursor.execute("INSERT INTO settings (user_id) VALUES (?)", (user_id,))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def authenticate_user(self, username, password):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            pwd_hash = self.hash_password(password)
            cursor.execute("SELECT id, must_change_password FROM users WHERE username = ? AND password_hash = ?", (username, pwd_hash))
            user = cursor.fetchone()
            return user if user else None

    def get_user_info(self, username):
        """Get user info including derived role"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if user:
                # Return tuple: (id, username, role) where role is derived from username
                user_id, user_name, email = user
                role = 'admin' if user_name == 'admin' else 'user'
                return (user_id, user_name, role)
            return None

    def update_user_email(self, user_id, email):
        """Update user email address"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
            conn.commit()
            return True

    def change_password(self, user_id, new_password):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            pwd_hash = self.hash_password(new_password)
            cursor.execute("""
                UPDATE users SET password_hash = ?, must_change_password = 0
                WHERE id = ?
            """, (pwd_hash, user_id))
            conn.commit()
            return True

    def add_scan_record(self, user_id, scan_type, target, results):
        devices = results.get('devices', {})
        device_count = len(devices)
        
        # Calculate vulnerability counts
        high, med, low = 0, 0, 0
        assessment = results.get('assessment', {})
        risk_summary = assessment.get('risk_assessment', {})
        severity = risk_summary.get('severity_breakdown', {})
        
        high = severity.get('Critical', 0) + severity.get('High', 0)
        med = severity.get('Medium', 0)
        low = severity.get('Low', 0) + severity.get('Info', 0)

        results_json = json.dumps(results)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scans (user_id, scan_type, target, device_count, vuln_high, vuln_med, vuln_low, results_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, scan_type, target, device_count, high, med, low, results_json))
            conn.commit()

    def get_scan_history(self, user_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_user_settings(self, user_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM settings WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_user_settings(self, user_id, subnet, auto_wifi, email, enable_email_reset=True, enable_security_questions=True):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE settings SET default_subnet = ?, auto_scan_wifi = ?, report_email = ?,
                    enable_email_reset = ?, enable_security_questions = ?
                WHERE user_id = ?
            """, (subnet, int(auto_wifi), email, int(enable_email_reset), int(enable_security_questions), user_id))
            conn.commit()
            
    def update_user_password(self, username, new_password_hash):
        """Update a user's password in the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET password_hash = ? WHERE username = ?",
                    (new_password_hash, username)
                )
                conn.commit()
            return True
        except Exception as e:
            print(f"Database Error: {e}")
            return False

    def get_admin_settings(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", ('admin',))
            result = cursor.fetchone()
            if result:
                return self.get_user_settings(result['id'])
            return None

    def get_dashboard_summary(self, user_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*), SUM(device_count), SUM(vuln_high), SUM(vuln_med), SUM(vuln_low)
                FROM scans WHERE user_id = ?
            """, (user_id,))
            stats = cursor.fetchone()
            # If no scans, stats will have Nones or be (0, None, ...)
            return {
                'total_scans': stats[0] or 0,
                'total_devices': stats[1] or 0,
                'total_high': stats[2] or 0,
                'total_med': stats[3] or 0,
                'total_low': stats[4] or 0
            }

    def get_all_users(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, created_at, must_change_password FROM users")
            return [dict(row) for row in cursor.fetchall()]

    def delete_user(self, user_id):
        # Protect admin account from deletion, regardless of id renumbering state
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if not user:
                return False
            if user[0] == 'admin':
                return False

            cursor.execute("DELETE FROM settings WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM user_security_answers WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return True

    def get_security_questions(self, count=3):
        """Get random security questions for user setup"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, question_text FROM security_questions ORDER BY RANDOM() LIMIT ?", (count,))
            return [{'id': row[0], 'text': row[1]} for row in cursor.fetchall()]

    def get_all_security_questions(self):
        """Return all security questions from the database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, question_text FROM security_questions ORDER BY id")
            return [{'id': row[0], 'text': row[1]} for row in cursor.fetchall()]

    def add_security_question(self, question_text):
        """Insert a new security question"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO security_questions (question_text) VALUES (?)", (question_text.strip(),))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def delete_security_question(self, question_id):
        """Delete a security question if it exists and not used by users (or clears associated answers)."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Optionally clear user answers for this question
            cursor.execute("DELETE FROM user_security_answers WHERE question_id = ?", (question_id,))
            cursor.execute("DELETE FROM security_questions WHERE id = ?", (question_id,))
            conn.commit()
            return True

    def set_security_answers(self, user_id, answers_dict):
        """Store user's security question answers (answers_dict: {question_id: answer})"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                for question_id, answer in answers_dict.items():
                    answer_hash = self.hash_password(answer.strip().lower())
                    cursor.execute("""
                        INSERT OR REPLACE INTO user_security_answers (user_id, question_id, answer_hash)
                        VALUES (?, ?, ?)
                    """, (user_id, question_id, answer_hash))
                conn.commit()
                return True
        except Exception as e:
            return False

    def get_user_security_questions_for_recovery(self, username, count=2):
        """Get security questions for password recovery (with question IDs but not answers)"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT u.id FROM users u WHERE u.username = ?
            """, (username,))
            user = cursor.fetchone()
            if not user:
                return None, None
            
            user_id = user[0]
            cursor.execute("""
                SELECT sq.id, sq.question_text FROM user_security_answers usa
                JOIN security_questions sq ON usa.question_id = sq.id
                WHERE usa.user_id = ?
                ORDER BY RANDOM() LIMIT ?
            """, (user_id, count))
            
            questions = [{'id': row[0], 'text': row[1]} for row in cursor.fetchall()]
            return user_id, questions if questions else None

    def verify_security_answers(self, user_id, answers_dict):
        """Verify user's security answers (answers_dict: {question_id: answer})"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            correct_count = 0
            total_count = len(answers_dict)
            
            for question_id, answer in answers_dict.items():
                answer_hash = self.hash_password(answer.strip().lower())
                cursor.execute("""
                    SELECT answer_hash FROM user_security_answers
                    WHERE user_id = ? AND question_id = ?
                """, (user_id, question_id))
                result = cursor.fetchone()
                if result and result[0] == answer_hash:
                    correct_count += 1
            
            # All answers must be correct
            return correct_count == total_count and total_count > 0

    def reset_password_with_verification(self, user_id, new_password):
        """Reset password (should be called after security verification)"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            pwd_hash = self.hash_password(new_password)
            cursor.execute("""
                UPDATE users SET password_hash = ?
                WHERE id = ?
            """, (pwd_hash, user_id))
            conn.commit()
            return True

    def get_user_email(self, username):
        """Get user's email for password recovery"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            return result if result else None

    def create_password_reset_token(self, user_id):
        """Create a password reset token for email recovery"""
        import secrets
        import datetime
        
        token = secrets.token_urlsafe(32)
        expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)  # 1 hour expiry
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO password_reset_tokens (user_id, token, expires_at)
                    VALUES (?, ?, ?)
                """, (user_id, token, expires_at.isoformat()))
                conn.commit()
                return token
        except Exception as e:
            return None

    def verify_password_reset_token(self, token):
        """Verify a password reset token and return user_id if valid"""
        import datetime
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT user_id, expires_at, used FROM password_reset_tokens
                WHERE token = ? AND used = 0
            """, (token,))
            
            result = cursor.fetchone()
            if not result:
                return None
                
            user_id, expires_at_str, used = result
            
            # Check if token has expired
            expires_at = datetime.datetime.fromisoformat(expires_at_str)
            if datetime.datetime.now() > expires_at:
                return None
                
            return user_id

    def use_password_reset_token(self, token, new_password):
        """Use a password reset token to change password"""
        user_id = self.verify_password_reset_token(token)
        if not user_id:
            return False
            
        # Reset password
        pwd_hash = self.hash_password(new_password)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users SET password_hash = ?, must_change_password = 0
                WHERE id = ?
            """, (pwd_hash, user_id))
            
            # Mark token as used
            cursor.execute("""
                UPDATE password_reset_tokens SET used = 1
                WHERE token = ?
            """, (token,))
            
            conn.commit()
            return True

    def create_support_message(self, user_id, subject, message):
        """Create a new support message/ticket"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO support_messages (user_id, subject, message)
                VALUES (?, ?, ?)
            """, (user_id, subject, message))
            conn.commit()
            return True

    def get_support_messages(self, user_id=None):
        """Get support messages. If user_id provided, get only that user's messages. Otherwise get all (admin)"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if user_id:
                cursor.execute("""
                    SELECT sm.*, u.username FROM support_messages sm
                    JOIN users u ON sm.user_id = u.id
                    WHERE sm.user_id = ?
                    ORDER BY sm.created_at DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT sm.*, u.username FROM support_messages sm
                    JOIN users u ON sm.user_id = u.id
                    ORDER BY sm.created_at DESC
                """)
            return [dict(row) for row in cursor.fetchall()]

    def update_message_status(self, message_id, status):
        """Update support message status (Open/Resolved/In Progress)"""
        resolved_at = datetime.now() if status == 'Resolved' else None
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE support_messages
                SET status = ?, resolved_at = ?
                WHERE id = ?
            """, (status, resolved_at, message_id))
            conn.commit()
            return True
