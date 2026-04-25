#!/usr/bin/env python3
"""
Password Reset Script for IoT Scanner
Resets all user passwords to 'admin' and forces password change on next login.
"""

import sqlite3
import hashlib
import os
from pathlib import Path

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def reset_all_passwords(db_path="scanner.db"):
    """Reset all user passwords to 'admin' and set must_change_password = 1"""
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found!")
        return False

    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            # Get all users
            cursor.execute("SELECT id, username FROM users")
            users = cursor.fetchall()

            if not users:
                print("No users found in database!")
                return False

            admin_hash = hash_password("admin")

            # Reset all passwords
            cursor.execute("""
                UPDATE users SET password_hash = ?, must_change_password = 1
            """, (admin_hash,))

            print(f"Successfully reset passwords for {len(users)} users:")
            for user_id, username in users:
                print(f"  - {username}: password reset to 'admin'")

            conn.commit()
            return True

    except Exception as e:
        print(f"Error resetting passwords: {e}")
        return False

if __name__ == "__main__":
    print("IoT Scanner Password Reset Tool")
    print("=" * 40)
    print("Resetting ALL user passwords to 'admin'")
    print("Users will be forced to change password on next login")
    print()
    
    if reset_all_passwords():
        print("\nPassword reset complete!")
        print("All users can now login with password 'admin'")
        print("They will be required to change it immediately.")
    else:
        print("\nPassword reset failed!")