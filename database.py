"""Password history database module."""

import sqlite3
import bcrypt
from datetime import datetime
import os


class PasswordDatabase:
    """Manages password history and prevents reuse."""

    def __init__(self, db_path='password_history.db'):
        """Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize database schema if it doesn't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_email, password_hash)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                last_password_change TIMESTAMP,
                password_change_count INTEGER DEFAULT 0
            )
        ''')

        conn.commit()
        conn.close()

    def add_password(self, user_email, password):
        """Add a password to user's history.
        
        Args:
            user_email: User's email address
            password: The password to store (will be hashed)
            
        Returns:
            bool: True if successful
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Hash the password using bcrypt
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Update or insert user record
            cursor.execute('''
                INSERT OR REPLACE INTO users (email, last_password_change, password_change_count)
                VALUES (?, ?, (SELECT COALESCE(password_change_count, 0) + 1 FROM users WHERE email = ?))
            ''', (user_email, datetime.now(), user_email))

            # Add to password history
            cursor.execute('''
                INSERT INTO password_history (user_email, password_hash)
                VALUES (?, ?)
            ''', (user_email, password_hash))

            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False

    def is_password_reused(self, user_email, password):
        """Check if password has been used before by this user.
        
        Args:
            user_email: User's email address
            password: The password to check
            
        Returns:
            bool: True if password was previously used
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT password_hash FROM password_history
                WHERE user_email = ?
            ''', (user_email,))

            hashes = cursor.fetchall()
            conn.close()

            # Check if password matches any stored hash
            for (stored_hash,) in hashes:
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                    return True
            return False
        except Exception as e:
            print(f"Database error: {e}")
            return False

    def get_password_history(self, user_email):
        """Get password change history for a user.
        
        Args:
            user_email: User's email address
            
        Returns:
            list: List of password change records
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT created_at FROM password_history
                WHERE user_email = ?
                ORDER BY created_at DESC
            ''', (user_email,))

            records = cursor.fetchall()
            conn.close()
            return records
        except Exception as e:
            print(f"Database error: {e}")
            return []

    def get_user_stats(self, user_email):
        """Get password statistics for a user.
        
        Args:
            user_email: User's email address
            
        Returns:
            dict: User statistics
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT password_change_count, last_password_change FROM users
                WHERE email = ?
            ''', (user_email,))

            result = cursor.fetchone()
            conn.close()

            if result:
                return {
                    'password_changes': result[0],
                    'last_change': result[1],
                }
            return {'password_changes': 0, 'last_change': None}
        except Exception as e:
            print(f"Database error: {e}")
            return {}
