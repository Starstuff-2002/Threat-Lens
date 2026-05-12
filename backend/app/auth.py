import sqlite3
import os

DB_PATH = "threatlens.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
    ''')
    
    # Check if we need to insert mock users
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        mock_users = [
            ("admin", "admin", "admin"),
            ("dev", "password", "developer"),
            ("guest", "guest", "guest")
        ]
        cursor.executemany('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', mock_users)
        conn.commit()
        
    conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT role FROM users WHERE username = ? AND password = ?', (username, password))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {"username": username, "role": result[0]}
    return None

def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users')
    users = [{"id": row[0], "username": row[1], "role": row[2]} for row in cursor.fetchall()]
    conn.close()
    return users
