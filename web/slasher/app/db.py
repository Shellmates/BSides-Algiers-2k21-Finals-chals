import sqlite3
import os
import time
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DB_PATH")

SQL_CREATE_USERS_TABLE = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        created_at DATE
    )
"""
SQL_CREATE_FILES_TABLE = """
    CREATE TABLE IF NOT EXISTS files (
        filename TEXT,
        user_id INTEGER,
        enc_filename TEXT,
        created_at DATE,
        PRIMARY KEY (filename, user_id),
        FOREIGN KEY (user_id)
        REFERENCES users (id)
            ON DELETE CASCADE
    )
"""

def init_db():
    execute_query(SQL_CREATE_USERS_TABLE)
    execute_query(SQL_CREATE_FILES_TABLE)

def execute_query(query, params=()):
    conn = sqlite3.connect(DB_PATH)
    curs = conn.cursor()
    curs.execute(query, params)
    result = curs.fetchall()
    conn.commit()
    conn.close()

    return result

class UserService:
    @staticmethod
    def exists(uid):
        result = execute_query("SELECT 1 FROM users WHERE id = ?", (uid,))
        return len(result) != 0

    @staticmethod
    def username_exists(username):
        result = execute_query("SELECT 1 FROM users WHERE username = ?", (username,))
        return len(result) != 0

    @staticmethod
    def add(username, password):
        if not UserService.username_exists(username):
            t = int(time.time())
            execute_query("INSERT INTO users (username, password, created_at) VALUES(?, ?, ?)", (username, password, t))
            return True
        else:
            return False

    @staticmethod
    def get(uid):
        rows = execute_query("SELECT username, password, created_at FROM users WHERE id = ?", (uid,))
        if len(rows) != 0:
            return {
                "id": uid,
                "username": rows[0][0],
                "password": rows[0][1],
                "created_at": rows[0][2]
            }
        else:
            return None

    @staticmethod
    def get_by_name(username):
        rows = execute_query("SELECT id, password, created_at FROM users WHERE username = ?", (username,))
        if len(rows) != 0:
            return {
                "id": rows[0][0],
                "username": username,
                "password": rows[0][1],
                "created_at": rows[0][2]
            }
        else:
            return None

    @staticmethod
    def getall():
        rows = execute_query("SELECT id, username, password, created_at FROM users")
        return [ {
            "id": row[0],
            "username": row[1],
            "password": row[2],
            "created_at": row[3],
        } for row in rows ]

class FileService:
    @staticmethod
    def exists(user_id, filename):
        result = execute_query("SELECT 1 FROM files WHERE user_id = ? AND filename = ?", (user_id, filename))
        return len(result) != 0

    @staticmethod
    def add(user_id, filename, enc_filename):
        if UserService.exists(user_id) and not FileService.exists(user_id, filename):
            t = int(time.time())
            execute_query("INSERT INTO files (user_id, filename, enc_filename, created_at) VALUES(?, ?, ?, ?)", (user_id, filename, enc_filename, t))
            return True
        else:
            return False

    @staticmethod
    def delete(user_id, filename):
        if FileService.exists(user_id, filename):
            execute_query("DELETE FROM files WHERE user_id = ? AND filename = ?", (user_id, filename))
            return True
        else:
            return False

    @staticmethod
    def get(user_id, enc_filename):
        rows = execute_query("SELECT filename, created_at FROM files WHERE user_id = ? AND enc_filename = ?", (user_id, enc_filename))
        if len(rows) != 0:
            return {
                "user_id": user_id,
                "filename": rows[0][0],
                "enc_filename": enc_filename,
                "created_at": rows[0][1],
            }
        else:
            return None

    @staticmethod
    def get_by_uid(user_id):
        rows = execute_query("SELECT filename, enc_filename, created_at FROM files WHERE user_id = ?", (user_id,))
        return [ {
            "user_id": user_id,
            "filename": row[0],
            "enc_filename": row[1],
            "created_at": row[2],
        } for row in rows ]

init_db()
