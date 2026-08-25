import sqlite3


DB_NAME = "database.db"


def get_connection():
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            attempts INTEGER DEFAULT 1,
            unknown_device INTEGER DEFAULT 0,
            unusual_time INTEGER DEFAULT 0,
            verification_failures INTEGER DEFAULT 0,
            location_change INTEGER DEFAULT 0,
            request_rate REAL DEFAULT 0,
            risk_score REAL DEFAULT 0,
            threat_level TEXT DEFAULT 'LOW',
            result TEXT DEFAULT 'NORMAL',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


def insert_event(
    username,
    action,
    attempts,
    unknown_device,
    unusual_time,
    verification_failures,
    location_change,
    request_rate,
    risk_score,
    threat_level,
    result
):
    connection = get_connection()

    connection.execute("""
        INSERT INTO events (
            username,
            action,
            attempts,
            unknown_device,
            unusual_time,
            verification_failures,
            location_change,
            request_rate,
            risk_score,
            threat_level,
            result
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        username,
        action,
        attempts,
        unknown_device,
        unusual_time,
        verification_failures,
        location_change,
        request_rate,
        risk_score,
        threat_level,
        result
    ))

    connection.commit()
    connection.close()


def get_events():
    connection = get_connection()
    rows = connection.execute(
        "SELECT * FROM events ORDER BY id DESC"
    ).fetchall()
    connection.close()
    return rows
