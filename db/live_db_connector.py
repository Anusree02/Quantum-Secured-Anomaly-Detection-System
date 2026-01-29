import sqlite3  # or psycopg2 / mysql.connector

import sqlite3

def init_live_db():
    conn = sqlite3.connect("qshield_live.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ehr_access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            role TEXT,
            department TEXT,
            access_timestamp TEXT,
            access_type TEXT,
            action_performed TEXT,
            ehr_record_id TEXT,
            anomaly_score REAL,
            flag INTEGER,
            response_action TEXT,
            session_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def insert_ehr_log(event, score, flag, action):
    conn = sqlite3.connect("qshield_live.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ehr_access_logs 
        (user_id, role, department, access_timestamp, access_type, action_performed,
         ehr_record_id, anomaly_score, flag, response_action, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["user_id"], event["role"], event["department"], event["access_timestamp"],
        event["access_type"], event["action_performed"], event["ehr_record_id"],
        score, flag, action, event["session_id"]
    ))
    conn.commit()
    conn.close()
