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
            access_result TEXT
        )
    """)
    conn.commit()
    conn.close()
