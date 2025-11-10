import logging
import sqlite3
from datetime import datetime

class DBHandler(logging.Handler):
    def __init__(self, db_path="logs.db"):
        super().__init__()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_table()

    def _create_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                timestamp TEXT,
                level TEXT,
                ip TEXT,
                app TEXT,
                message TEXT
            )
        """)
        self.conn.commit()

    def emit(self, record):
        msg = record.getMessage()
        if "updated beacon for" in msg and "from" in msg:
            parts = msg.split()
            try:
                ip = parts[3]
                app = parts[5]
            except IndexError:
                ip = app = "unknown"
        else:
            ip = app = "unknown"

        self.conn.execute(
            "INSERT INTO logs (timestamp, level, ip, app, message) VALUES (?, ?, ?, ?, ?)",
            (datetime.fromtimestamp(record.created).isoformat(), record.levelname, ip, app, msg)
        )
        self.conn.commit()