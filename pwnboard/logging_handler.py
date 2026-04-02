import logging
from datetime import datetime
from .db import pooled_connection

class DBHandler(logging.Handler):
    def __init__(self):
        super().__init__()

    def emit(self, record):
        msg = record.getMessage()
        if "updated beacon for" in msg and "from" in msg:
            parts = msg.split()
            try:
                ip = parts[3]
                app = parts[5]
            except IndexError:
                ip = app = "unknown"

            try:
                with pooled_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO logs (timestamp, level, ip, app, message) VALUES (%s, %s, %s, %s, %s)",
                            (datetime.fromtimestamp(record.created).isoformat(), record.levelname, ip, app, msg),
                        )
                    conn.commit()
            except Exception:
                self.handleError(record)