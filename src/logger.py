import os
from datetime import datetime
from constants import ALERT_LOG_FILE
LOG_Path=os.path.join(ALERT_LOG_FILE,'security.log')

def write_log(message):
    """Appends a security event with an explicit timestamp to disk."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{current_time}] {message}\n"
    
    with open(LOG_Path, "a",errors='ignore', encoding="utf-8") as f:
        f.write(log_entry)