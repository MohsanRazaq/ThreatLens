from datetime import datetime

ALERT_LOG_FILE = "security_alerts.log"

def write_log(message):
    """Appends a security event with an explicit timestamp to disk."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{current_time}] {message}\n"
    
    with open(ALERT_LOG_FILE, "a",errors='ignore', encoding="utf-8") as f:
        f.write(log_entry)