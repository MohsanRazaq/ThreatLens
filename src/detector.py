from datetime import datetime
from logger import write_log
from constants import MAX_404_THRESHOLD, MAX_LOGIN_THRESHOLD

TIME_PATTERN = "%d/%b/%Y:%H:%M:%S %z"

def detect_vulnerability_scanners(ip, hits):
    """Checks if an IP is rapidly hitting non-existent endpoints."""
    errors_404_timestamp = [hit['timestamps'] for hit in hits if hit['status_code'] == '404']
    
    if errors_404_timestamp and len(errors_404_timestamp) > MAX_404_THRESHOLD:
        first_404_time = datetime.strptime(errors_404_timestamp[0], TIME_PATTERN).timestamp()
        last_404_time = datetime.strptime(errors_404_timestamp[-1], TIME_PATTERN).timestamp()
        
        if last_404_time - first_404_time <= 300:
            alert_msg = f'BLock Ip {ip}: Found "not found" errors [Vulnerability Scanner]'
            print(alert_msg)
            write_log(alert_msg)


def detect_brute_force(ip, hits):
    """Checks if an IP is hammering login pages with POST requests."""
    login_attempts = sum(1 for hit in hits if hit['method'] == 'POST' and 'login' in hit['url'].lower())
    
    if login_attempts > MAX_LOGIN_THRESHOLD:
        alert_msg = f'BLock Ip [{ip}]: Detected {login_attempts} [credential brute-force detector]'
        print(alert_msg)
        write_log(alert_msg)


def detect_data_exfiltration(ip, hits):
    """Checks if an IP successfully pulled down massive server payloads."""
    for hit in hits:
        bytes_transferred = hit['size']
        if bytes_transferred > 524288000:  # 500 MB
            alert_msg = f' ALERT IP [{ip}]: Downloaded a massive file ({bytes_transferred / 1024 / 1024:.2f} MB) at {hit["timestamps"]}. Potential Data Leak!'                
            print(alert_msg)
            write_log(alert_msg)