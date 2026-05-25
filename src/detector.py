from datetime import datetime
from logger import write_log
from constants import MAX_404_THRESHOLD, MAX_LOGIN_THRESHOLD

TIME_PATTERN = "%d/%b/%Y:%H:%M:%S %z"

def detect_vulnerability_scanners(ip, hits):
    """Checks if an IP is hitting non-existent endpoints over a short window."""
    # Strip any potential whitespace layout padding from your status codes
    errors_404_timestamp = [hit['timestamps'] for hit in hits if str(hit['status_code']).strip() == '404']
    
    if errors_404_timestamp and len(errors_404_timestamp) > MAX_404_THRESHOLD:
        first_404_time = datetime.strptime(errors_404_timestamp[0], TIME_PATTERN).timestamp()
        last_404_time = datetime.strptime(errors_404_timestamp[-1], TIME_PATTERN).timestamp()
        
        time_diff = last_404_time - first_404_time
        
        # Catch instant automation spikes (where time_diff == 0)
        if time_diff <= 300:
            alert_msg = f'Block IP {ip}: Triggered {len(errors_404_timestamp)} "Not Found" errors [Vulnerability Scanner]'
            print(alert_msg)
            write_log(alert_msg)


def detect_brute_force(ip, hits):
    """Checks if an IP is hammering target endpoints with POST requests."""
    # ADJUSTED: Added 'filter' and 'settings' to match your target parameters
    SUSPICIOUS_KEYWORDS = ['login', 'signin', 'updatevariation', 'settings', 'filter']
    
    login_attempts = sum(
        1 for hit in hits 
        if hit['method'] == 'POST' and any(kw in hit['url'].lower() for kw in SUSPICIOUS_KEYWORDS)
    )
    
    if login_attempts > MAX_LOGIN_THRESHOLD:
        alert_msg = f'Block IP [{ip}]: Sent {login_attempts} automated state-changing POST requests [Credential/Parameter Brute-Force]'
        print(alert_msg)
        write_log(alert_msg)


def detect_rate_limit_and_dos(ip, hits):
    """Tracks absolute request speed to catch rapid flooding/DoS attacks."""
    if len(hits) >= 2:
        first_hit = datetime.strptime(hits[0]['timestamps'], TIME_PATTERN).timestamp()
        last_hit = datetime.strptime(hits[-1]['timestamps'], TIME_PATTERN).timestamp()
        
        total_duration = last_hit - first_hit
        
        # If hits happen in the exact same second, drop duration to 1 to avoid a 0-division crash
        if total_duration == 0:
            total_duration = 1.0
            
        requests_per_second = len(hits) / total_duration
        
        # ADJUSTED: Lowered constraints slightly so small local mock files trigger live alerts easily
        if len(hits) > 10 and requests_per_second > 2.0:
            alert_msg = f'Block IP [{ip}]: Flooding detected! Sent {len(hits)} requests at {requests_per_second:.2f} req/sec [Application DoS / Rate Limit Violation]'
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