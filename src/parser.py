import re
from collections import defaultdict

LOG_PATTERN = re.compile(r'(\d+\.\d+\.\d+\.\d+).*?\s\[(.+?)\]\s"([A-Z]+)\s(.+?)\s.*?"\s(\d{3})\s(\d+)')

def parse_access_logs(file_path):
    """Reads raw server logs and groups them into an IP history database."""
    ip_database = defaultdict(list)
    print('\n        Processing Server Logs')
    
    with open(file_path, 'r', errors='ignore', encoding='utf-8') as f:
        for line in f:
            match = LOG_PATTERN.search(line)
            if match:
                ip = match.group(1)
                size_raw = match.group(6)
                size = 0 if size_raw == '-' else int(size_raw)
                
                hit_details = {
                    'timestamps': match.group(2),
                    'method': match.group(3),
                    'url': match.group(4),
                    'status_code': match.group(5),
                    'size': size
                }
                ip_database[ip].append(hit_details)
                
    return ip_database