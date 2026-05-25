from constants import ACCESS_LOGS
from parser import parse_access_logs
from logger import write_log
from detector import (
    detect_vulnerability_scanners,
    detect_brute_force,
    detect_data_exfiltration
)

def main():
    # 1. Ingest logs using the parser module
    ip_history_db = parse_access_logs(ACCESS_LOGS)
    
    print('------Analyzing IP behaviour------')
    print('------Starting malicious Scan------')
    
    # 2. Feed the results to the detector modules
    for ip, hits in ip_history_db.items():
        detect_vulnerability_scanners(ip, hits)
        detect_brute_force(ip, hits)
        detect_data_exfiltration(ip, hits)
        
    # 3. Execution Sign-off
    write_log('Log analysis completed successfully.')
    print('Analysis complete.')

if __name__ == "__main__":
    main()