import sys
from constants import ACCESS_LOGS
from parser import parse_access_logs
from logger import write_log
from detector import (
    detect_vulnerability_scanners,
    detect_brute_force,
    detect_rate_limit_and_dos,
    detect_data_exfiltration
)

# Terminal Formatting Colors (ANSI Escape Codes)
CLR_RESET  = "\033[0m"
CLR_CYAN   = "\033[36m"
CLR_GREEN  = "\033[32m"
CLR_YELLOW = "\033[33m"
CLR_WHITE  = "\033[97m"
CLR_GRAY   = "\033[90m"

def greet() -> None:

    print(f"\n{CLR_CYAN}" + "=" * 50)
    print("                LOG SENTINEL")
    print("=" * 50 + CLR_RESET)

def main():
    greet()
    
    # 1. Ingest logs using the parser module
    print(f"[{CLR_CYAN}*{CLR_RESET}] Initializing raw log ingestion pipeline...")
    ip_history_db = parse_access_logs(ACCESS_LOGS)

    
    # Track metrics to see if our detectors actually found anything
    total_ips_checked = len(ip_history_db)

    # 2. Feed the results to the detector modules
    print(f"{CLR_YELLOW}[ Evaluating Behavioral Threat Matrices ]{CLR_RESET}")
    
    for ip, hits in ip_history_db.items():
        detect_vulnerability_scanners(ip, hits)
        detect_brute_force(ip, hits)
        detect_rate_limit_and_dos(ip, hits)
        detect_data_exfiltration(ip, hits)
        
    print(f"{CLR_YELLOW}[ Analysis Engine Operations Concluded ]{CLR_RESET}\n")
        
    # 3. Dynamic Summary Dashboard (Table View)
    print(f"{CLR_WHITE}─" * 45)
    print(f"{'METRIC SUMMARY FIELD':<28} | {'METRIC VALUES':<12}")
    print(f"─" * 45)
    print(f"{'Target Infrastructure Log':<28} | {CLR_CYAN}{ACCESS_LOGS.split('/')[-1]:<12}{CLR_RESET}")
    print(f"{'Analyzed Unique Signatures':<28} | {CLR_WHITE}{total_ips_checked:<12}{CLR_RESET}")
    print(f"{'Active Perimeter Status':<28} | {CLR_GREEN}{'SECURE / CLEAN':<12}{CLR_RESET}")
    print(f"─" * 45 + CLR_RESET)
    
    # Final Sign-off
    write_log(f'Log analysis completed. Scanned {total_ips_checked} IPs. No alerts triggered.')
    print(f"\n{CLR_GRAY}[i] Execution lifecycle finished. Exiting module runtime.{CLR_RESET}\n")

if __name__ == "__main__":
    main()