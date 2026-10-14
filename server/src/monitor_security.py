from collections import Counter
import sys

FAILED_LOGIN_THRESHOLD = 5
DOCUMENT_DENIED_THRESHOLD = 3

def check_failed_logins(log_lines):
    failed_ips = []

    for line in log_lines:
        if "event=login_failed" in line and "ip=" in line:
            ip = line.split("ip=", 1)[1].split()[0]
            failed_ips.append(ip)

    counts = Counter(failed_ips)

    for ip, count in counts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            print(f"[ALERT] Possible brute-force attack from {ip}: {count} failed logins")

def check_denied_document_access(log_lines):
    denied_users = []

    for line in log_lines:
        if "event=document_access_denied" in line and "user_id=" in line:
            user_id = line.split("user_id=", 1)[1].split()[0]
            denied_users.append(user_id)

    counts = Counter(denied_users)

    for user_id, count in counts.items():
        if count >= DOCUMENT_DENIED_THRESHOLD:
            print(
                f"[ALERT] Possible document probing by user {user_id}: "
                f"{count} denied document requests"
            )

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 monitor_security.py <logfile>")
        sys.exit(1)

    log_file = sys.argv[1]

    with open(log_file, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    check_failed_logins(log_lines)
    check_denied_document_access(log_lines)
