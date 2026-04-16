import re
from collections import defaultdict

log_file = "auth.log"
alert_file = "alerts.txt"

# Threshold for brute-force detection
THRESHOLD = 4

def detect_bruteforce():
    failed_attempts = defaultdict(int)
    successful_logins = []
    alerts = []

    with open(log_file, "r") as file:
        for line in file:

            # Detect failed attempts
            if "Failed password" in line:
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    failed_attempts[ip] += 1

                    if failed_attempts[ip] == THRESHOLD:
                        alerts.append(f"[ALERT] SSH Brute-force suspected from IP: {ip}")

            # Detect successful login
            if "Accepted password" in line:
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                user_match = re.search(r'for (\w+)', line)

                if ip_match and user_match:
                    ip = ip_match.group(1)
                    user = user_match.group(1)

                    successful_logins.append((user, ip))
                    alerts.append(f"[INFO] Successful login: User={user}, IP={ip}")

    return alerts


def save_alerts(alerts):
    with open(alert_file, "w") as file:
        for alert in alerts:
            file.write(alert + "\n")


if __name__ == "__main__":
    alerts = detect_bruteforce()
    save_alerts(alerts)

    print("Detection complete. Alerts:")
    for alert in alerts:
        print(alert)