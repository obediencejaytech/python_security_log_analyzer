from collections import defaultdict
from pathlib import Path

LOG_FILE = Path("sample_security.log")
REPORT_FILE = Path("reports/security_report.txt")

FAILED_LOGIN_THRESHOLD = 3


def analyze_log(file_path):
    users = defaultdict(
        lambda: {
            "failed": 0,
            "successful": 0,
        }
    )

    malformed_lines = 0
    total_events = 0

    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            for line in log_file:
                line = line.strip()

                if not line:
                    continue

                parts = line.split("|")

                if len(parts) != 3:
                    malformed_lines += 1
                    continue

                timestamp, username, event = [
                    part.strip() for part in parts
                ]

                if not timestamp or not username:
                    malformed_lines += 1
                    continue

                if event not in ("LOGIN_FAILED", "LOGIN_SUCCESS"):
                    malformed_lines += 1
                    continue

                total_events += 1

                if event == "LOGIN_FAILED":
                    users[username]["failed"] += 1
                else:
                    users[username]["successful"] += 1

    except FileNotFoundError:
        print(f"ERROR: Log file not found: {file_path}")
        return None

    except OSError as error:
        print(f"ERROR: Could not read log file: {error}")
        return None

    return users, total_events, malformed_lines


def get_risk_level(failed_logins):
    if failed_logins >= FAILED_LOGIN_THRESHOLD:
        return "HIGH RISK"

    if failed_logins == 2:
        return "MEDIUM RISK"

    return "LOW RISK"


def generate_report(users, total_events, malformed_lines):
    report_lines = [
        "=== PYTHON SECURITY LOG ANALYZER ===",
        "",
        "=== USER SECURITY SUMMARY ===",
    ]

    high_risk_users = []

    for username in sorted(users):
        failed = users[username]["failed"]
        successful = users[username]["successful"]
        risk = get_risk_level(failed)

        report_lines.append(
            f"{username}: {failed} failed, "
            f"{successful} successful - {risk}"
        )

        if failed >= FAILED_LOGIN_THRESHOLD:
            high_risk_users.append(username)

    report_lines.extend([
        "",
        "=== HIGH-RISK ALERTS ===",
    ])

    if high_risk_users:
        for username in high_risk_users:
            failed = users[username]["failed"]
            report_lines.append(
                f"ALERT: {username} has {failed} failed logins!"
            )
    else:
        report_lines.append("No high-risk users detected.")

    low_risk_count = sum(
        get_risk_level(data["failed"]) == "LOW RISK"
        for data in users.values()
    )

    medium_risk_count = sum(
        get_risk_level(data["failed"]) == "MEDIUM RISK"
        for data in users.values()
    )

    high_risk_count = sum(
        get_risk_level(data["failed"]) == "HIGH RISK"
        for data in users.values()
    )

    report_lines.extend([
        "",
        "=== RISK SUMMARY ===",
        f"Low-risk users: {low_risk_count}",
        f"Medium-risk users: {medium_risk_count}",
        f"High-risk users: {high_risk_count}",
        f"Total users: {len(users)}",
        f"Total valid events: {total_events}",
        f"Malformed lines skipped: {malformed_lines}",
        "",
        "=== ANALYSIS COMPLETE ===",
    ])

    return "\n".join(report_lines)


def main():
    result = analyze_log(LOG_FILE)

    if result is None:
        return

    users, total_events, malformed_lines = result

    report = generate_report(
        users,
        total_events,
        malformed_lines,
    )

    print(report)

    try:
        REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
        REPORT_FILE.write_text(report + "\n", encoding="utf-8")
        print(f"\nReport saved to: {REPORT_FILE}")

    except OSError as error:
        print(f"\nERROR: Could not save report: {error}")


if __name__ == "__main__":
    main()
