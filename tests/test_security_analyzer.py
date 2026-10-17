import tempfile
import unittest
from pathlib import Path

from security_analyzer import analyze_log, get_risk_level, generate_report


class TestSecurityAnalyzer(unittest.TestCase):

    def test_high_risk_threshold(self):
        self.assertEqual(get_risk_level(3), "HIGH RISK")
        self.assertEqual(get_risk_level(5), "HIGH RISK")

    def test_medium_risk_threshold(self):
        self.assertEqual(get_risk_level(2), "MEDIUM RISK")

    def test_low_risk_threshold(self):
        self.assertEqual(get_risk_level(0), "LOW RISK")
        self.assertEqual(get_risk_level(1), "LOW RISK")

    def test_count_login_events(self):
        log_content = (
            "2026-10-16 08:00:00 | Alice | LOGIN_FAILED\n"
            "2026-10-16 08:01:00 | Alice | LOGIN_FAILED\n"
            "2026-10-16 08:02:00 | Bob | LOGIN_SUCCESS\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test.log"
            log_path.write_text(log_content, encoding="utf-8")

            users, total_events, malformed_lines = analyze_log(log_path)

        self.assertEqual(users["Alice"]["failed"], 2)
        self.assertEqual(users["Alice"]["successful"], 0)
        self.assertEqual(users["Bob"]["successful"], 1)
        self.assertEqual(total_events, 3)
        self.assertEqual(malformed_lines, 0)

    def test_malformed_line_is_skipped(self):
        log_content = (
            "2026-10-16 08:00:00 | Alice | LOGIN_FAILED\n"
            "This is not a valid log entry\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test.log"
            log_path.write_text(log_content, encoding="utf-8")

            users, total_events, malformed_lines = analyze_log(log_path)

        self.assertEqual(total_events, 1)
        self.assertEqual(malformed_lines, 1)
        self.assertEqual(users["Alice"]["failed"], 1)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "missing.log"
            result = analyze_log(missing_path)

        self.assertIsNone(result)

    def test_report_contains_high_risk_alert(self):
        users = {
            "Alice": {"failed": 3, "successful": 0},
            "Bob": {"failed": 1, "successful": 1},
        }

        report = generate_report(users, 5, 0)

        self.assertIn("ALERT: Alice has 3 failed logins!", report)
        self.assertIn("Total users: 2", report)
        self.assertIn("HIGH RISK", report)


if __name__ == "__main__":
    unittest.main()
