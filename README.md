# Python Security Log Analyzer

**Author:** Obedience Jay

**Project Type:** Beginner Cybersecurity / Python

**Status:** Initial version — automated tests included
## Overview
Python Security Log Analyzer is a defensive cybersecurity learning project that analyzes login event logs, counts failed and successful login attempts, identifies potentially risky activity, and generates a readable security report.
The project was built with Python's standard library and is designed for educational use.
## Features
Reads login events from a text log file.
Counts failed and successful logins for each user.
Classifies users by failed-login count.
Flags users with three or more failed login events.
Skips malformed log entries and counts them.
Handles missing or unreadable log files gracefully.
Generates a text-based security report.
Includes automated tests using Python's unittest framework.
## Project Structure
python_security_log_analyzer/
├── security_analyzer.py
├── sample_security.log
├── README.md
├── .gitignore
├── reports/
│   └── security_report.txt
└── tests/
    └── test_security_analyzer.py
Generated reports and Python cache files are excluded from Git by default.
## Requirements
Python 3.10 or newer
No third-party packages required
## How to Run
Clone or download the project, then enter its directory.
Run the analyzer:
python security_analyzer.py
The program reads sample_security.log, displays the analysis, and saves the report to:
reports/security_report.txt
## Run the Tests
From the project root, execute:
python -m unittest discover -s tests -v
The tests cover risk classification, login-event counting, malformed log entries, missing files, and report generation.
## Risk Classification
Failed login events
Classification
0–1
LOW RISK
2
MEDIUM RISK
3 or more
HIGH RISK
## Important Limitations
This is an educational project, not a production security monitoring system.
Failed logins are counted across the entire input file; successful logins do not reset the failure count.
The program does not currently enforce a time window for detecting repeated attempts.
The timestamp field is checked for non-empty content but is not validated as a real date and time.
The sample log contains synthetic events, not real user authentication data.
A high-risk alert indicates activity worth investigating; it does not prove an account has been compromised.
## Future Improvements
Add timestamp validation and time-window detection.
Support command-line arguments for input and report paths.
Add more edge-case and integration tests.
Support structured JSON or CSV security logs.
Improve report formatting and summary statistics.
## Learning Purpose
This project demonstrates introductory Python skills, file handling, dictionaries, functions, exception handling, report generation, and automated testing in a defensive cybersecurity context.
## License
This project is available for educational use. A formal open-source license can be added when the repository is published.
