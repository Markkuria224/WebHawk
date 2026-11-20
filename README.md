# WebHawk

**A modular desktop web application security assessment platform.**

- **Version:** 0.1.0
- **Author:** Mark Kuria
- **Language:** Python
- **Interface:** PySide6

## Overview

WebHawk is a desktop security assessment tool designed to help users
inspect web application security configurations and identify common
security weaknesses.

The platform uses modular analyzers, structured findings and
evidence-based reporting.

## Planned Features

- HTTP reconnaissance and inspection
- HTTP security-header analysis
- Cookie security assessment
- CORS configuration analysis
- TLS configuration inspection
- Severity-based security findings
- Evidence and remediation guidance
- JSON and PDF report generation
- Desktop graphical interface

## Technology Stack

- Python 3.12+
- PySide6
- HTTPX
- Pydantic
- SQLite
- Pytest

## Security and Authorization

WebHawk is intended for localhost environments, authorized testing
laboratories and systems for which the operator has explicit permission.

The initial release will prioritize passive security assessment.
Aggressive scanning, brute-force attacks and destructive testing are
outside the initial scope.

## Development Status

Currently under development.

## License

MIT License.
