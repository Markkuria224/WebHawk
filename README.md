# WebHawk

**A desktop web application security assessment platform built with Python and PySide6.**

WebHawk is a modular security assessment application designed to inspect HTTP responses from explicitly authorized web targets. It combines a desktop interface, controlled HTTP transport, authorization profiles, and evidence-backed analysis to help identify common web security configuration weaknesses.

> **Development status:** Early development — version 0.1.0. Features and interfaces may change.

## Features

### Implemented

- **HTTP assessment pipeline** — performs controlled, single-target HTTP assessments.
- **Authorization profiles** — define approved hostnames, IP networks, and optional loopback access.
- **Authorization preview** — validate a target against its configured authorization scope before assessment.
- **HSTS analysis** — inspect HTTP Strict Transport Security configuration.
- **Cookie security analysis** — inspect response cookies for security-related attributes.
- **CORS analysis** — evaluate observed Cross-Origin Resource Sharing response configuration.
- **Structured findings** — produce severity-rated findings with classifications, confidence levels, and supporting evidence.
- **Hardened HTTP transport** — enforce TLS verification, disable redirects and environment proxy inheritance, and apply request timeouts and response-size limits.
- **Desktop interface** — provides a dashboard, assessment workspace, and authorized-target management.

### Planned

- Dedicated findings and evidence workspaces.
- Application settings interface.
- Exportable assessment reports.
- Additional security analysis modules.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.12+ | Application language |
| PySide6 | Desktop graphical interface |
| HTTPX | Asynchronous HTTP communication |
| Pydantic | Configuration and data validation |
| Pytest | Automated testing |
| trustme | Local TLS testing |

## Architecture

WebHawk separates assessment execution, authorization, transport, analysis, and presentation into distinct components.

```text
WebHawk
│
├── Desktop GUI
│   ├── Dashboard
│   ├── Assessment
│   └── Authorized Targets
│
├── Core
│   ├── URL Normalization
│   ├── Authorization
│   ├── Authorization Storage
│   ├── Assessment Pipeline
│   ├── HTTP Configuration
│   └── HTTP Transport
│
├── Analyzers
│   ├── HSTS
│   ├── Cookies
│   └── CORS
│
└── Structured Results
    ├── Findings
    ├── Evidence
    ├── Severity
    └── Assessment Status
```

Authorization profiles are stored locally in a versioned JSON file. Assessment results are represented using structured application models.

## Security and Safety

WebHawk is designed around explicit authorization and controlled assessment.

The current implementation includes:

- Explicit target authorization through configured profiles.
- Hostname and network scope validation.
- DNS resolution and address safety checks.
- TLS certificate verification.
- Disabled HTTP redirects.
- Disabled environment proxy inheritance.
- Configurable connection, read, write, and pool timeouts.
- Bounded HTTP response consumption.
- Sanitization of stored response URLs.
- Redaction of sensitive response-header values in stored metadata.
- Controlled error reporting that avoids exposing internal exception messages.

The default maximum response size is **2 MB**, configurable up to 10 MB.

The assessment pipeline currently uses a single HTTP `GET` request. Response bodies are streamed and discarded rather than retained for analysis.

### Intended Use

Use WebHawk only against:

- Localhost environments explicitly included in an authorization profile.
- Authorized testing laboratories.
- Web applications and infrastructure for which you have explicit permission to conduct security assessments.

WebHawk is not intended for unauthorized scanning, brute-force attacks, exploitation, destructive testing, or denial-of-service activity.

## Installation

### Requirements

- Windows (primary development and tested platform).
- Python 3.12 or later.
- Git.

Linux and macOS compatibility has not yet been verified.

### Clone the repository

```powershell
git clone https://github.com/Markkuria224/WebHawk.git
cd WebHawk
```



### Create a virtual environment

```powershell
py -3 -m venv .venv
```

### Activate it on Windows

```powershell
.\.venv\Scripts\Activate.ps1
```

### Install the application and development dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### Run WebHawk

```powershell
webhawk
```

## Testing

Run the automated test suite:

```powershell
python -m pytest
```

The project includes unit and integration tests covering authorization, URL normalization, HTTP transport, response analysis, GUI workflows, and local TLS behavior.

## Project Structure

```text
WebHawk/
├── src/
│   └── webhawk/
│       ├── analyzers/
│       ├── core/
│       │   └── transport/
│       ├── gui/
│       │   └── pages/
│       └── main.py
├── tests/
│   └── integration/
├── lab/
├── pyproject.toml
├── README.md
└── .gitignore
```

## Development Status

WebHawk is an actively developed project. Its assessment engine, authorization controls, HTTP transport, initial analysis modules, and core desktop workflows are implemented.

The dedicated Findings, Evidence, and Settings workspaces remain under development.

Additional reporting and security analysis capabilities are also planned.

## License

MIT
