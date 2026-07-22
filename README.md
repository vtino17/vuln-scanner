# Vuln Scanner

Modular vulnerability scanner for network devices and services. Correlates discovered services against known CVEs, generates reports in multiple formats, and supports scheduled scanning with notification integration.

## Features

- Service discovery and fingerprinting
- CVE correlation via NVD database
- Modular plugin architecture for custom checks
- Reports in JSON, HTML, CSV, and SARIF formats
- Scheduled scanning with configurable intervals
- Email, Slack, and webhook notifications
- CIDR-based target specification
- Rate limiting and concurrency control
- Exit code integration for CI/CD pipelines

## Installation

```bash
pip install vuln-scanner
```

Or from source:

```bash
git clone https://github.com/vtino17/vuln-scanner.git
cd vuln-scanner
pip install -e .
```

## Quick Start

```bash
# Scan a single host
vuln-scan scan 192.168.1.1

# Scan a CIDR range with HTML report
vuln-scan scan 10.0.0.0/24 --output report.html --format html

# Scan with full vulnerability correlation
vuln-scan scan target.example.com --cve --severity high

# Scheduled daily scan
vuln-scan schedule 10.0.0.0/24 --interval daily --notify slack

# List available plugins
vuln-scan plugins --list
```

## Architecture

```
vuln-scan
  core/             Engine, target parser, scheduler
  plugins/          CVE check modules
  reporters/        Output format handlers
  notifiers/        Alert integrations
```

## Plugin Development

```python
from vuln_scanner.core.plugin import BasePlugin

class CustomCheck(BasePlugin):
    name = "custom-ssl-check"
    description = "Checks SSL certificate expiration"

    def run(self, target):
        result = self.check_cert(target.host, target.port)
        return {"cert_expiry_days": result}
```

## Supported Output Formats

- JSON (machine-readable)
- HTML (browser-ready report)
- CSV (spreadsheet import)
- SARIF (GitHub Advanced Security compatible)

## Notifications

- SMTP email
- Slack webhook
- Generic webhook (custom integrations)

## Testing

```bash
pytest tests/ --cov=vuln_scanner
```

## License

MIT
