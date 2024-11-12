# Subdomain Takeover Vulnerability Scanner

This tool is designed to help security professionals and bug bounty hunters identify potential subdomain takeover vulnerabilities. It checks subdomains for misconfigurations that could lead to takeover attacks, specifically by matching CNAME records against known vulnerable services.

## Features
- Scans subdomains for potential takeover vulnerabilities.
- Utilizes a list of service error signatures to detect misconfigurations.
- Provides real-time feedback on subdomain status (vulnerable, not vulnerable, or unreachable).

## Requirements
- Python 3.x
- `requests` library
- `dnspython` library

Install the required libraries using pip:
```bash
pip install -r requirements.txt
```
## Usage
```bash
python overwatch.py --help
