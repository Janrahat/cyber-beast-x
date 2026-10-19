# CYBER BEAST X

A colorful Python toolkit for basic security checks and public-information lookups. Designed to run on **Termux** and **Kali Linux**.

## Features

- Public IP information lookup (approximate region/ISP where available)
- Phone-number formatting and numbering-plan validation
- DNS resolution
- Basic HTTP response/header check for websites you own or are authorized to test
- Local system information
- JSON report saving

> This is a starter toolkit, not a full penetration-testing suite. It does not identify phone subscribers, reveal exact private locations, exploit Android devices, or break into accounts. Use website and network checks only with authorization.

## Termux installation

```bash
pkg update
pkg install python nano -y
pip install -r requirements.txt
python cyber_beast.py
```

## Kali Linux installation

```bash
sudo apt update
sudo apt install python3 python3-venv git -y
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python cyber_beast.py
```

## Reports

The tool writes results to `cyber_beast_reports.json` in the current directory. Review the file before sharing it, as reports can contain information about systems you checked.

## Disclaimer

Only use this tool on systems you own or have explicit permission to assess. Results are informational and are not a substitute for a professional security audit.
