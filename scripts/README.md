# Scripts

Python tools built for SOC workflows. Each script is self-contained and documented.

## Setup
```bash
pip install -r requirements.txt
```

## Folders
- `log_parsers/` — Parse Zeek, Suricata, Syslog, and Windows Event logs
- `ioc_tools/` — Extract and enrich IOCs from text, logs, and reports
- `api_integrations/` — VirusTotal, Splunk, MISP API wrappers
- `utilities/` — General helpers (timestamp conversion, IP enrichment, etc.)
