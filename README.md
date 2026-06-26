# cybersec-lab

A living SOC analyst lab notebook — detection rules, Python tooling, threat hunts, CTF write-ups, and threat intelligence notes. Built to grow with daily practice.

## Structure

| Folder | Purpose |
|---|---|
| `detections/` | Sigma, Suricata, and YARA rules |
| `scripts/` | Python tools for log parsing, IOC extraction, API integrations |
| `threat_hunts/` | Hunt hypotheses and completed playbooks |
| `ctf_writeups/` | Challenge solutions with MITRE ATT&CK mappings |
| `intel_notes/` | TTP breakdowns, threat actor profiles, MITRE notes |
| `lab_configs/` | Tool configs for Security Onion, Splunk, Zeek, Suricata |
| `pcap_analysis/` | PCAP-based investigation notes |

## Tools in use
- **SIEM:** Splunk Enterprise (home lab)
- **NSM:** Security Onion · Zeek · Suricata
- **Scripting:** Python 3
- **Detection formats:** Sigma · Suricata rules · YARA

## Contribution habit
Every commit is a rep. Aim for at least one meaningful change per day:
- A new or tuned detection rule
- A Python function added to a script
- A hunt hypothesis documented
- A CTF challenge solved and written up
- A TTP or threat actor note updated
