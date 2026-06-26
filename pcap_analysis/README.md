# PCAP Analysis

Notes and findings from PCAP-based investigations.

## Sources
- [Malware-Traffic-Analysis.net](https://malware-traffic-analysis.net/)
- Home lab captures (tcpdump / Security Onion)
- CTF challenges

## Workflow
1. Drop PCAP in `samples/` (gitignored — don't commit actual malicious PCAPs)
2. Replay through Zeek: `zeek -C -r sample.pcap local`
3. Document findings in `notes/[filename].md`

## Tools
- Wireshark
- Zeek (offline PCAP replay)
- `tshark` for CLI filtering
- NetworkMiner for artifact extraction
