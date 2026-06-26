# Hunt: DNS Tunneling via Long Subdomain Queries

**Date:** 2024-01-15
**Analyst:** Abass
**Status:** `Completed — True Positive (simulated)`

---

## Hypothesis
An adversary may be using DNS as a covert channel by encoding data in unusually long subdomain labels, detectable via Zeek dns.log query length analysis.

## MITRE ATT&CK Mapping
- **Tactic:** Command and Control / Exfiltration
- **Technique:** T1071 — Application Layer Protocol
- **Sub-technique:** T1071.004 — DNS

## Data Sources
- [x] Zeek `dns.log`
- [x] Suricata alert logs

## Hunt Queries

### Zeek CLI
```bash
cat dns.log | zeek-cut ts id.orig_h id.resp_h query qtype_name \
  | awk -F'\t' 'length($5) > 50 {print}' \
  | sort -t$'\t' -k2,2 | head 30
```

### Splunk SPL
```spl
index=zeek sourcetype=zeek_dns
| eval query_len=len(query)
| where query_len > 50
| stats count avg(query_len) max(query_len) by id_orig_h, id_resp_h
| sort -count
```

## Findings
Simulated using `iodine` DNS tunnel tool in home lab. Queries consistently exceeded 60 chars. Suricata alert fired correctly with sid:9000001.

## Outcome
- [x] True positive (simulated) — created Suricata rule: `detections/suricata/dns/dns_tunneling_long_query.rules`

## References
- https://attack.mitre.org/techniques/T1071/004/
- https://github.com/yarrick/iodine
