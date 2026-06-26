# Hunt: [Name]

**Date:** YYYY-MM-DD
**Analyst:** Abass
**Status:** `In Progress` / `Completed` / `No Findings`

---

## Hypothesis
> What do you suspect is happening and why?

## MITRE ATT&CK Mapping
- **Tactic:**
- **Technique:**
- **Sub-technique:**

## Data Sources
- [ ] Zeek logs (conn.log, dns.log, http.log)
- [ ] Suricata alerts
- [ ] Windows Event Logs
- [ ] Sysmon
- [ ] Splunk

## Hunt Queries

### Splunk SPL
```spl
index=* sourcetype=zeek_dns
| stats count by query
| where len(query) > 50
| sort -count
```

### Zeek / CLI
```bash
cat dns.log | zeek-cut query | awk 'length > 50' | sort | uniq -c | sort -rn
```

## Findings
*Document what you found — screenshots, log snippets, IPs.*

## Outcome
- [ ] True positive — created detection rule: [link to rule]
- [ ] False positive — documented why
- [ ] Inconclusive — need more data

## References
-
