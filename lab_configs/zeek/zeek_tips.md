# Zeek Tips & Field Reference

## Key log files
| Log | Description |
|---|---|
| `conn.log` | All network connections (src/dst IP, port, bytes, duration) |
| `dns.log` | DNS queries and responses |
| `http.log` | HTTP requests (method, URI, user-agent, response code) |
| `ssl.log` | SSL/TLS connections (JA3 fingerprints, cert info) |
| `files.log` | File transfers observed on the wire |
| `weird.log` | Protocol anomalies flagged by Zeek |

## Useful zeek-cut one-liners

### Top talkers by bytes out
```bash
cat conn.log | zeek-cut id.orig_h orig_bytes | sort -t$'\t' -k2 -rn | head 20
```

### All unique DNS queries
```bash
cat dns.log | zeek-cut query | sort -u
```

### HTTP requests with suspicious user agents
```bash
cat http.log | zeek-cut id.orig_h host uri user_agent | grep -iE "(curl|wget|python|go-http|nmap)"
```

## PCAP replay
```bash
# Replay a PCAP through Zeek for offline analysis
zeek -C -r capture.pcap local
```
