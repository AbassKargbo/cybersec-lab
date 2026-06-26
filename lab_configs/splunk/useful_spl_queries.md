# Useful SPL Queries

A growing reference of SPL queries built and tested in the home lab.

---

## Authentication & Account Activity

### Failed logon attempts
```spl
index=wineventlog EventCode=4625
| stats count by src_ip, user, host
| where count > 5
| sort -count
```

### Brute force success (failures followed by successful login)
```spl
index=wineventlog EventCode IN (4625, 4624)
| stats count(eval(EventCode=4625)) AS failures,
        count(eval(EventCode=4624)) AS successes BY user, src_ip
| where failures > 5 AND successes > 0
```

## Process Execution

### Suspicious parent-child process relationships
```spl
index=wineventlog EventCode=4688
| where ParentProcessName IN ("winword.exe","excel.exe","outlook.exe")
  AND NewProcessName IN ("powershell.exe","cmd.exe","wscript.exe","cscript.exe")
| table _time, host, user, ParentProcessName, NewProcessName, CommandLine
```

## Network

### Zeek — high connection count per destination
```spl
index=zeek sourcetype=zeek_conn
| stats count BY id_orig_h, id_resp_h, id_resp_p
| where count > 50
| sort -count
```

### DNS — long query strings (possible tunneling)
```spl
index=zeek sourcetype=zeek_dns
| eval qlen=len(query)
| where qlen > 50
| stats count avg(qlen) max(qlen) BY id_orig_h, query
| sort -count
```
