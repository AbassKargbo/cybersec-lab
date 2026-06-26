# T1059 — Command and Scripting Interpreter

**Tactic:** Execution
**Last updated:** 2024-01-01

---

## Summary
Adversaries abuse command-line interpreters (cmd, PowerShell, Bash, Python) to execute malicious commands or scripts. One of the most commonly observed execution techniques.

## Sub-techniques of note
| Sub-tech | Name | Common tools |
|---|---|---|
| T1059.001 | PowerShell | Empire, PowerSploit, PS Remoting |
| T1059.003 | Windows Command Shell | LOLBins (certutil, mshta, regsvr32) |
| T1059.006 | Python | Custom scripts, reverse shells |

## Detection ideas
- PowerShell script block logging (Event ID 4104)
- Command-line length anomalies
- Encoded/obfuscated strings (`-EncodedCommand`, `^c^m^d`)
- Parent-child process anomalies (e.g. Word spawning PowerShell)

## Splunk SPL
```spl
index=wineventlog EventCode=4688
| eval cmd_len=len(CommandLine)
| where cmd_len > 200 OR match(CommandLine, "-[Ee]nc")
| table _time, host, user, ParentProcessName, NewProcessName, CommandLine
| sort -_time
```

## References
- https://attack.mitre.org/techniques/T1059/
- https://lolbas-project.github.io/
