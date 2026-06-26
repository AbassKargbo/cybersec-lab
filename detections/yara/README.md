# YARA Rules

File and memory-based detection rules. Useful for malware triage and threat hunting.

## Resources
- https://yara.readthedocs.io/
- https://github.com/Yara-Rules/rules
- https://bazaar.abuse.ch/

## Template
```yara
rule Template_Rule
{
    meta:
        description = ""
        author = "Abass"
        date = ""
        reference = ""
        mitre = ""
    strings:
        $s1 = ""
    condition:
        any of them
}
```
