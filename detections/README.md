# Detections

Custom detection rules written and tuned in the home lab.

## Folders
- `sigma/` — Platform-agnostic Sigma rules, organized by ATT&CK tactic
- `suricata/` — Network-based Suricata IDS rules
- `yara/` — YARA rules for file/memory-based detection

## Naming convention
`[tactic]_[technique_id]_[description].yml`
Example: `lateral_movement_T1021_rdp_brute_force.yml`
