# Threat Hunts

Structured hunt playbooks. Each hunt starts as a hypothesis and gets promoted to `completed/` once executed and documented.

## Hunt workflow
1. Write a hypothesis using `templates/hunt_template.md`
2. Execute the hunt in the lab or SIEM
3. Document findings and move to `completed/`
4. If a detection gap is confirmed, write a rule in `detections/`
