# Hope Bridge Foundation — SOC Triage Playbook

## 1. Overview

This playbook defines a consistent process for reviewing, prioritizing, and escalating security alerts for Hope Bridge Foundation. The goal is to identify potentially harmful activity, reduce unnecessary alerts, document analyst decisions, and escalate serious incidents to a senior security analyst.

This playbook is intended for initial alert triage. Alert-to-MITRE ATT&CK mappings are preliminary, keyword-based associations and must not be treated as proof that an attack occurred.

## 2. Triage Flow

Follow these steps for every alert:

1. **Receive:** Record the alert timestamp, alert type, source identifier, destination identifier, and available severity information.
2. **Validate:** Check that the alert contains usable information. Review the alert description, relevant logs, affected system, and whether similar alerts occurred nearby in time.
3. **Enrich:** Consult available asset inventory, user context, network records, and the `mapping.csv` ATT&CK association where relevant.
4. **Classify:** Assign Low, Medium, or High priority using the criteria below. Increase priority when evidence indicates greater impact or urgency.
5. **Respond or escalate:** Follow the severity-specific guidance. Do not perform disruptive containment actions without authorization.
6. **Document and close:** Record evidence reviewed, classification, actions taken, escalation details, outcome, and closure reason.

### Quick Decision Flow

- Alert received → validate available evidence.
- If the alert is invalid or unsupported, document why and close it according to the organization's process.
- If suspicious activity is present, classify severity.
- Low → document and monitor.
- Medium → investigate promptly and notify the responsible analyst or senior analyst as needed.
- High → promptly escalate to the senior analyst and follow the incident-response process.
- Record the decision and outcome for every alert.

## 3. Severity Levels and Handling

### High

**Definition:** Credible evidence of potentially serious compromise, active exploitation, malware, unauthorized privileged access, or significant risk to sensitive systems or data.

**Required actions:**
- Prioritize immediate review.
- Notify the senior security analyst promptly using the approved contact channel.
- Preserve relevant logs and evidence.
- Identify potentially affected systems, accounts, and data.
- Follow the authorized incident-response and containment procedures.
- Record the timeline, decisions, notifications, and actions taken.

### Medium

**Definition:** Suspicious activity that needs further investigation but does not yet have confirmed evidence of a severe or ongoing compromise.

**Required actions:**
- Investigate promptly during the current working period.
- Review related alerts, source and destination identifiers, and available logs.
- Determine whether the activity is expected, repeated, or associated with other indicators.
- Escalate if the evidence becomes more serious, the scope increases, or uncertainty creates significant risk.
- Document findings and the next action.

### Low

**Definition:** An alert with limited evidence of harmful activity, low apparent impact, or an event that may be expected or benign.

**Required actions:**
- Validate the alert and check for obvious false positives.
- Record the reason for the low-priority classification.
- Close it according to the organization's process or continue monitoring if appropriate.
- Reassess the severity if new evidence appears.

**Important:** Severity assigned by `clean_alerts.py` is keyword-based and severity assigned during triage must consider evidence and business impact. Do not treat the two as interchangeable.

## 4. Escalation Paths

### Escalate to the Senior Security Analyst when:
- A High-severity alert is received.
- Evidence suggests account compromise, malware, exploitation, or unauthorized access.
- Multiple related alerts suggest a broader incident.
- Sensitive information or important services may be affected.
- The analyst cannot confidently determine whether activity is safe.
- An incident exceeds the analyst's authorization or technical capability.

### Contact and Communication

- **First contact:** Designated senior security analyst or SOC team lead.
- **Backup contact:** IT administrator or designated incident-response contact, following the organization's approved process.
- **Communication method:** Approved organizational email, ticketing system, or incident-response channel.
- **Contact details:** Use the current internal contact list. Specific names, phone numbers, and email addresses must be confirmed by the foundation; do not invent contact details.

For a High-severity incident, notify the senior analyst promptly and follow the foundation's incident-response procedures. If the primary contact is unavailable, use the documented backup path.

## 5. Evidence and Documentation

For each alert, record:

- Alert ID or reference, if available.
- Timestamp and alert type.
- Source and destination identifiers.
- Initial severity and final triage classification.
- Relevant logs, observations, and ATT&CK mapping, if applicable.
- Actions taken and their authorization.
- Person or team notified and time of escalation.
- Investigation outcome, follow-up owner, and closure reason.

Preserve evidence according to the foundation's data-handling and retention policies. Do not include passwords, secrets, or unnecessary personal information in notes.

## 6. Closure Criteria

An alert may be closed when the available evidence has been reviewed, the decision is documented, required escalation has occurred, and no further action remains assigned to the triaging analyst. If investigation is incomplete, keep the alert open or transfer it to the responsible owner.

## 7. Review and Limitations

This playbook is a starter procedure for a small SOC. Response times, named contacts, legal reporting requirements, and containment authority must be approved by Hope Bridge Foundation. Review the playbook periodically and update it when systems, risks, or internal procedures change.
