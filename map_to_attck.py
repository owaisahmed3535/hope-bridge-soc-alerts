
import json
import re
import pandas as pd

INPUT_FILE = "alerts_clean.csv"
ATTACK_FILE = "enterprise-attack.json"
OUTPUT_FILE = "mapping.csv"

TACTIC_KEYWORDS = {
    "exploit": ["T1190", "Exploit Public-Facing Application"],
    "command execution": ["T1059", "Command and Scripting Interpreter"],
    "malware": ["T1204", "User Execution"],
    "backdoor": ["T1505.003", "Web Shell"],
    "scan": ["T1046", "Network Service Discovery"],
    "flood": ["T1498", "Network Denial of Service"],
    "injection": ["T1190", "Exploit Public-Facing Application"],
    "xss": ["T1189", "Drive-by Compromise"],
    "snmp": ["T1016", "System Network Configuration Discovery"],
    "ssh": ["T1021.004", "SSH"],
    "web": ["T1071.001", "Web Protocols"],
    "dns": ["T1071.004", "DNS"],
    "ftp": ["T1071.002", "File Transfer Protocols"],
    "phishing": ["T1566", "Phishing"],
    "brute force": ["T1110", "Brute Force"],
    "password": ["T1110", "Brute Force"],
    "unauthorized": ["T1078", "Valid Accounts"],
    "suspicious": ["T1036", "Masquerading"],
}

DEFAULT_TECHNIQUE = [
    "T1046",
    "Network Service Discovery",
]


def load_attack_techniques(filename):
    """Extract active ATT&CK Enterprise techniques from official STIX JSON."""
    with open(filename, "r", encoding="utf-8") as file:
        data = json.load(file)

    techniques = {}

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        platforms = obj.get("x_mitre_domains", [])
        if "enterprise-attack" not in platforms:
            continue

        external_ids = [
            ref.get("external_id")
            for ref in obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
            and ref.get("external_id")
        ]

        if not external_ids:
            continue

        technique_id = external_ids[0]
        technique_name = obj.get("name", "Unknown")

        techniques[technique_id] = technique_name

    return techniques


def choose_technique(alert_type, techniques):
    """Choose a keyword-based ATT&CK technique that exists in the source JSON."""
    text = str(alert_type).lower()

    for keyword, candidate in TACTIC_KEYWORDS.items():
        if keyword in text:
            technique_id, fallback_name = candidate
            if technique_id in techniques:
                return technique_id, techniques[technique_id]

    default_id, default_name = DEFAULT_TECHNIQUE
    if default_id in techniques:
        return default_id, techniques[default_id]

    raise ValueError("Default technique ID was not found in ATT&CK JSON.")


def main():
    alerts = pd.read_csv(INPUT_FILE)

    if "alert_type" not in alerts.columns:
        raise ValueError("alerts_clean.csv must contain an alert_type column.")

    techniques = load_attack_techniques(ATTACK_FILE)
    if not techniques:
        raise ValueError("No active Enterprise ATT&CK techniques were found.")

    rows = []
    for alert_type in alerts["alert_type"].dropna().unique():
        technique_id, technique_name = choose_technique(
            alert_type, techniques
        )
        rows.append({
            "alert_type": alert_type,
            "technique_id": technique_id,
            "technique_name": technique_name,
        })

    result = pd.DataFrame(
        rows,
        columns=["alert_type", "technique_id", "technique_name"],
    )
    result.to_csv(OUTPUT_FILE, index=False)

    print(f"Loaded {len(techniques)} ATT&CK techniques.")
    print(f"Mapped {len(result)} unique alert types to {OUTPUT_FILE}.")
    print("Distinct techniques used:", result["technique_id"].nunique())
    print("Output columns:", ", ".join(result.columns))


if __name__ == "__main__":
    main()

