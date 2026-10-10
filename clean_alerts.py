
import pandas as pd

INPUT_FILE = "dataset-labeled-anon-ip.csv.bz2"
OUTPUT_FILE = "alerts_clean.csv"

REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "alert_type",
    "severity",
]


def assign_severity(alert_type):
    """Assign a documented keyword-based triage priority."""
    text = str(alert_type).lower()

    high_keywords = [
        "exploit",
        "command execution",
        "rce",
        "unauthorized",
        "malware",
        "backdoor",
    ]

    medium_keywords = [
        "flood",
        "scan",
        "xss",
        "injection",
        "suspicious",
        "amplification",
    ]

    if any(keyword in text for keyword in high_keywords):
        return "high"

    if any(keyword in text for keyword in medium_keywords):
        return "medium"

    return "low"


def main():
    df = pd.read_csv(
        INPUT_FILE,
        compression="bz2",
        usecols=["Timestamp", "ExtIP", "IntIP", "SignatureText"],
    )

    df = df.rename(
        columns={
            "Timestamp": "timestamp",
            "ExtIP": "src_ip",
            "IntIP": "dst_ip",
            "SignatureText": "alert_type",
        }
    )

    # Remove rows with missing required data and duplicate alerts.
    df = df.dropna(subset=["timestamp", "src_ip", "dst_ip", "alert_type"])
    df = df.drop_duplicates()

    # Assign heuristic triage severity; this is not the dataset's Label.
    df["severity"] = df["alert_type"].apply(assign_severity)

    # Keep a manageable sample with a variety of alert types.
    df = df.drop_duplicates(subset=["alert_type"], keep="first")
    df = df[REQUIRED_COLUMNS].head(100)

    if len(df) < 20:
        raise ValueError("Dataset produced fewer than 20 unique alerts.")

    df.to_csv(OUTPUT_FILE, index=False)

    print(f"Created {OUTPUT_FILE} with {len(df)} alerts.")
    print("Columns:", ", ".join(df.columns))


if __name__ == "__main__":
    main()
