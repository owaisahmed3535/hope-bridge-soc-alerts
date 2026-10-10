
## Task 1: Collect and Prepare Sample SOC Alerts

### Dataset Source

This project uses the public NIDS Alert Group Dataset:

https://github.com/ristov/nids-alert-data

The downloaded source file is `dataset-labeled-anon-ip.csv.bz2`. The dataset contains anonymized external and internal host identifiers.

### Output

The cleaning script generates `alerts_clean.csv` with 100 unique alert types and these columns:

- `timestamp`
- `src_ip`
- `dst_ip`
- `alert_type`
- `severity`

### Cleaning and Severity Method

The script selects the required fields, removes rows with missing required values, removes duplicate records, and keeps one record per alert type.

Severity is assigned using a keyword-based triage heuristic:
- `high`: alert names containing keywords such as `exploit`, `command execution`, or `malware`.
- `medium`: alert names containing keywords such as `flood`, `scan`, or `xss`.
- `low`: alert names that do not match the defined high or medium keywords.

These severity values are heuristic triage priorities, not official severity labels supplied by the dataset.

### Run Instructions

**Download the Source Dataset**

Download the original dataset before running the cleaning script:

```bash
wget -O dataset-labeled-anon-ip.csv.bz2 https://raw.githubusercontent.com/ristov/nids-alert-data/main/dataset-labeled-anon-ip.csv.bz2
```

The downloaded dataset is used as input by `clean_alerts.py` and is not included in this repository.

Install Pandas if needed:

```bash
python3 -m pip install pandas
```

Run the cleaning script from the repository directory:

```bash
python3 clean_alerts.py
```

Verify the CSV:

```bash
python3 -c "import pandas as pd; df = pd.read_csv('alerts_clean.csv'); print('Rows:', len(df)); print(df.columns.tolist())"
```
