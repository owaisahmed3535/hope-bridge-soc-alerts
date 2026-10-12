
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

## Task 2: Map Alerts to MITRE ATT&CK Techniques

### Data Source

This task uses the official MITRE ATT&CK Enterprise STIX dataset:

https://github.com/mitre-attack/attack-stix-data

The source JSON file is `enterprise-attack.json`. It is downloaded locally and is not included in this repository.

### Script and Output

- `map_to_attck.py` reads `alerts_clean.csv` and the official ATT&CK JSON dataset.
- `mapping.csv` contains `alert_type`, `technique_id`, and `technique_name`.
- The script extracts active Enterprise ATT&CK techniques and uses keyword-based rules to associate alert descriptions with techniques.
- Technique IDs are checked against the downloaded dataset, and official technique names are taken from the JSON.
- Alerts that do not match a defined keyword are assigned a default Network Service Discovery technique. These mappings are preliminary heuristic associations and should be validated by a SOC analyst; they do not prove that a technique occurred.

### Run Instructions

Download the source JSON:

```bash
wget -O enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

Install dependencies if needed:

```bash
python3 -m pip install pandas
```

Generate the mapping:

```bash
python3 map_to_attck.py
```

Verify the output:

```bash
python3 -c "import pandas as pd; df=pd.read_csv('mapping.csv'); print('Rows:',len(df)); print('Unique techniques:',df['technique_id'].nunique()); print(df.columns.tolist())"
```

### Validation Results

The generated mapping contains 100 unique alert types, all three required columns, zero missing values, and 13 distinct ATT&CK technique IDs.
