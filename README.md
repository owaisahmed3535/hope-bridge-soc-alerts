
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



## Task 3: SOC Triage Playbook

The `playbook.md` file provides a documented SOC alert triage process for Hope Bridge Foundation.

It covers:
- Alert validation and investigation steps.
- Severity definitions and handling for Low, Medium, and High alerts.
- Escalation criteria and communication paths to a senior security analyst.
- Evidence documentation, closure criteria, and playbook limitations.

The playbook uses a practical, evidence-based triage approach. Alert severity and preliminary MITRE ATT&CK mappings should be validated during investigation. Contact names and response time requirements must be confirmed by the foundation.

### View the Playbook

See [`playbook.md`](playbook.md) for the complete triage procedure.





## Task 4: Weekly SOC Report Template

This task provides a reusable weekly SOC reporting template for Hope Bridge Foundation.

### Files

- `report_template.md` — reusable template with clearly marked placeholders for weekly report data.
- `sample_report.md` — illustrative example of a completed weekly SOC report.

### How to Fill the Template

1. Open `report_template.md` and copy it into a new file for the reporting week.
2. Replace all bracketed placeholders, such as `[START_DATE]`, `[TOTAL_ALERTS]`, and `[ANALYST_NAME]`, with verified information.
3. Complete the Summary with total alerts, severity counts, confirmed incidents, and escalations.
4. Populate Top Alerts with significant events, timestamps, severity, source IPs, statuses, and actions taken.
5. Complete Trends using current and previous reporting-period data. If comparison data is unavailable, state that clearly.
6. Add Recommendations with priority, reason, suggested owner, and target date.
7. Verify counts and findings against `alerts_clean.csv` and available investigation records before sharing the report.

### Reporting Notes

`sample_report.md` contains illustrative example data only. Its figures and events are not verified live incidents. Replace them with validated findings before using a report operationally.

MITRE ATT&CK associations in `mapping.csv` are preliminary keyword-based mappings and do not independently confirm that an attack occurred.

### View the Reports

- [Weekly SOC Report Template](report_template.md)
- [Sample Weekly SOC Report](sample_report.md)
