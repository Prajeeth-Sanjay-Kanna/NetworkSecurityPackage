# DNS Tunneling Detection System

A beginner-friendly Network Security project that analyzes DNS query records and flags patterns that may be associated with DNS tunneling. It uses transparent, rule-based detection and displays results in a local Flask dashboard.

## Features

- Dashboard statistics based on the current analysis
- Sample DNS dataset for a repeatable demo
- CSV and PCAP/PCAPNG upload
- Rule-based checks for query length, long labels, entropy, encoded-looking labels, subdomain depth, repeated domains, and unique subdomains
- Risk score from 0 to 100 with Low, Medium, and High severity
- Search, severity filtering, and sorting
- CSV and JSON report exports
- Unit tests for the detection engine

A flagged query is a suspicious indicator, not proof of malicious activity. The simple frequency rules operate on the uploaded dataset as a whole rather than a continuous time-window model.

## Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS
- Internet access for installing packages

## Windows setup

Open PowerShell in the project folder:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser.

If PowerShell blocks virtual-environment activation, run the commands from Command Prompt instead:

```bat
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

## Linux setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Demo workflow

1. Start the app.
2. Select **Analyze sample dataset**.
3. Review the dashboard cards and recent alerts.
4. Open **All results** to search, filter, and sort the analysis.
5. Open an individual row to inspect its triggered rules.
6. Export the report as CSV or JSON.

The sample dataset is synthetic and intended only for demonstration.

## CSV format

The minimum required column is `domain`. Optional columns include `timestamp`, `source_ip`, `destination_ip`, and `record_type`.

Example:

```csv
timestamp,source_ip,destination_ip,domain,record_type
2026-10-26T09:00:00Z,192.0.2.10,192.0.2.53,www.example.com,A
2026-10-26T09:00:01Z,192.0.2.10,192.0.2.53,shop.example.net,A
```

The parser also accepts `query`, `queried_domain`, or `qname` instead of `domain`, and common aliases such as `src_ip`, `dst_ip`, and `qtype`.

## Run tests

```bash
python -m unittest discover -s tests
```

## PCAP support

PCAP analysis uses Scapy. Upload only packet captures you are authorized to inspect. The web app itself binds to localhost and does not start live packet capture. PCAP uploads are parsed as data and are not executed.

## Detection method

The detector checks query length, longest label length, entropy of subdomain labels, subdomain depth, encoded-looking patterns, total requests for a registered domain in the uploaded dataset, and unique subdomain count. Rule weights are added and capped at 100.

Severity defaults:
- Low: 0–29
- Medium: 30–59
- High: 60–100

These thresholds are educational defaults, not an industry standard. Adjust them to fit the dataset and evaluate false positives.

## Limitations

- DNS tunneling detection is heuristic; legitimate domains can look unusual.
- Query frequency and unique-subdomain checks summarize the uploaded dataset and do not currently apply sliding time windows.
- Registered-domain extraction handles common multi-label suffixes using a small local list, not the complete Public Suffix List.
- Encrypted DNS traffic may not expose query names in a packet capture.
- Live capture is not included in this version.

## Security notes

The application limits uploads to 12 MB, uses safe upload names, validates supported extensions, and binds to localhost. Do not expose the development server to an untrusted network. Set `DNS_DETECTOR_SECRET` to a unique random value if adapting the project beyond a local demo.
