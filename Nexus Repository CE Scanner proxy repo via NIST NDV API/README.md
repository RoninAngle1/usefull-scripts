# File Malware and NIST NVD CVE Scanner

A non-destructive Bash security scanner that analyzes files for malware and known CVE references.

The script combines:

* ClamAV malware scanning
* NIST National Vulnerability Database API lookups
* CVE extraction from filenames
* CVE extraction from readable file content
* SHA-256 checksum generation
* MIME type detection
* Optional filename-based vulnerability searches
* CSV, JSON, and text report generation

The scanner does not delete, move, rename, quarantine, or modify scanned files.

---

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [How It Works](#how-it-works)
* [Limitations](#limitations)
* [Requirements](#requirements)
* [Installation](#installation)
* [Script Configuration](#script-configuration)
* [NVD API Key](#nvd-api-key)
* [Usage](#usage)
* [Examples](#examples)
* [Reports](#reports)
* [Exit Codes](#exit-codes)
* [Troubleshooting](#troubleshooting)
* [Security Considerations](#security-considerations)
* [Automation](#automation)
* [Project Structure](#project-structure)
* [License](#license)

---

## Overview

The script scans regular files in a selected directory and creates security reports containing:

* File name and path
* File size
* MIME type
* SHA-256 checksum
* Malware scan result
* Detected malware signature
* Embedded CVE identifiers
* NIST NVD vulnerability information
* CVSS score
* CVSS severity
* CVSS vector
* Weakness information
* Publication and modification dates
* Reference links

The script is designed for local file inspection, security reviews, downloaded artifact analysis, package inspection, and repository security checks.

---

## Features

### Malware Detection

Files are scanned using ClamAV.

Possible malware scan results include:

| Result          | Description                               |
| --------------- | ----------------------------------------- |
| `CLEAN`         | No known malware was detected             |
| `INFECTED`      | ClamAV detected a known malware signature |
| `ERROR`         | ClamAV could not complete the scan        |
| `NOT_AVAILABLE` | ClamAV is not installed                   |

The script does not automatically remove or quarantine infected files.

---

### CVE Extraction

The script searches for CVE identifiers matching the following format:

```text
CVE-YYYY-NNNN
```

Examples:

```text
CVE-2024-3094
CVE-2025-12345
CVE-2026-9876
```

CVE identifiers are searched in:

* Filenames
* Readable file contents
* Strings extracted from binary files

---

### NIST NVD Integration

Discovered CVE identifiers are queried against the NIST National Vulnerability Database.

Information retrieved may include:

* CVE ID
* Vulnerability status
* Description
* Published date
* Last modified date
* CVSS version
* CVSS score
* Severity
* CVSS vector
* CWE weakness identifiers
* External references

---

### Filename Keyword Lookup

The script can optionally search the NVD using a sanitized filename.

For example:

```text
openssl-3.0.12.tar.gz
```

may be converted into a search keyword similar to:

```text
openssl 3 0 12
```

Enable this feature with:

```bash
NVD_KEYWORD_LOOKUP=1
```

Filename keyword results are only possible vulnerability candidates.

A matching CVE does not prove that the scanned file is vulnerable.

---

### Non-Destructive Operation

The scanner never intentionally:

* Deletes files
* Moves files
* Renames files
* Modifies file contents
* Quarantines files
* Changes permissions
* Replaces files

Temporary files created by the script are removed when the scan finishes.

---

### Report Formats

The script creates three report types:

* Plain-text report
* CSV report
* JSON report

NVD API responses are also cached locally.

---

## How It Works

The scanning workflow is:

```text
Start
  |
  v
Validate dependencies
  |
  v
Initialize report files
  |
  v
Find regular files
  |
  v
Calculate SHA-256 checksum
  |
  v
Detect MIME type
  |
  v
Scan with ClamAV
  |
  v
Search for embedded CVE identifiers
  |
  v
Query NIST NVD
  |
  v
Optional filename keyword search
  |
  v
Write TXT, CSV, and JSON reports
  |
  v
Display scan summary
```

---

## Limitations

### NIST Does Not Scan Files for Malware

The NIST NVD API is a vulnerability database.

It does not upload, inspect, or scan arbitrary local files.

Malware scanning is performed locally by ClamAV.

---

### CVE References Do Not Prove Vulnerability

A file containing a CVE identifier may only be documentation, source code, a changelog, or a security report.

The presence of a CVE ID does not prove that the file is vulnerable.

---

### Filename Searches Can Produce False Positives

Filename keyword searches are approximate.

For reliable vulnerability matching, you normally need accurate information such as:

* Vendor
* Product
* Version
* Package ecosystem
* CPE identifier
* Package URL
* Software bill of materials

---

### ClamAV Uses Signature-Based Detection

ClamAV primarily detects known threats using malware signatures.

A clean result does not guarantee that the file is safe.

Unknown, encrypted, obfuscated, or newly created malware may not be detected.

---

### Current Directory Scope

By default, the script scans only regular files directly inside the selected directory.

It does not recursively scan subdirectories because it uses:

```bash
find "$SCAN_DIRECTORY" -maxdepth 1 -type f
```

---

## Requirements

### Supported Operating Systems

The script is intended for Unix-like operating systems, including:

* Ubuntu
* Debian
* Red Hat Enterprise Linux
* Rocky Linux
* AlmaLinux
* Fedora
* CentOS Stream
* Other Bash-compatible Linux distributions

---

### Required Commands

The following commands are required:

| Command  | Purpose                           |
| -------- | --------------------------------- |
| `bash`   | Executes the script               |
| `curl`   | Queries the NIST NVD API          |
| `jq`     | Parses and generates JSON         |
| `grep`   | Extracts CVE identifiers          |
| `find`   | Locates files                     |
| `date`   | Generates timestamps              |
| `sed`    | Sanitizes values                  |
| `sort`   | Removes duplicate CVE identifiers |
| `tr`     | Converts and filters text         |
| `mktemp` | Creates temporary directories     |

---

### Recommended Commands

| Command     | Purpose                                     |
| ----------- | ------------------------------------------- |
| `clamscan`  | Scans files for malware                     |
| `freshclam` | Updates ClamAV signatures                   |
| `file`      | Detects MIME types                          |
| `sha256sum` | Generates SHA-256 checksums                 |
| `strings`   | Extracts readable strings from binary files |
| `stat`      | Retrieves file size                         |
| `realpath`  | Resolves absolute paths                     |

---

## Installation

## Ubuntu and Debian

Install the required packages:

```bash
sudo apt update

sudo apt install -y \
  bash \
  curl \
  jq \
  grep \
  findutils \
  coreutils \
  sed \
  file \
  binutils \
  clamav \
  clamav-freshclam
```

Update the ClamAV signature database:

```bash
sudo freshclam
```

On systems where the ClamAV updater service is running, you may need to stop it temporarily:

```bash
sudo systemctl stop clamav-freshclam 2>/dev/null || true
sudo freshclam
sudo systemctl start clamav-freshclam 2>/dev/null || true
```

---

## RHEL, Rocky Linux, and AlmaLinux

Enable the EPEL repository if necessary:

```bash
sudo dnf install -y epel-release
```

Install the dependencies:

```bash
sudo dnf install -y \
  bash \
  curl \
  jq \
  grep \
  findutils \
  coreutils \
  sed \
  file \
  binutils \
  clamav \
  clamav-update
```

Update the ClamAV database:

```bash
sudo freshclam
```

Package names may differ depending on the operating system version and enabled repositories.

---

## Verify Dependencies

Check the required commands:

```bash
command -v bash
command -v curl
command -v jq
command -v grep
command -v find
command -v clamscan
command -v freshclam
command -v file
command -v sha256sum
command -v strings
```

Check the ClamAV version:

```bash
clamscan --version
```

Check the signature database:

```bash
freshclam --version
```

---

## Script Installation

Save the script as:

```text
scan-files-security.sh
```

Make it executable:

```bash
chmod +x scan-files-security.sh
```

Optionally install it globally:

```bash
sudo install -m 0755 \
  scan-files-security.sh \
  /usr/local/bin/scan-files-security
```

Run the globally installed command with:

```bash
scan-files-security
```

---

## Script Configuration

The script is configured using environment variables.

### Configuration Variables

| Variable                       |                   Default | Description                                       |
| ------------------------------ | ------------------------: | ------------------------------------------------- |
| `SCAN_DIRECTORY`               |                       `.` | Directory containing files to scan                |
| `REPORT_DIRECTORY`             | `./security-scan-reports` | Directory used for generated reports              |
| `NVD_API_KEY`                  |                     Empty | Optional NIST NVD API key                         |
| `NVD_KEYWORD_LOOKUP`           |                       `0` | Enables filename-based NVD searches               |
| `NVD_KEYWORD_LIMIT`            |                      `10` | Maximum filename keyword CVE results              |
| `CONTENT_SCAN_BYTES`           |                `10485760` | Maximum readable content inspected per file       |
| `MAX_CONTENT_INSPECTION_BYTES` |               `104857600` | Maximum file size eligible for content inspection |
| `NVD_REQUEST_DELAY`            |                `6` or `1` | Delay between NVD API requests                    |

---

### `SCAN_DIRECTORY`

Directory containing the files to scan.

Default:

```bash
SCAN_DIRECTORY=.
```

Example:

```bash
SCAN_DIRECTORY=/opt/packages
```

The script scans only regular files directly inside this directory.

---

### `REPORT_DIRECTORY`

Directory used for reports and cached NVD responses.

Default:

```bash
REPORT_DIRECTORY=./security-scan-reports
```

Example:

```bash
REPORT_DIRECTORY=/var/log/security-file-scanner
```

The executing user must have permission to create and write files in this directory.

---

### `NVD_API_KEY`

Optional NIST NVD API key.

Default:

```bash
NVD_API_KEY=
```

Example:

```bash
export NVD_API_KEY='your-api-key'
```

An API key generally allows a higher request rate than unauthenticated requests.

Do not store the API key directly inside the script.

---

### `NVD_KEYWORD_LOOKUP`

Controls filename-based vulnerability searching.

Disabled:

```bash
NVD_KEYWORD_LOOKUP=0
```

Enabled:

```bash
NVD_KEYWORD_LOOKUP=1
```

This feature may significantly increase the number of NVD API requests.

---

### `NVD_KEYWORD_LIMIT`

Maximum number of CVE results processed from each filename keyword search.

Default:

```bash
NVD_KEYWORD_LIMIT=10
```

Example:

```bash
NVD_KEYWORD_LIMIT=5
```

---

### `CONTENT_SCAN_BYTES`

Maximum number of bytes examined when searching file contents for embedded CVE identifiers.

Default:

```bash
CONTENT_SCAN_BYTES=10485760
```

This equals approximately 10 MiB.

Example for 20 MiB:

```bash
CONTENT_SCAN_BYTES=20971520
```

This limit does not restrict the ClamAV malware scan.

---

### `MAX_CONTENT_INSPECTION_BYTES`

Files larger than this value are not inspected for embedded CVE strings.

Default:

```bash
MAX_CONTENT_INSPECTION_BYTES=104857600
```

This equals approximately 100 MiB.

Large files may still be scanned by ClamAV.

---

### `NVD_REQUEST_DELAY`

Delay in seconds between NVD API calls.

Default without an API key:

```bash
NVD_REQUEST_DELAY=6
```

Default with an API key:

```bash
NVD_REQUEST_DELAY=1
```

Increase the delay if NVD returns HTTP `429` rate-limit responses:

```bash
NVD_REQUEST_DELAY=10
```

---

## NVD API Key

An NVD API key is optional but recommended for frequent or large scans.

Set it for the current shell:

```bash
export NVD_API_KEY='your-nvd-api-key'
```

Run the scanner:

```bash
./scan-files-security.sh
```

Remove it from the current shell afterward:

```bash
unset NVD_API_KEY
```

You can also pass it for one command only:

```bash
NVD_API_KEY='your-nvd-api-key' \
./scan-files-security.sh
```

Avoid placing the key in:

* Git repositories
* Shared shell history
* Public documentation
* World-readable environment files
* CI/CD logs

---

## Usage

### Basic Usage

Scan files in the current directory:

```bash
./scan-files-security.sh
```

---

### Scan Another Directory

```bash
SCAN_DIRECTORY=/path/to/files \
./scan-files-security.sh
```

Example:

```bash
SCAN_DIRECTORY=/opt/downloads \
./scan-files-security.sh
```

---

### Use a Custom Report Directory

```bash
REPORT_DIRECTORY=/var/log/file-security-scan \
./scan-files-security.sh
```

---

### Enable Filename Keyword Searches

```bash
NVD_KEYWORD_LOOKUP=1 \
./scan-files-security.sh
```

---

### Use an NVD API Key

```bash
NVD_API_KEY='your-api-key' \
./scan-files-security.sh
```

---

### Full Example

```bash
SCAN_DIRECTORY=/opt/packages \
REPORT_DIRECTORY=/var/log/package-security \
NVD_API_KEY='your-api-key' \
NVD_KEYWORD_LOOKUP=1 \
NVD_KEYWORD_LIMIT=5 \
CONTENT_SCAN_BYTES=20971520 \
MAX_CONTENT_INSPECTION_BYTES=209715200 \
NVD_REQUEST_DELAY=2 \
./scan-files-security.sh
```

---

## Examples

### Scan Downloaded Packages

```bash
SCAN_DIRECTORY=/srv/downloads \
REPORT_DIRECTORY=/srv/security-reports \
./scan-files-security.sh
```

---

### Scan Application Artifacts

```bash
SCAN_DIRECTORY=/opt/application/artifacts \
NVD_KEYWORD_LOOKUP=1 \
./scan-files-security.sh
```

---

### Scan a Single File

The script scans all regular files in the selected directory.

To scan only one file, place it in a temporary directory:

```bash
mkdir -p /tmp/single-file-scan

cp -- /path/to/application.jar /tmp/single-file-scan/

SCAN_DIRECTORY=/tmp/single-file-scan \
./scan-files-security.sh
```

The original file remains unchanged.

---

### Scan Without Filename Keyword Lookup

```bash
NVD_KEYWORD_LOOKUP=0 \
./scan-files-security.sh
```

Only CVE identifiers explicitly found in filenames or file contents are queried.

---

### Use a Longer API Delay

```bash
NVD_REQUEST_DELAY=10 \
./scan-files-security.sh
```

This is useful when NVD rate limiting occurs.

---

## Example Console Output

```text
[2026-07-27 09:10:00] Starting non-destructive security scan.
[2026-07-27 09:10:00] No files will be deleted, moved or modified.
[2026-07-27 09:10:00] Scanning file: ./application.jar
[2026-07-27 09:10:04] Querying NIST NVD for CVE-2024-12345
[2026-07-27 09:10:10] Scanning file: ./library.so
[2026-07-27 09:10:13] No embedded CVE identifiers found in: ./library.so

==================================================================
Scan summary
Completed: 2026-07-27T09:10:20+04:00
Files scanned: 2
Malware detections: 0
Unique CVE records queried: 1
CVE references found: 1
Filename keyword matches: 0
NVD request errors: 0
Files deleted: 0
Files modified: 0

Reports:
  Text: ./security-scan-reports/security-scan-20260727-091000.txt
  CSV:  ./security-scan-reports/security-scan-20260727-091000.csv
  JSON: ./security-scan-reports/security-scan-20260727-091000.json
```

---

## Reports

Reports are created under:

```text
security-scan-reports/
```

Example:

```text
security-scan-reports/
├── security-scan-20260727-091000.txt
├── security-scan-20260727-091000.csv
├── security-scan-20260727-091000.json
└── nvd-cache/
    ├── CVE-2024-12345.json
    └── CVE-2025-9876.json
```

---

### Text Report

The text report is intended for human review.

Example:

```text
File: ./application.jar
Size: 18234567 bytes
Type: application/java-archive
SHA-256: 11962a5e...
Malware status: CLEAN
Malware details: No malware detected
------------------------------------------------------------------

CVE: CVE-2024-12345
Source file: ./application.jar
Detection method: embedded-cve-reference
Status: Analyzed
Published: 2024-03-01T10:00:00.000
Last modified: 2025-01-15T12:00:00.000
CVSS version: CVSS 3.1
CVSS score: 8.8
Severity: HIGH
Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
Weakness: CWE-78
Description: Example vulnerability description.
References: https://example.org/advisory
```

---

### CSV Report

The CSV report can be opened in spreadsheet applications or imported into analysis systems.

Columns:

| Column             | Description                |
| ------------------ | -------------------------- |
| `file`             | Scanned file path          |
| `record_type`      | `MALWARE` or `CVE`         |
| `identifier`       | SHA-256 checksum or CVE ID |
| `severity`         | NVD severity               |
| `score`            | CVSS score                 |
| `status`           | Malware or CVE status      |
| `detection_method` | Detection source           |
| `description`      | Result details             |

Example:

```csv
"file","record_type","identifier","severity","score","status","detection_method","description"
"./application.jar","MALWARE","11962a5e...","","","CLEAN","ClamAV","No malware detected"
"./application.jar","CVE","CVE-2024-12345","HIGH","8.8","Analyzed","embedded-cve-reference","Example vulnerability description"
```

---

### JSON Report

The JSON report contains the basic file scan information.

Example:

```json
[
  {
    "file": "./application.jar",
    "filename": "application.jar",
    "sizeBytes": 18234567,
    "mimeType": "application/java-archive",
    "sha256": "11962a5e...",
    "malware": {
      "scanner": "ClamAV",
      "status": "CLEAN",
      "details": "No malware detected"
    }
  }
]
```

Detailed NVD responses are stored separately in the cache directory.

---

### NVD Cache

The NVD cache avoids repeatedly downloading the same CVE record.

Example:

```text
security-scan-reports/nvd-cache/CVE-2024-12345.json
```

To force the script to retrieve current data again, remove the required cache file:

```bash
rm -f \
  security-scan-reports/nvd-cache/CVE-2024-12345.json
```

To clear the entire cache:

```bash
rm -rf security-scan-reports/nvd-cache
```

This removes only cached API responses, not scanned files.

---

## Exit Codes

|      Exit Code | Meaning                                                              |
| -------------: | -------------------------------------------------------------------- |
|            `0` | Scan completed without malware detection or NVD request errors       |
|            `2` | One or more malware detections occurred                              |
|            `3` | One or more NVD API requests failed                                  |
| Other non-zero | Dependency, configuration, filesystem, or unexpected execution error |

Example:

```bash
./scan-files-security.sh
exit_code=$?

case "$exit_code" in
  0)
    echo "Security scan completed successfully."
    ;;

  2)
    echo "Malware was detected."
    ;;

  3)
    echo "The scan completed with NVD API errors."
    ;;

  *)
    echo "The scanner failed with exit code: $exit_code"
    ;;
esac
```

---

## Troubleshooting

### `curl: command not found`

Install curl:

```bash
sudo apt install -y curl
```

Or on RHEL-compatible systems:

```bash
sudo dnf install -y curl
```

---

### `jq: command not found`

Install jq:

```bash
sudo apt install -y jq
```

Or:

```bash
sudo dnf install -y jq
```

---

### ClamAV Is Not Installed

The report may show:

```text
Malware status: NOT_AVAILABLE
```

Install ClamAV:

```bash
sudo apt install -y clamav clamav-freshclam
```

Then update the database:

```bash
sudo freshclam
```

---

### ClamAV Database Is Outdated

Update signatures:

```bash
sudo freshclam
```

Check the ClamAV version:

```bash
clamscan --version
```

---

### `freshclam` Lock Error

Example:

```text
ERROR: Failed to lock the log file
```

Stop the updater service temporarily:

```bash
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
```

---

### NVD Returns HTTP 403

Possible causes:

* Invalid API key
* Disabled API key
* Incorrect `apiKey` header
* Excessive request rate
* Network security device blocking the request

Test without an API key:

```bash
unset NVD_API_KEY
NVD_REQUEST_DELAY=10 ./scan-files-security.sh
```

---

### NVD Returns HTTP 429

HTTP `429` means the request rate is too high.

Increase the delay:

```bash
NVD_REQUEST_DELAY=15 \
./scan-files-security.sh
```

For large scans, use an NVD API key.

---

### NVD Requests Time Out

Test connectivity:

```bash
curl -I \
  https://services.nvd.nist.gov/rest/json/cves/2.0
```

Check DNS:

```bash
getent hosts services.nvd.nist.gov
```

Check TLS:

```bash
curl -v \
  https://services.nvd.nist.gov/rest/json/cves/2.0
```

---

### No CVEs Are Found

This may be expected.

The script only discovers CVEs that:

* Appear in the filename
* Appear in readable content
* Appear in extracted binary strings
* Match an optional filename keyword search

The script does not perform package dependency resolution or SBOM analysis.

---

### Hidden Files Are Not Scanned

The script uses `find`, so hidden regular files are included.

Examples:

```text
.env
.hidden-config
.application-data
```

They are scanned if they are directly inside `SCAN_DIRECTORY`.

---

### Subdirectories Are Not Scanned

The default command includes:

```bash
-maxdepth 1
```

To scan recursively, change:

```bash
find "$SCAN_DIRECTORY" \
  -maxdepth 1 \
  -type f \
  -print0
```

to:

```bash
find "$SCAN_DIRECTORY" \
  -type f \
  -print0
```

Review report-directory exclusions before enabling recursive scanning.

---

### Permission Denied

Run the script as a user with read access to scanned files and write access to the report directory.

Check permissions:

```bash
ls -ld "$SCAN_DIRECTORY"
ls -l "$SCAN_DIRECTORY"
```

Avoid using `sudo` unless it is required.

---

### Report Directory Is Scanned

The script attempts to skip files inside its report directory.

For a clearer separation, place reports outside the scan directory:

```bash
SCAN_DIRECTORY=/opt/packages \
REPORT_DIRECTORY=/var/log/package-security \
./scan-files-security.sh
```

---

## Security Considerations

### Do Not Execute Suspicious Files

The script reads and scans files but does not execute them.

Do not manually run files that are flagged as suspicious.

---

### Scan in an Isolated Environment

For untrusted files, consider scanning inside:

* A disposable virtual machine
* A hardened analysis host
* A restricted container
* A malware analysis sandbox
* A network-isolated environment

---

### Protect Reports

Reports may contain:

* Full file paths
* Usernames
* Internal product names
* Package versions
* Vulnerability information
* External advisory links
* Security-sensitive metadata

Restrict report permissions:

```bash
chmod -R 700 security-scan-reports
```

---

### Protect the NVD API Key

Do not print the key in logs.

Avoid commands that expose the key through process listings or shared command history.

A protected environment file can be used:

```bash
sudo install -m 0600 /dev/null /etc/file-security-scanner.env
```

Example content:

```bash
NVD_API_KEY=replace-with-real-key
NVD_REQUEST_DELAY=2
NVD_KEYWORD_LOOKUP=0
```

Load it before execution:

```bash
set -a
source /etc/file-security-scanner.env
set +a

./scan-files-security.sh
```

---

### Verify Malware Findings

False positives are possible.

Before taking action:

1. Record the file checksum.
2. Review the ClamAV signature.
3. Compare results with another trusted scanning engine.
4. Confirm the file source.
5. Inspect digital signatures where available.
6. Review package provenance.
7. Follow your incident-response procedure.

---

## Automation

## Cron Example

Run every day at 02:00:

```cron
0 2 * * * SCAN_DIRECTORY=/opt/packages REPORT_DIRECTORY=/var/log/package-security /usr/local/bin/scan-files-security
```

Because cron uses a limited environment, use absolute paths when possible.

Example wrapper script:

```bash
#!/usr/bin/env bash

set -Eeuo pipefail

export SCAN_DIRECTORY="/opt/packages"
export REPORT_DIRECTORY="/var/log/package-security"
export NVD_KEYWORD_LOOKUP="0"
export NVD_REQUEST_DELAY="10"

exec /usr/local/bin/scan-files-security
```

---

## Systemd Service

Create:

```text
/etc/systemd/system/file-security-scan.service
```

Example:

```ini
[Unit]
Description=File Malware and NIST NVD CVE Scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=-/etc/file-security-scanner.env
Environment=SCAN_DIRECTORY=/opt/packages
Environment=REPORT_DIRECTORY=/var/log/package-security
ExecStart=/usr/local/bin/scan-files-security
User=securityscanner
Group=securityscanner
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/opt/packages
ReadWritePaths=/var/log/package-security

[Install]
WantedBy=multi-user.target
```

Reload systemd:

```bash
sudo systemctl daemon-reload
```

Run manually:

```bash
sudo systemctl start file-security-scan.service
```

Review the result:

```bash
sudo systemctl status file-security-scan.service
```

View logs:

```bash
sudo journalctl \
  -u file-security-scan.service \
  --no-pager
```

---

## Systemd Timer

Create:

```text
/etc/systemd/system/file-security-scan.timer
```

Example:

```ini
[Unit]
Description=Run File Security Scan Daily

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
```

Enable the timer:

```bash
sudo systemctl daemon-reload

sudo systemctl enable --now \
  file-security-scan.timer
```

Check the timer:

```bash
systemctl list-timers \
  file-security-scan.timer
```

---

## Project Structure

Recommended directory layout:

```text
file-security-scanner/
├── README.md
├── scan-files-security.sh
├── .gitignore
├── examples/
│   ├── file-security-scan.service
│   ├── file-security-scan.timer
│   └── file-security-scanner.env.example
└── security-scan-reports/
    ├── security-scan-YYYYMMDD-HHMMSS.txt
    ├── security-scan-YYYYMMDD-HHMMSS.csv
    ├── security-scan-YYYYMMDD-HHMMSS.json
    └── nvd-cache/
```

Recommended `.gitignore`:

```gitignore
security-scan-reports/
*.tmp
*.log
.env
```

---

## Recommended Environment Example

Create:

```text
file-security-scanner.env.example
```

Content:

```bash
# Directory containing files to scan
SCAN_DIRECTORY=/opt/packages

# Directory used for reports
REPORT_DIRECTORY=/var/log/package-security

# Optional NIST NVD API key
NVD_API_KEY=

# Enable filename keyword searches: 0 or 1
NVD_KEYWORD_LOOKUP=0

# Maximum CVEs processed per filename search
NVD_KEYWORD_LIMIT=10

# Maximum readable content inspected per file: 10 MiB
CONTENT_SCAN_BYTES=10485760

# Maximum file size eligible for content inspection: 100 MiB
MAX_CONTENT_INSPECTION_BYTES=104857600

# Delay between NVD API requests
NVD_REQUEST_DELAY=6
```

---

## Suggested Improvements

Possible future enhancements include:

* Recursive directory scanning
* Software Bill of Materials generation
* Package URL identification
* CPE matching
* OSV API integration
* CISA KEV catalog checks
* Vendor advisory integration
* YARA rule scanning
* Archive extraction and nested scanning
* Digital signature validation
* VirusTotal hash lookups
* HTML report generation
* Email notifications
* Webhook notifications
* Prometheus metrics
* Automatic report retention
* Parallel ClamAV scanning
* Configurable include and exclude patterns
* CI/CD pipeline integration

---

## Disclaimer

This script provides supporting security information and does not guarantee that a file is safe or vulnerable.

Results should be reviewed by qualified security personnel.

A clean malware scan does not guarantee that a file is harmless.

A CVE keyword match does not prove that the scanned software is affected.

Use the script as one component of a broader vulnerability-management and malware-analysis process.

---

## License

Internal Use

Modify and distribute according to your organization's security and software policies.
