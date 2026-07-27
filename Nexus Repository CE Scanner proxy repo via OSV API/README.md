# Nexus Repository CE Security Scanner

A Bash-based security scanner for **Sonatype Nexus Repository OSS/Community Edition** that inventories cached artifacts from proxy repositories and identifies known vulnerabilities and malicious packages using the **Open Source Vulnerabilities (OSV)** database.

The scanner is completely **read-only**. It never modifies, deletes, quarantines, or blocks content inside Nexus.

---

## Features

- Discover all Nexus **proxy repositories**
- Scan only selected repository formats
- Scan repositories matching a regular expression
- Scan explicitly selected repositories
- Inventory every cached component
- Inventory every asset
- Collect SHA-1, SHA-256 and MD5 hashes
- Map Nexus components into OSV ecosystems
- Query the OSV Batch API
- Detect:
  - CVEs
  - GHSA advisories
  - MAL-* malicious packages
- Separate malware findings from ordinary vulnerabilities
- Automatic retries
- Exponential backoff
- Retry-After header support
- Temporary OSV disable after repeated HTTP 403 responses
- Produce detailed TSV, CSV and JSONL reports
- Never changes repository contents

---

# Architecture

```text
                    +------------------------+
                    |  Nexus Repository CE   |
                    +-----------+------------+
                                |
                                |
                REST API (/repositories)
                                |
                                v
                +-----------------------------+
                | Discover Proxy Repositories |
                +-------------+---------------+
                              |
                              |
                REST API (/components)
                              |
                              v
               +------------------------------+
               | Enumerate Components/Assets  |
               +--------------+---------------+
                              |
                              |
                    Map package ecosystem
                              |
                              v
                 +--------------------------+
                 |      OSV Batch API       |
                 +-------------+------------+
                               |
                               |
                               v
                  +---------------------------+
                  | Report Generation Engine  |
                  +-------------+-------------+
                                |
                                |
      +-------------------------------------------------------+
      | repositories.tsv                                      |
      | components.csv                                        |
      | assets.csv                                            |
      | osv-results.jsonl                                     |
      | vulnerabilities.tsv                                   |
      | malware.tsv                                           |
      | malware-by-repository.tsv                             |
      | summary.txt                                           |
      +-------------------------------------------------------+
```

---

# Scan Workflow

```text
Start
  │
  ▼
Validate configuration
  │
  ▼
Retrieve Nexus repositories
  │
  ▼
Filter repositories
  │
  ▼
Enumerate components
  │
  ▼
Enumerate assets
  │
  ▼
Map packages to OSV ecosystem
  │
  ▼
Build OSV batches
  │
  ▼
Submit OSV Batch API requests
  │
  ▼
Parse vulnerabilities
  │
  ▼
Separate malware
  │
  ▼
Generate reports
  │
  ▼
Finish
```

---

# Requirements

## Operating System

Linux

## Required Software

- Bash 4+
- curl
- jq
- awk
- sed
- sort
- cut
- mktemp
- find

Ubuntu example

```bash
sudo apt install \
    bash \
    curl \
    jq \
    gawk \
    sed \
    coreutils \
    findutils
```

---

# Supported Nexus Formats

| Nexus Format | OSV Ecosystem |
|--------------|---------------|
| npm | npm |
| pypi | PyPI |
| maven2 | Maven |
| nuget | NuGet |
| cargo | crates.io |
| golang | Go |
| rubygems | RubyGems |
| composer | Packagist |
| cocoapods | CocoaPods |

---

# Repository Selection

Repositories are selected using three independent filters.

1.

Repository format

```text
SCAN_FORMATS
```

2.

Repository name regular expression

```text
SCAN_REPOSITORY_REGEX
```

3.

Explicit repository list

```text
SCAN_REPOSITORIES
```

All three filters must match.

Example:

```bash
SCAN_FORMATS="npm,pypi"
SCAN_REPOSITORY_REGEX=".*-proxy"
SCAN_REPOSITORIES=""
```

---

# How It Works

For every selected proxy repository the scanner performs the following steps.

1.

Enumerates all cached components.

2.

Enumerates every asset belonging to each component.

3.

Collects metadata.

- repository
- format
- package
- version
- hashes
- download URL

4.

Maps Nexus package metadata into OSV package coordinates.

Example:

```
Nexus

Format : npm
Name   : lodash

↓

OSV

Ecosystem : npm
Package   : lodash
```

5.

Packages are grouped into configurable batches.

6.

Each batch is submitted to the OSV Batch API.

7.

Results are processed.

8.

Reports are generated.

---

# Security Model

This script is completely read-only.

It never

- deletes artifacts
- quarantines packages
- modifies repositories
- changes metadata
- uploads artifacts
- blocks downloads

Required Nexus permission is read-only REST API access.

---

# Configuration

The scanner is configured entirely through environment variables.

Example

```bash
export NEXUS_URL="https://nexus.example.com"
export NEXUS_USER="scanner"
export NEXUS_PASSWORD="password"

./scan.sh
```

---

# Environment Variables

## Nexus Configuration

### NEXUS_URL

Base URL of the Nexus server.

Example

```bash
https://nexus.example.com
```

Default

```text
https://nexus.example.com
```

---

### NEXUS_USER

Username used for REST API authentication.

---

### NEXUS_PASSWORD

Password used for REST API authentication.

---

### SCAN_FORMATS

Comma-separated Nexus repository formats.

Example

```bash
npm,pypi
```

Possible values

```
npm
pypi
maven2
nuget
cargo
golang
rubygems
composer
cocoapods
```

---

### SCAN_REPOSITORY_REGEX

Extended regular expression matched against repository names.

Example

```bash
.*
```

Example

```bash
^npm-.*
```

---

### SCAN_REPOSITORIES

Optional comma-separated repository names.

Example

```bash
npm-proxy,pypi-proxy
```

Empty value scans every matching repository.

---

## OSV Configuration

### ENABLE_OSV

Enable or disable OSV lookups.

Default

```text
true
```

---

### OSV_BATCH_URL

OSV Batch API endpoint.

Default

```text
https://api.osv.dev/v1/querybatch
```

---

### OSV_BATCH_SIZE

Maximum number of components per batch.

Default

```text
100
```

Larger values reduce HTTP requests.

Smaller values reduce retry impact.

---

### OSV_MAX_RETRIES

Maximum retries for temporary failures.

Default

```
10
```

---

### OSV_RETRY_BASE_SECONDS

Initial retry delay.

Default

```
10
```

---

### OSV_RETRY_MAX_SECONDS

Maximum retry delay.

Default

```
300
```

---

### OSV_403_BASE_COOLDOWN

Initial cooldown after HTTP 403.

Default

```
120
```

---

### OSV_403_MAX_COOLDOWN

Maximum cooldown after repeated HTTP 403 responses.

Default

```
900
```

---

### OSV_MAX_CONSECUTIVE_403

After this many consecutive HTTP 403 responses OSV queries are disabled for the remainder of the scan.

Default

```
5
```

---

### OSV_REQUEST_DELAY

Delay between successful OSV requests.

Default

```
2
```

---

### OSV_RESPECT_RETRY_AFTER

Honor Retry-After headers.

Default

```
true
```

---

### OSV_USER_AGENT

HTTP User-Agent string.

Default

```
nexus-ce-security-scanner/2.1
```

---

## HTTP Configuration

### CONNECT_TIMEOUT

TCP connection timeout.

Default

```
30
```

---

### REQUEST_TIMEOUT

Maximum HTTP request duration.

Default

```
300
```

---

### NEXUS_CURL_RETRIES

Number of retries for Nexus requests.

Default

```
3
```

---

### INSECURE_TLS

Disable TLS certificate verification.

Only use for internal self-signed certificates.

Default

```
false
```

---

## Output Configuration

### OUTPUT_ROOT

Root directory for reports.

---

### OUTPUT_DIR

Directory where reports are generated.

---

### RUN_ID

Unique scan identifier.

Generated automatically if omitted.

```
20260727T153011Z
```

---

# Running the Scanner

Basic scan

```bash
export NEXUS_URL=https://nexus.example.com
export NEXUS_USER=scanner
export NEXUS_PASSWORD=secret

./scan.sh
```

Only npm

```bash
export SCAN_FORMATS="npm"
```

Only PyPI

```bash
export SCAN_FORMATS="pypi"
```

Multiple formats

```bash
export SCAN_FORMATS="npm,pypi,maven2"
```

Scan only repositories ending in "-proxy"

```bash
export SCAN_REPOSITORY_REGEX=".*-proxy"
```

Scan only one repository

```bash
export SCAN_REPOSITORIES="npm-proxy"
```

---

# Generated Reports

| Report | Description |
|---------|-------------|
| repositories.tsv | Repository summary |
| components.jsonl | Raw mapped components |
| components.csv | Component inventory |
| assets.csv | Asset inventory with hashes |
| osv-results.jsonl | Raw OSV results |
| vulnerabilities.tsv | All advisory matches |
| malware.tsv | MAL-* packages |
| malware-by-repository.tsv | Malware grouped by repository |
| failed-osv-queries.jsonl | Deferred batches |
| errors.log | Runtime errors |
| summary.txt | Final summary |
---

# Report Details

## `repositories.tsv`

Contains one row per scanned repository.

Columns

| Column | Description |
|---------|-------------|
| repository | Nexus repository name |
| format | Nexus repository format |
| status | completed or failed |
| components | Number of components scanned |
| assets | Number of assets inventoried |
| osv_findings | Number of advisory matches |
| malware_findings | Number of malware matches |

Example

```text
repository          format   status     components  assets  osv_findings malware_findings
npm-proxy           npm      completed  1542        1610    32           1
pypi-proxy          pypi     completed  2300        2350    18           0
```

---

## `components.csv`

Contains every package successfully mapped into an OSV ecosystem.

Columns

| Column | Description |
|---------|-------------|
| repository | Nexus repository |
| format | Nexus format |
| component_id | Nexus component ID |
| group | Package group/namespace |
| name | Package name |
| version | Package version |
| osv_ecosystem | OSV ecosystem |
| osv_package | Package name sent to OSV |
| osv_ids | Matching advisory IDs |
| osv_finding_count | Number of advisories |
| malware_ids | MAL-* identifiers |
| malware_count | Number of malware findings |

---

## `assets.csv`

Contains every cached asset.

Columns

| Column | Description |
|---------|-------------|
| repository | Repository |
| format | Repository format |
| component_id | Nexus component |
| asset_id | Asset identifier |
| path | Asset path |
| content_type | MIME type |
| file_size | Size in bytes |
| sha1 | SHA-1 checksum |
| sha256 | SHA-256 checksum |
| md5 | MD5 checksum |
| download_url | Nexus download URL |

---

## `osv-results.jsonl`

Raw OSV API responses stored as JSON Lines.

Useful for:

- auditing
- custom reporting
- reprocessing
- debugging

---

## `vulnerabilities.tsv`

Contains every vulnerability found.

Includes:

- CVE
- GHSA
- other OSV advisory identifiers

Example

```text
repository      format package         version     advisory
npm-proxy       npm    lodash          4.17.20     GHSA-....
npm-proxy       npm    minimist        0.0.8       CVE-2021-....
```

---

## `malware.tsv`

Contains only malicious package findings.

Example

```text
repository      format package version malware_id
npm-proxy       npm    evilpkg 1.0.0   MAL-2024-1234
```

---

## `malware-by-repository.tsv`

Aggregated malware statistics.

Example

```text
count repository
3 npm-proxy
1 pypi-proxy
```

---

## `summary.txt`

High-level overview of the scan.

Includes

- repositories scanned
- components inventoried
- assets inventoried
- vulnerabilities
- malware
- failed repositories
- deferred OSV queries
- runtime errors

Example

```text
Repositories selected: 12
Repositories completed: 12
Components mapped: 15421
Assets inventoried: 18122
OSV findings: 94
Malware findings: 3
```

---

# Sample Execution

```bash
export NEXUS_URL=https://nexus.example.com
export NEXUS_USER=scanner
export NEXUS_PASSWORD='secret'

./scan.sh
```

Console output

```text
[2026-07-27T08:15:00Z] Retrieving Nexus repository inventory
[2026-07-27T08:15:02Z] Found 12 proxy repositories

Scanning proxy repository: npm-proxy

Repository progress:
page=1
components=100
assets=125

Submitting OSV batch:
components=100

Repository progress:
page=2
components=200
assets=248

...

Scan completed

Reports generated:

summary.txt
repositories.tsv
components.csv
assets.csv
vulnerabilities.tsv
malware.tsv
```

---

# Output Directory Structure

```text
nexus-security-scan-20260727T081500Z/

├── summary.txt
├── repositories.tsv
├── components.csv
├── components.jsonl
├── assets.csv
├── vulnerabilities.tsv
├── malware.tsv
├── malware-by-repository.tsv
├── osv-results.jsonl
├── failed-osv-queries.jsonl
├── errors.log
└── tmp/
```

---

# Retry Logic

The scanner automatically retries temporary failures.

Supported retry conditions include

- Connection failures
- HTTP 408
- HTTP 425
- HTTP 429
- HTTP 500
- HTTP 502
- HTTP 503
- HTTP 504

Retry strategy

```text
10 s
20 s
40 s
80 s
160 s
300 s (maximum)
```

A small random jitter is added to prevent synchronized retry storms.

---

# HTTP 403 Handling

Repeated HTTP 403 responses often indicate:

- API rate limiting
- reverse proxy restrictions
- firewall policies
- temporary OSV protection

The scanner

- respects Retry-After headers
- exponentially increases cooldowns
- temporarily disables OSV after repeated failures
- stores unchecked batches in

```text
failed-osv-queries.jsonl
```

No inventory information is lost.

---

# Package Mapping

The scanner converts Nexus package metadata into OSV ecosystems.

| Nexus | OSV |
|---------|------|
| npm | npm |
| pypi | PyPI |
| maven2 | Maven |
| nuget | NuGet |
| cargo | crates.io |
| composer | Packagist |
| rubygems | RubyGems |
| golang | Go |
| cocoapods | CocoaPods |

Example

```text
Repository

npm

↓

Package

express

↓

OSV

ecosystem=npm
package=express
```

---

# Malware Detection

The scanner distinguishes malicious packages from ordinary vulnerabilities.

Malware includes

- MAL-* advisories
- advisories marked as malicious
- advisories with malicious aliases

Results are written to

```text
malware.tsv
```

Ordinary vulnerabilities remain in

```text
vulnerabilities.tsv
```

---

# Performance

Performance depends primarily on

- Nexus REST API latency
- number of cached components
- OSV response time
- network bandwidth

Typical inventory speed

| Components | Approximate Time |
|------------|-----------------|
| 1,000 | <1 minute |
| 10,000 | 3–10 minutes |
| 100,000 | 20–60 minutes |

Actual runtime depends on API latency and retry activity.

---

# Security Considerations

The scanner

- does not authenticate to package registries
- does not download package contents
- does not modify Nexus
- only queries Nexus REST APIs
- stores only package metadata and hashes

Use a read-only Nexus account whenever possible.

---

# Troubleshooting

## No repositories found

Verify

- Nexus URL
- credentials
- REST API permissions

---

## No vulnerabilities found

Possible causes

- packages are not present in OSV
- unsupported package ecosystem
- repository filters excluded packages
- OSV temporarily unavailable

---

## HTTP 401

Verify

- username
- password
- reverse proxy authentication

---

## HTTP 403

Possible causes

- API rate limiting
- WAF
- corporate proxy
- temporary OSV restrictions

Increase

```text
OSV_REQUEST_DELAY
```

or reduce

```text
OSV_BATCH_SIZE
```

---

## Invalid JSON

Ensure

- Nexus returns valid JSON
- reverse proxy does not modify responses

---

## TLS Errors

If Nexus uses a self-signed certificate

```bash
export INSECURE_TLS=true
```

Only use this for trusted internal environments.

---

# Limitations

This scanner does **not**

- perform static code analysis
- analyze source code
- inspect container image layers
- unpack archives
- detect zero-day malware
- quarantine packages
- remove packages
- block downloads

It relies exclusively on package metadata and the OSV database.

---

# Best Practices

For production environments

- use a dedicated read-only account
- scan regularly
- archive reports
- review malware findings immediately
- investigate repeated vulnerable packages
- monitor failed OSV queries
- keep Nexus updated
- secure TLS certificates

---

# Exit Status

| Exit Code | Meaning |
|-----------|---------|
| 0 | Scan completed |
| 1 | Configuration or runtime failure |

---

# Contributing

Contributions are welcome.

Suggested improvements include

- additional ecosystem mappings
- parallel repository scanning
- HTML report generation
- SBOM export
- SARIF output
- SPDX support
- CycloneDX export
- additional advisory sources

---

# License

This project is provided as-is without warranty.

Use at your own risk.

---

# Disclaimer

This tool provides **best-effort advisory matching** using the Open Source Vulnerabilities (OSV) database.

A clean scan **does not guarantee** that cached artifacts are free from vulnerabilities or malicious content. Likewise, reported findings should be validated before taking remediation actions.

The scanner is intended to assist with inventory and vulnerability assessment and should be used alongside additional security controls such as repository governance, software composition analysis (SCA), malware scanning, and secure software supply chain practices.

---

# Advanced Usage

## Scan Only npm Repositories

```bash
export SCAN_FORMATS="npm"

./scan.sh
```

---

## Scan npm and PyPI

```bash
export SCAN_FORMATS="npm,pypi"

./scan.sh
```

---

## Scan Maven Repositories

```bash
export SCAN_FORMATS="maven2"
```

---

## Scan Multiple Ecosystems

```bash
export SCAN_FORMATS="npm,pypi,maven2,nuget,cargo"
```

---

## Scan Repository Names Matching a Pattern

```bash
export SCAN_REPOSITORY_REGEX=".*-proxy"
```

Examples

Matches

```
npm-proxy
pypi-proxy
docker-proxy
```

Does not match

```
npm-hosted
raw-hosted
```

---

## Scan a Single Repository

```bash
export SCAN_REPOSITORIES="npm-proxy"
```

---

## Scan Multiple Named Repositories

```bash
export SCAN_REPOSITORIES="npm-proxy,pypi-proxy,maven-central"
```

---

## Disable OSV Queries

Sometimes inventory collection is required without contacting the OSV API.

```bash
export ENABLE_OSV=false
```

This produces

- Repository inventory
- Component inventory
- Asset inventory

without vulnerability lookups.

---

# Repository Filtering Logic

Repositories are processed only if all filters match.

```text
                     Repository
                          │
                          ▼
                 Repository Type
                          │
                proxy ? ─────── no
                  │
                 yes
                  │
                  ▼
          Repository Format
                  │
          matches SCAN_FORMATS ?
                  │
              yes │ no
                  ▼
         Repository Regex
                  │
 matches SCAN_REPOSITORY_REGEX ?
                  │
              yes │ no
                  ▼
      Explicit Repository List
                  │
 matches SCAN_REPOSITORIES ?
                  │
              yes │ no
                  ▼
              Scan Repository
```

---

# OSV Query Workflow

```text
Components

     │

     ▼

Map Package

     │

     ▼

Build Batch

     │

     ▼

POST /querybatch

     │

     ▼

Receive Results

     │

     ▼

Separate

 ┌───────────────┐
 │ Vulnerability │
 └───────────────┘

 ┌───────────────┐
 │   Malware     │
 └───────────────┘

     │

     ▼

Generate Reports
```

---

# Retry Strategy

Temporary failures are handled automatically.

```text
Request

 │

 ▼

HTTP 503

 │

 ▼

Retry 10s

 │

 ▼

HTTP 503

 │

 ▼

Retry 20s

 │

 ▼

HTTP 503

 │

 ▼

Retry 40s

 │

 ▼

Success
```

---

# HTTP 403 Cooldown Strategy

```text
HTTP 403

 │

 ▼

Cooldown

120 seconds

 │

 ▼

HTTP 403

 │

 ▼

Cooldown

240 seconds

 │

 ▼

HTTP 403

 │

 ▼

Cooldown

480 seconds

 │

 ▼

Maximum reached

 │

 ▼

Disable OSV

 │

 ▼

Continue Inventory
```

The scan continues even when OSV becomes temporarily unavailable.

---

# Data Flow

```text
                Nexus Repository

                      │

         REST API (/repositories)

                      │

                      ▼

            Repository Enumeration

                      │

         REST API (/components)

                      │

                      ▼

             Component Enumeration

                      │

                      ▼

             Asset Enumeration

                      │

                      ▼

            Package Normalization

                      │

                      ▼

              OSV Batch Builder

                      │

                      ▼

              OSV Batch API

                      │

                      ▼

             Advisory Processing

                      │

                      ▼

          CSV / TSV / JSONL Reports
```

---

# Directory Layout

```text
project/

├── scan.sh
├── README.md
└── nexus-security-scan-20260727T103012Z
    ├── summary.txt
    ├── repositories.tsv
    ├── components.csv
    ├── components.jsonl
    ├── assets.csv
    ├── osv-results.jsonl
    ├── vulnerabilities.tsv
    ├── malware.tsv
    ├── malware-by-repository.tsv
    ├── failed-osv-queries.jsonl
    ├── errors.log
    └── tmp
```

---

# Interpreting Results

## No Vulnerabilities

```
OSV advisory matches: 0
```

Meaning

- No advisories matched packages that were successfully queried.
- This **does not** guarantee that the repository is secure.

---

## Vulnerabilities Found

```
OSV advisory matches: 34
```

Meaning

Packages matched one or more OSV advisories.

Review

```
vulnerabilities.tsv
```

---

## Malware Found

```
OSV malware matches: 2
```

Meaning

Packages were identified as malicious by OSV.

Immediately review

```
malware.tsv
```

and determine whether those artifacts should remain in the repository.

---

## Deferred Queries

```
Failed/deferred OSV queries: 250
```

Meaning

Some packages could not be checked because OSV was temporarily unavailable.

Inventory data is still complete.

---

# Performance Tuning

## Faster Inventory

Increase

```bash
OSV_BATCH_SIZE=200
```

Pros

- fewer HTTP requests
- lower network overhead

Cons

- larger retries
- larger failed batches

---

## Reduced API Pressure

Increase

```bash
OSV_REQUEST_DELAY=5
```

Useful when

- corporate proxies throttle requests
- HTTP 429 responses occur
- HTTP 403 responses occur

---

## Slow Nexus Servers

Increase

```bash
REQUEST_TIMEOUT=600
CONNECT_TIMEOUT=60
```

---

# Security Recommendations

For production environments

✔ Use a dedicated read-only Nexus account.

✔ Restrict API permissions.

✔ Store credentials outside the script.

✔ Rotate credentials periodically.

✔ Protect generated reports.

✔ Schedule regular scans.

✔ Archive historical reports.

✔ Review malware findings immediately.

---

# Automation Example

Run every night using cron.

```cron
0 2 * * * /opt/nexus-security/scan.sh
```

Example

```bash
0 2 * * * \
NEXUS_URL=https://repo.example.com \
NEXUS_USER=scanner \
NEXUS_PASSWORD='********' \
/opt/nexus-security/scan.sh
```

---

# CI/CD Example

```yaml
name: Nexus Security Scan

on:
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:

      - uses: actions/checkout@v4

      - name: Install Dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y jq curl gawk

      - name: Run Scan
        env:
          NEXUS_URL: ${{ secrets.NEXUS_URL }}
          NEXUS_USER: ${{ secrets.NEXUS_USER }}
          NEXUS_PASSWORD: ${{ secrets.NEXUS_PASSWORD }}
        run: ./scan.sh

      - name: Upload Reports
        uses: actions/upload-artifact@v4
        with:
          name: nexus-security-reports
          path: nexus-security-scan-*/
```

---

# Frequently Asked Questions

## Does this scanner modify Nexus?

No.

The scanner performs **read-only** REST API operations and never modifies repository content.

---

## Does it download package contents?

No.

Only metadata exposed through the Nexus REST API is collected.

---

## Does it scan Docker images?

No.

Docker image vulnerability scanning requires image analysis tools such as Trivy, Grype, or Docker Scout.

---

## Does it replace Sonatype Firewall?

No.

Sonatype Firewall includes proprietary malware intelligence, policy enforcement, quarantine capabilities, and supply chain protections that are outside the scope of this project.

This scanner provides an **open-source alternative for advisory lookup and inventory reporting**, but it is **not a feature-complete replacement** for Sonatype Firewall.

---

## Can it detect zero-day vulnerabilities?

No.

It reports only advisories currently published in the OSV database.

---

## Can it detect malicious packages?

Yes.

The scanner reports advisories identified by OSV as malicious (for example, `MAL-*` advisories) and writes them to `malware.tsv`.

---

## Why are some packages missing from the results?

Possible reasons include:

- Unsupported package ecosystem
- Missing package metadata in Nexus
- Package not present in the OSV database
- OSV query deferred due to temporary service errors

---

# Changelog

## Version 2.1

- Added batch OSV queries
- Improved retry logic
- Added exponential backoff
- Added HTTP 403 cooldown handling
- Added Retry-After support
- Added deferred query reporting
- Added malware-specific reports
- Improved component batching
- Improved inventory reporting
- Fixed component enumeration issue caused by `jq` consuming loop input
- Added comprehensive summary report

---

# Acknowledgements

This project builds upon publicly available technologies and services, including:

- Bash
- curl
- jq
- Sonatype Nexus Repository Community Edition
- Open Source Vulnerabilities (OSV)

Special thanks to the maintainers of these open-source projects for making security automation possible.

---

---

# Comparison with Sonatype Firewall

| Feature | This Scanner | Sonatype Firewall |
|----------|--------------|-------------------|
| Read Nexus Components | ✅ | ✅ |
| Read Nexus Assets | ✅ | ✅ |
| Inventory Cached Packages | ✅ | ✅ |
| Detect Known Vulnerabilities | ✅ (OSV) | ✅ |
| Detect Known Malicious Packages | ✅ (OSV MAL-*) | ✅ |
| Repository Reports | ✅ | ✅ |
| CSV Reports | ✅ | ✅ |
| JSON Reports | ✅ | ✅ |
| Automatic Retry | ✅ | ✅ |
| Repository Quarantine | ❌ | ✅ |
| Download Blocking | ❌ | ✅ |
| Policy Enforcement | ❌ | ✅ |
| License Compliance | ❌ | ✅ |
| Proprietary Threat Intelligence | ❌ | ✅ |
| Continuous Policy Evaluation | ❌ | ✅ |

---

# Supported HTTP Status Codes

The scanner handles the following HTTP responses automatically.

| HTTP Code | Description | Action |
|------------|-------------|--------|
| 200 | Success | Continue |
| 400 | Invalid request | Stop batch |
| 401 | Authentication failure | Record error |
| 403 | Rate limit / Forbidden | Cooldown and retry |
| 408 | Timeout | Retry |
| 425 | Too Early | Retry |
| 429 | Too Many Requests | Retry |
| 500 | Internal Server Error | Retry |
| 502 | Bad Gateway | Retry |
| 503 | Service Unavailable | Retry |
| 504 | Gateway Timeout | Retry |

---

# Component Processing Lifecycle

Every package passes through the following lifecycle.

```text
                Nexus Component

                      │

                      ▼

             Read Component Metadata

                      │

                      ▼

             Read Associated Assets

                      │

                      ▼

             Normalize Package Name

                      │

                      ▼

             Determine OSV Ecosystem

                      │

                      ▼

             Build Batch Request

                      │

                      ▼

              Submit to OSV API

                      │

          ┌───────────┴────────────┐
          │                        │
          ▼                        ▼

  Vulnerability Found       No Match

          │                        │
          ▼                        ▼

 Update Reports           Continue Scan
```

---

# Asset Inventory

For every component the scanner records every asset.

Typical examples include

### npm

```
package.json
package.tgz
```

---

### Maven

```
jar
pom
sources.jar
javadoc.jar
```

---

### PyPI

```
wheel
tar.gz
```

---

### NuGet

```
nupkg
nuspec
```

---

# Hash Collection

The scanner records every checksum already stored by Nexus.

Supported hashes

| Hash | Purpose |
|-------|----------|
| SHA-1 | Legacy integrity |
| SHA-256 | Strong integrity verification |
| MD5 | Legacy compatibility |

No hash calculations are performed locally.

The scanner simply records metadata exposed by the Nexus REST API.

---

# Logging

Console output is timestamped.

Example

```text
[2026-07-27T09:31:10Z] Retrieving Nexus repository inventory

[2026-07-27T09:31:11Z] Found 12 proxy repositories

[2026-07-27T09:31:13Z] Scanning proxy repository:
npm-proxy

[2026-07-27T09:31:20Z] Repository progress:
components=100
assets=131

[2026-07-27T09:31:25Z] Submitting OSV batch:
components=100
```

Runtime errors are additionally written to

```
errors.log
```

---

# Report Relationships

```text
                 Components

                      │

          ┌───────────┴────────────┐

          ▼                        ▼

     components.csv          assets.csv

          │

          ▼

    osv-results.jsonl

          │

 ┌────────┴────────┐

 ▼                 ▼

vulnerabilities    malware

          │

          ▼

malware-by-repository

          │

          ▼

      summary.txt
```

---

# Best Practices

## Credentials

Avoid hardcoding credentials inside the script.

Preferred

```bash
export NEXUS_URL=https://repo.example.com
export NEXUS_USER=scanner
export NEXUS_PASSWORD='********'
```

---

## Dedicated Scanner Account

Create a dedicated Nexus account with only the permissions required to:

- browse repositories
- read components
- read assets
- access REST APIs

Administrative permissions are unnecessary.

---

## Regular Scans

Recommended frequencies

| Repository Size | Recommendation |
|-----------------|---------------|
| Small | Daily |
| Medium | Nightly |
| Large Enterprise | Continuous scheduled scans |

---

## Archive Reports

Retain previous reports.

Historical data helps identify

- newly introduced vulnerabilities
- malware trends
- repository growth
- package churn

---

# Known Limitations

The scanner intentionally does **not**:

- download package archives
- unpack artifacts
- inspect source code
- analyze compiled binaries
- inspect Docker image layers
- perform static analysis
- perform dynamic analysis
- execute sandbox analysis
- inspect SBOMs
- detect unpublished vulnerabilities

Its purpose is metadata inventory and advisory correlation.

---

# Future Roadmap

Potential enhancements include

- HTML dashboard
- Interactive reports
- SQLite output
- PostgreSQL output
- SARIF export
- CycloneDX SBOM export
- SPDX export
- Parallel repository scanning
- Parallel OSV queries
- Multi-threaded inventory
- Incremental scanning
- Scan resume support
- Prometheus metrics
- Grafana dashboards
- Email notifications
- Slack notifications
- Microsoft Teams notifications
- GitHub Security Advisory integration
- CISA KEV integration
- NVD enrichment
- EPSS scoring
- CVSS prioritization
- Risk scoring
- Package popularity scoring
- Historical trend reports

---

# Example Complete Scan

```bash
export NEXUS_URL=https://repo.example.com
export NEXUS_USER=scanner
export NEXUS_PASSWORD='password'

export SCAN_FORMATS="npm,pypi,maven2"

export SCAN_REPOSITORY_REGEX=".*"

export ENABLE_OSV=true

export OSV_BATCH_SIZE=100

./scan.sh
```

Expected output

```text
Found 18 proxy repositories

Scanning npm-proxy...

Scanning pypi-proxy...

Scanning maven-central...

Generating reports...

Scan completed successfully.
```

---

# Exit Codes

| Exit Code | Meaning |
|------------|---------|
| 0 | Scan completed successfully |
| 1 | Fatal configuration or runtime error |

---

# Frequently Asked Questions

### Does this scanner require Sonatype Nexus Pro?

No.

It is designed specifically for **Sonatype Nexus Repository OSS / Community Edition** and relies only on publicly available REST APIs.

---

### Can it scan hosted repositories?

By default, **no**.

Only repositories whose type is **proxy** are scanned.

---

### Can it scan group repositories?

No.

Group repositories aggregate other repositories and are intentionally skipped.

---

### Does it upload any data to Nexus?

No.

The scanner never uploads or modifies repository content.

---

### Does it store downloaded packages?

No.

Only repository metadata returned by the REST API is processed.

---

### Is Internet access required?

Yes, when `ENABLE_OSV=true`.

The scanner queries the public OSV Batch API.

If OSV queries are disabled, Internet connectivity is unnecessary after Nexus access is established.

---

### Is this scanner safe to run against production Nexus servers?

Yes.

The scanner performs **read-only** API requests and does not alter repository contents.

The primary impact is the additional REST API load generated during inventory collection.

---

# Support

If you encounter issues:

1. Verify Nexus connectivity.
2. Verify REST API credentials.
3. Review `errors.log`.
4. Check `failed-osv-queries.jsonl` for deferred OSV requests.
5. Review `summary.txt` for the overall scan status.

---

# License

This project is released under the MIT License (or your preferred open-source license).

You are free to use, modify, and distribute this project in accordance with the terms of the chosen license.

---

# Disclaimer

This tool is intended for **security assessment, inventory, and reporting** purposes only.

While it leverages the Open Source Vulnerabilities (OSV) database to identify known vulnerabilities and malicious packages, **no automated security scanner can guarantee complete detection of all threats**.

Always combine the results of this tool with:

- Secure software development practices
- Regular dependency updates
- Repository governance
- Supply chain security controls
- Manual security reviews
- Additional vulnerability scanning tools

---

## Author

Developed as an open-source utility for securing **Sonatype Nexus Repository Community Edition** installations through automated package inventory and OSV-based vulnerability analysis by RoninAngle1.

Contributions, bug reports, and feature requests are welcome.

