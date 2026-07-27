# Nexus Repository CE Scanner

> Offline vulnerability and malware scanner for **Sonatype Nexus
> Repository CE** using a **local GitHub Advisory Database**. The
> scanner inventories Nexus proxy repositories, performs offline
> advisory matching, and generates detailed security reports without
> using OSV API, VirusTotal, OpenCVE, or commercial services.

------------------------------------------------------------------------

# Table of Contents

1.  Overview
2.  Features
3.  Architecture
4.  Workflow
5.  Requirements
6.  Configuration
7.  Complete `.env.example`
8.  Environment Variable Reference
9.  Installation
10. Running the Scanner
11. Sample Output
12. Generated Reports
13. REST API Flow
14. GitHub README Content
15. Operations Guide
16. Troubleshooting
17. Security Notes

------------------------------------------------------------------------

# 1. Overview

The scanner:

-   Connects to Sonatype Nexus Repository CE
-   Enumerates proxy repositories
-   Inventories packages and assets
-   Downloads (or reuses) a local GitHub Advisory Database
-   Builds a local advisory index
-   Maps Nexus package formats to GitHub ecosystems
-   Matches package versions against advisory ranges
-   Generates CSV, TSV, JSONL and summary reports

The scanner **never modifies Nexus content**.

------------------------------------------------------------------------

# 2. Features

-   Offline vulnerability scanning
-   Offline malware advisory matching
-   Local GitHub Advisory Database
-   Supports:
    -   npm
    -   PyPI
    -   Maven
    -   NuGet
    -   Go
    -   RubyGems
    -   Cargo
    -   Composer
-   Asset inventory
-   Version-aware advisory matching
-   Read-only operation
-   Detailed reporting

------------------------------------------------------------------------

# 3. Architecture

``` text
                   GitHub Advisory Database
                 (Local Archive / Extracted Copy)
                             │
                             ▼
                  Build Local Advisory Index
                             │
                             ▼
+----------------+      REST API      +-------------------+
| Nexus CE Proxy | ─────────────────► | Inventory Engine  |
| Repositories   |                    | (Bash Script)     |
+----------------+                    +---------+---------+
                                               │
                                               ▼
                                      Version Matching
                                               │
                                               ▼
                                      Report Generation
                                               │
                                               ▼
                     CSV • TSV • JSONL • Summary Reports
```

------------------------------------------------------------------------

# 4. Workflow

``` text
Validate Environment
        │
        ▼
Download / Reuse Advisory Database
        │
        ▼
Build Advisory Index
        │
        ▼
Retrieve Nexus Repositories
        │
        ▼
Inventory Components & Assets
        │
        ▼
Map Packages to GitHub Ecosystems
        │
        ▼
Match Against Advisories
        │
        ▼
Generate Reports
```

------------------------------------------------------------------------

# 5. Requirements

-   bash
-   curl
-   jq
-   python3
-   awk
-   sed
-   sort
-   cut
-   mktemp
-   tar
-   sha256sum

------------------------------------------------------------------------

# 6. Configuration

The scanner is configured entirely through environment variables.

------------------------------------------------------------------------

# 7. Complete `.env.example`

``` bash
###############################################################################
# Nexus Connection
###############################################################################

NEXUS_URL=https://nexus.example.com
NEXUS_USER=scanner
NEXUS_PASSWORD=ChangeMe

###############################################################################
# Repository Selection
###############################################################################

SCAN_FORMATS=npm,pypi,maven2,nuget
SCAN_REPOSITORY_REGEX=.*
SCAN_REPOSITORIES=

###############################################################################
# Network
###############################################################################

CONNECT_TIMEOUT=30
REQUEST_TIMEOUT=300
NEXUS_CURL_RETRIES=3
INSECURE_TLS=false

###############################################################################
# GitHub Advisory Database
###############################################################################

GITHUB_ADVISORY_ARCHIVE_URL=https://github.com/github/advisory-database/archive/refs/heads/main.tar.gz
GITHUB_ADVISORY_DB=./github-advisory-database
UPDATE_ADVISORY_DB=true
ADVISORY_CATEGORIES=github-reviewed,malware
FORCE_REBUILD_INDEX=false

###############################################################################
# Output
###############################################################################

OUTPUT_ROOT=./reports
RUN_ID=
OUTPUT_DIR=
```

------------------------------------------------------------------------

# 8. Environment Variable Reference

  ------------------------------------------------------------------------------------------------------------------------------
  Variable                        Default                                                 Required         Description
  ------------------------------- ------------------------------------------------------- ---------------- ---------------------
  `NEXUS_URL`                     None                                                    Yes              Base URL of the Nexus
                                                                                                           Repository CE server.

  `NEXUS_USER`                    None                                                    Yes              Username used to
                                                                                                           authenticate with the
                                                                                                           Nexus REST API.

  `NEXUS_PASSWORD`                None                                                    Yes              Password or access
                                                                                                           token for the Nexus
                                                                                                           user.

  `SCAN_FORMATS`                  `npm,pypi,maven2,nuget`                                 No               Comma-separated
                                                                                                           repository formats to
                                                                                                           scan.

  `SCAN_REPOSITORY_REGEX`         `.*`                                                    No               Regular expression
                                                                                                           used to filter
                                                                                                           repository names.

  `SCAN_REPOSITORIES`             Empty                                                   No               Explicit
                                                                                                           comma-separated list
                                                                                                           of repository names.

  `CONNECT_TIMEOUT`               `30`                                                    No               Connection timeout in
                                                                                                           seconds.

  `REQUEST_TIMEOUT`               `300`                                                   No               Maximum request
                                                                                                           execution time in
                                                                                                           seconds.

  `NEXUS_CURL_RETRIES`            `3`                                                     No               Number of retry
                                                                                                           attempts for failed
                                                                                                           Nexus API calls.

  `INSECURE_TLS`                  `false`                                                 No               Disables TLS
                                                                                                           certificate
                                                                                                           validation. Intended
                                                                                                           only for testing
                                                                                                           environments.

  `GITHUB_ADVISORY_ARCHIVE_URL`   GitHub main archive                                     No               URL of the GitHub
                                                                                                           Advisory Database
                                                                                                           archive.

  `GITHUB_ADVISORY_DB`            `./github-advisory-database`                            No               Local directory where
                                                                                                           the advisory database
                                                                                                           is stored.

  `UPDATE_ADVISORY_DB`            `true`                                                  No               Downloads or
                                                                                                           refreshes the
                                                                                                           advisory database
                                                                                                           before each scan.

  `ADVISORY_CATEGORIES`           `github-reviewed,malware`                               No               Advisory categories
                                                                                                           to include
                                                                                                           (`github-reviewed`,
                                                                                                           `malware`,
                                                                                                           `unreviewed`).

  `FORCE_REBUILD_INDEX`           `false`                                                 No               Forces rebuilding the
                                                                                                           advisory index even
                                                                                                           if unchanged.

  `OUTPUT_ROOT`                   Current directory                                       No               Root directory for
                                                                                                           generated reports.

  `RUN_ID`                        UTC timestamp                                           No               Unique identifier for
                                                                                                           the scan execution.
                                                                                                           Normally generated
                                                                                                           automatically.

  `OUTPUT_DIR`                    `${OUTPUT_ROOT}/nexus-github-advisory-scan-${RUN_ID}`   No               Overrides the
                                                                                                           automatically
                                                                                                           generated output
                                                                                                           directory.
  ------------------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------

# 9. Installation

``` bash
chmod +x nexus_scan.sh

cp .env.example .env

nano .env

source .env

./nexus_scan.sh
```

------------------------------------------------------------------------

# 10. Running the Scanner

``` bash
./nexus_scan.sh
```

or

``` bash
NEXUS_URL=https://nexus.example.com \
NEXUS_USER=scanner \
NEXUS_PASSWORD=secret \
./nexus_scan.sh
```

------------------------------------------------------------------------

# 11. Sample Output

``` text
Downloading GitHub Advisory Database...
Building advisory index...
Retrieving Nexus repositories...
Found 12 proxy repositories
Scanning npm-proxy...
Scanning maven-central...
Matching components...
Generating reports...
Scan completed.

Reports generated:
 summary.txt
 repositories.tsv
 components.csv
 assets.csv
 findings.jsonl
 vulnerabilities.tsv
 malware.tsv
 malware-by-repository.tsv
 errors.log
```

------------------------------------------------------------------------

# 12. Generated Reports

  Report                      Description
  --------------------------- -----------------------------
  summary.txt                 Scan summary
  repositories.tsv            Repository inventory
  components.csv              Component inventory
  assets.csv                  Asset inventory with hashes
  findings.jsonl              Raw findings
  vulnerabilities.tsv         Vulnerability report
  malware.tsv                 Malware findings
  malware-by-repository.tsv   Malware summary
  errors.log                  Errors encountered

------------------------------------------------------------------------

# 13. REST API Flow

``` text
GET /service/rest/v1/repositories
            │
            ▼
Filter proxy repositories
            │
            ▼
GET /service/rest/v1/components?repository=<repo>
            │
            ▼
Component Inventory
            │
            ▼
Package Mapping
            │
            ▼
Local Advisory Matching
            │
            ▼
Report Generation
```

------------------------------------------------------------------------

# 14. GitHub README

## Highlights

-   Offline
-   Read-only
-   Multi-ecosystem
-   No external scanning APIs
-   Local advisory matching
-   CSV / TSV / JSONL reports

Quick start:

``` bash
git clone <repository>
cp .env.example .env
./nexus_scan.sh
```

------------------------------------------------------------------------

# 15. Operations Guide

Daily: 1. Update advisory database. 2. Run scanner. 3. Review summary.
4. Investigate malware findings. 5. Archive reports.

Weekly: - Refresh advisory DB - Review errors.log - Verify Nexus
credentials - Review scan trends

------------------------------------------------------------------------

# 16. Troubleshooting

  Problem                 Resolution
  ----------------------- ---------------------------------------------------------
  Authentication failed   Verify NEXUS_USER and NEXUS_PASSWORD
  TLS error               Use INSECURE_TLS=true only in trusted test environments
  No repositories found   Verify repository permissions and filters
  No advisories indexed   Check UPDATE_ADVISORY_DB and advisory path
  Reports missing         Verify OUTPUT_ROOT permissions

------------------------------------------------------------------------

# 17. Security Notes

-   The scanner is read-only.
-   No packages are uploaded externally.
-   No Nexus content is modified.
-   Vulnerability findings do not necessarily indicate malware.
-   No findings do not guarantee software is free from vulnerabilities.
