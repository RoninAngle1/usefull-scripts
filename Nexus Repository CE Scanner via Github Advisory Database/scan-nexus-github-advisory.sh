#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# Nexus Repository CE scanner using a LOCAL clone of GitHub Advisory Database
#
# No OSV API, VirusTotal, OpenCVE, or commercial service is used.
#
# Requirements:
#   bash curl jq python3 awk sed sort cut mktemp find tar sha256sum
#
# Important:
#   - GitHub malware advisories are currently primarily/npm-specific.
#   - Vulnerability matching uses GitHub Advisory Database OSV records.
#   - This script never deletes Nexus content.
###############################################################################

###############################################################################
# Nexus configuration
###############################################################################

NEXUS_URL="${NEXUS_URL:-https://nexus.example.com}"
NEXUS_USER="${NEXUS_USER:-scanner}"
NEXUS_PASSWORD="${NEXUS_PASSWORD:-}"

SCAN_FORMATS="${SCAN_FORMATS:-npm,pypi,maven2,nuget}"
SCAN_REPOSITORY_REGEX="${SCAN_REPOSITORY_REGEX:-.*}"
SCAN_REPOSITORIES="${SCAN_REPOSITORIES:-}"

CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-30}"
REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-300}"
NEXUS_CURL_RETRIES="${NEXUS_CURL_RETRIES:-3}"
INSECURE_TLS="${INSECURE_TLS:-false}"

###############################################################################
# GitHub Advisory Database configuration
###############################################################################

GITHUB_ADVISORY_ARCHIVE_URL="${GITHUB_ADVISORY_ARCHIVE_URL:-https://github.com/github/advisory-database/archive/refs/heads/main.tar.gz}"
GITHUB_ADVISORY_DB="${GITHUB_ADVISORY_DB:-./github-advisory-database}"
GITHUB_ADVISORY_SOURCE_ID_FILE="${GITHUB_ADVISORY_DB}/.source.sha256"

# true: clone/update database before scanning
# false: use the existing local checkout only
UPDATE_ADVISORY_DB="${UPDATE_ADVISORY_DB:-true}"

# Include these advisory categories:
#   github-reviewed
#   malware
#   unreviewed
#
# Recommended default excludes unreviewed advisories because many lack precise
# package mapping.
ADVISORY_CATEGORIES="${ADVISORY_CATEGORIES:-github-reviewed,malware}"

# Rebuild index even when the database commit has not changed.
FORCE_REBUILD_INDEX="${FORCE_REBUILD_INDEX:-false}"

###############################################################################
# Output
###############################################################################

OUTPUT_ROOT="${OUTPUT_ROOT:-.}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUTPUT_DIR="${OUTPUT_DIR:-${OUTPUT_ROOT}/nexus-github-advisory-scan-${RUN_ID}}"
TEMP_DIR="${OUTPUT_DIR}/tmp"

ADVISORY_INDEX="${GITHUB_ADVISORY_DB}/.nexus-advisory-index.jsonl"
ADVISORY_INDEX_META="${GITHUB_ADVISORY_DB}/.nexus-advisory-index.meta"

REPOSITORIES_TSV="${OUTPUT_DIR}/repositories.tsv"
COMPONENTS_JSONL="${OUTPUT_DIR}/components.jsonl"
COMPONENTS_CSV="${OUTPUT_DIR}/components.csv"
ASSETS_CSV="${OUTPUT_DIR}/assets.csv"
FINDINGS_JSONL="${OUTPUT_DIR}/findings.jsonl"
VULNERABILITIES_TSV="${OUTPUT_DIR}/vulnerabilities.tsv"
MALWARE_TSV="${OUTPUT_DIR}/malware.tsv"
MALWARE_BY_REPOSITORY_TSV="${OUTPUT_DIR}/malware-by-repository.tsv"
SUMMARY_FILE="${OUTPUT_DIR}/summary.txt"
ERROR_LOG="${OUTPUT_DIR}/errors.log"

###############################################################################
# Runtime
###############################################################################

declare -a CURL_TLS_ARGS=()
if [[ "$INSECURE_TLS" == "true" ]]; then
    CURL_TLS_ARGS=(-k)
fi

###############################################################################
# Helpers
###############################################################################

log() {
    printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" >&2
}

record_error() {
    local message="$*"
    printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$message" >> "$ERROR_LOG"
    log "ERROR: $message"
}

fatal() {
    record_error "$*"
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'Required command is missing: %s\n' "$1" >&2
        exit 1
    }
}

csv_escape() {
    local value="${1:-}"
    value="${value//$'\r'/ }"
    value="${value//$'\n'/ }"
    value="${value//\"/\"\"}"
    printf '"%s"' "$value"
}

contains_csv_value() {
    [[ ",$1," == *",$2,"* ]]
}

format_is_selected() {
    contains_csv_value "$SCAN_FORMATS" "$1"
}

repository_is_selected() {
    [[ -z "$SCAN_REPOSITORIES" ]] || contains_csv_value "$SCAN_REPOSITORIES" "$1"
}

nexus_curl() {
    curl \
        "${CURL_TLS_ARGS[@]}" \
        --fail \
        --silent \
        --show-error \
        --location \
        --retry "$NEXUS_CURL_RETRIES" \
        --retry-all-errors \
        --retry-delay 2 \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$REQUEST_TIMEOUT" \
        --user "${NEXUS_USER}:${NEXUS_PASSWORD}" \
        "$@"
}

initialize_reports() {
    mkdir -p "$OUTPUT_DIR" "$TEMP_DIR"
    : > "$ERROR_LOG"
    : > "$COMPONENTS_JSONL"
    : > "$FINDINGS_JSONL"

    printf '%s\n' \
        $'repository\tformat\tstatus\tcomponents\tassets\tfindings\tmalware_findings' \
        > "$REPOSITORIES_TSV"

    printf '%s\n' \
        '"repository","format","component_id","group","name","version","github_ecosystem","github_package","finding_count","malware_count"' \
        > "$COMPONENTS_CSV"

    printf '%s\n' \
        '"repository","format","component_id","asset_id","path","content_type","file_size","sha1","sha256","md5","download_url"' \
        > "$ASSETS_CSV"

    printf '%s\n' \
        $'repository\tformat\tpackage\tversion\tadvisory_id\taliases\tseverity\tsummary' \
        > "$VULNERABILITIES_TSV"

    printf '%s\n' \
        $'repository\tformat\tpackage\tversion\tadvisory_id\taliases\tsummary' \
        > "$MALWARE_TSV"

    printf '%s\n' $'count\trepository' > "$MALWARE_BY_REPOSITORY_TSV"
}

validate_configuration() {
    local cmd
    for cmd in bash curl jq python3 awk sed sort cut mktemp find tr wc tar sha256sum; do
        require_command "$cmd"
    done

    [[ -n "$NEXUS_URL" ]] || fatal "NEXUS_URL is empty"
    [[ -n "$NEXUS_USER" ]] || fatal "NEXUS_USER is empty"
    [[ -n "$NEXUS_PASSWORD" ]] || fatal "NEXUS_PASSWORD is empty"
}

###############################################################################
# GitHub Advisory Database clone/update
###############################################################################

sync_advisory_database() {
    if [[ "$UPDATE_ADVISORY_DB" != "true" ]]; then
        [[ -d "${GITHUB_ADVISORY_DB}/advisories" ]] ||
            fatal "Advisory database is missing and UPDATE_ADVISORY_DB=false"

        log "Using existing extracted GitHub Advisory Database"
        return 0
    fi

    log "Downloading GitHub Advisory Database source archive"

    local archive_file
    local extract_dir
    local source_hash

    archive_file="$(mktemp "${TEMP_DIR}/github-advisory.XXXXXX.tar.gz")"
    extract_dir="$(mktemp -d "${TEMP_DIR}/github-advisory-extract.XXXXXX")"

    if ! curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --retry 5 \
        --retry-all-errors \
        --retry-delay 3 \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$REQUEST_TIMEOUT" \
        --output "$archive_file" \
        "$GITHUB_ADVISORY_ARCHIVE_URL"; then
        rm -rf "$archive_file" "$extract_dir"
        fatal "Unable to download GitHub Advisory Database archive"
    fi

    source_hash="$(sha256sum "$archive_file" | awk '{print $1}')"

    if [[ -s "$GITHUB_ADVISORY_SOURCE_ID_FILE" &&
          "$(cat "$GITHUB_ADVISORY_SOURCE_ID_FILE")" == "$source_hash" &&
          -d "${GITHUB_ADVISORY_DB}/advisories" ]]; then
        log "GitHub Advisory Database archive is unchanged"
        rm -rf "$archive_file" "$extract_dir"
        return 0
    fi

    if ! tar -xzf "$archive_file" --strip-components=1 -C "$extract_dir"; then
        rm -rf "$archive_file" "$extract_dir"
        fatal "Unable to extract GitHub Advisory Database archive"
    fi

    [[ -d "${extract_dir}/advisories" ]] || {
        rm -rf "$archive_file" "$extract_dir"
        fatal "Downloaded archive does not contain advisories/"
    }

    rm -rf "$GITHUB_ADVISORY_DB"
    mkdir -p "$(dirname "$GITHUB_ADVISORY_DB")"
    mv "$extract_dir" "$GITHUB_ADVISORY_DB"
    printf '%s\n' "$source_hash" > "$GITHUB_ADVISORY_SOURCE_ID_FILE"

    rm -f "$archive_file"

    log "GitHub Advisory Database archive installed"
}
###############################################################################
# Build a compact package-oriented index
###############################################################################

build_advisory_index() {
    local source_id
    source_id="$(cat "$GITHUB_ADVISORY_SOURCE_ID_FILE" 2>/dev/null || printf unknown)"

    if [[ "$FORCE_REBUILD_INDEX" != "true" &&
          -s "$ADVISORY_INDEX" &&
          -s "$ADVISORY_INDEX_META" &&
          "$(cat "$ADVISORY_INDEX_META")" == "$source_id|$ADVISORY_CATEGORIES" ]]; then
        log "Using existing advisory index"
        return 0
    fi

    log "Building local advisory index"

    python3 - "$GITHUB_ADVISORY_DB" "$ADVISORY_INDEX" "$ADVISORY_CATEGORIES" <<'PY'
import json
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
output = Path(sys.argv[2])
categories = {x.strip() for x in sys.argv[3].split(",") if x.strip()}

base = root / "advisories"
count = 0
affected_count = 0

with output.open("w", encoding="utf-8") as out:
    for category in sorted(categories):
        category_dir = base / category
        if not category_dir.is_dir():
            continue

        for path in category_dir.rglob("*.json"):
            try:
                advisory = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                print(f"WARNING: cannot parse {path}: {exc}", file=sys.stderr)
                continue

            advisory_id = advisory.get("id", "")
            aliases = advisory.get("aliases") or []
            summary = advisory.get("summary") or ""
            severity = advisory.get("database_specific", {}).get("severity", "")
            is_malware = (
                category == "malware"
                or advisory_id.startswith("MAL-")
                or bool(advisory.get("database_specific", {}).get("malicious", False))
            )

            for affected in advisory.get("affected") or []:
                package = affected.get("package") or {}
                ecosystem = package.get("ecosystem") or ""
                name = package.get("name") or ""
                if not ecosystem or not name:
                    continue

                row = {
                    "id": advisory_id,
                    "aliases": aliases,
                    "summary": summary,
                    "severity": severity,
                    "is_malware": is_malware,
                    "category": category,
                    "ecosystem": ecosystem,
                    "package": name,
                    "versions": affected.get("versions") or [],
                    "ranges": affected.get("ranges") or [],
                    "database_specific": advisory.get("database_specific") or {},
                    "source_file": str(path.relative_to(root)),
                }
                out.write(json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n")
                affected_count += 1

            count += 1

print(f"Indexed {count} advisories and {affected_count} affected-package records", file=sys.stderr)
PY

    printf '%s' "$source_id|$ADVISORY_CATEGORIES" > "$ADVISORY_INDEX_META"
}

###############################################################################
# Nexus-to-GitHub ecosystem mapping
###############################################################################

map_to_github() {
    local format="$1"
    local group="$2"
    local name="$3"

    case "$format" in
        npm)
            if [[ "$name" == @*/* ]]; then
                printf 'npm\t%s\n' "$name"
            elif [[ -n "$group" && "$group" != "null" ]]; then
                printf 'npm\t@%s/%s\n' "${group#@}" "$name"
            else
                printf 'npm\t%s\n' "$name"
            fi
            ;;
        pypi)
            printf 'PyPI\t%s\n' "$name"
            ;;
        maven2)
            [[ -n "$group" && "$group" != "null" ]] &&
                printf 'Maven\t%s:%s\n' "$group" "$name" ||
                printf '\t\n'
            ;;
        nuget)
            printf 'NuGet\t%s\n' "$name"
            ;;
        golang)
            if [[ "$name" == */* ]]; then
                printf 'Go\t%s\n' "$name"
            elif [[ -n "$group" && "$group" != "null" ]]; then
                printf 'Go\t%s/%s\n' "${group%/}" "$name"
            else
                printf 'Go\t%s\n' "$name"
            fi
            ;;
        rubygems)
            printf 'RubyGems\t%s\n' "$name"
            ;;
        cargo)
            printf 'crates.io\t%s\n' "$name"
            ;;
        composer)
            if [[ "$name" == */* ]]; then
                printf 'Packagist\t%s\n' "$name"
            elif [[ -n "$group" && "$group" != "null" ]]; then
                printf 'Packagist\t%s/%s\n' "${group%/}" "$name"
            else
                printf '\t\n'
            fi
            ;;
        *)
            printf '\t\n'
            ;;
    esac
}

###############################################################################
# Asset inventory
###############################################################################

write_asset_csv() {
    local repository="$1"
    local format="$2"
    local component_id="$3"
    local asset_json="$4"

    local asset_id path content_type file_size sha1 sha256 md5 download_url
    asset_id="$(jq -r '.id // ""' <<< "$asset_json")"
    path="$(jq -r '.path // ""' <<< "$asset_json")"
    content_type="$(jq -r '.contentType // ""' <<< "$asset_json")"
    file_size="$(jq -r '.fileSize // 0' <<< "$asset_json")"
    sha1="$(jq -r '.checksum.sha1 // ""' <<< "$asset_json")"
    sha256="$(jq -r '.checksum.sha256 // ""' <<< "$asset_json")"
    md5="$(jq -r '.checksum.md5 // ""' <<< "$asset_json")"
    download_url="$(jq -r '.downloadUrl // ""' <<< "$asset_json")"

    {
        csv_escape "$repository"; printf ','
        csv_escape "$format"; printf ','
        csv_escape "$component_id"; printf ','
        csv_escape "$asset_id"; printf ','
        csv_escape "$path"; printf ','
        csv_escape "$content_type"; printf ','
        csv_escape "$file_size"; printf ','
        csv_escape "$sha1"; printf ','
        csv_escape "$sha256"; printf ','
        csv_escape "$md5"; printf ','
        csv_escape "$download_url"; printf '\n'
    } >> "$ASSETS_CSV"
}

###############################################################################
# Create normalized component record
###############################################################################

prepare_component() {
    local repository="$1"
    local format="$2"
    local component_json="$3"

    local component_id group name version mapping ecosystem package
    component_id="$(jq -r '.id // ""' <<< "$component_json")"
    group="$(jq -r '.group // ""' <<< "$component_json")"
    name="$(jq -r '.name // ""' <<< "$component_json")"
    version="$(jq -r '.version // ""' <<< "$component_json")"

    [[ -n "$name" && -n "$version" && "$name" != "null" && "$version" != "null" ]] ||
        return 1

    mapping="$(map_to_github "$format" "$group" "$name")"
    ecosystem="$(cut -f1 <<< "$mapping")"
    package="$(cut -f2- <<< "$mapping")"

    [[ -n "$ecosystem" && -n "$package" ]] || return 1

    # Explicit input prevents consuming the outer while-read loop's stdin.
    jq -c \
        --arg repository "$repository" \
        --arg format "$format" \
        --arg component_id "$component_id" \
        --arg group "$group" \
        --arg name "$name" \
        --arg version "$version" \
        --arg ecosystem "$ecosystem" \
        --arg package "$package" \
        '{
            repository: $repository,
            format: $format,
            component_id: $component_id,
            group: $group,
            name: $name,
            version: $version,
            ecosystem: $ecosystem,
            package: $package
        }' <<< "$component_json"
}

###############################################################################
# Match all components against the local advisory index
#
# Version matching is implemented in Python because GitHub advisory files use
# OSV range events. The comparator normalizes common SemVer/PEP440/Maven-like
# versions. Exact entries in affected.versions are always honored.
###############################################################################

match_components() {
    log "Matching Nexus components against local GitHub Advisory Database"

    python3 - \
        "$ADVISORY_INDEX" \
        "$COMPONENTS_JSONL" \
        "$FINDINGS_JSONL" <<'PY'
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

index_path = Path(sys.argv[1])
components_path = Path(sys.argv[2])
findings_path = Path(sys.argv[3])

def normalize_package(ecosystem, name):
    # PyPI package names are case-insensitive and normalize runs of ._- to '-'.
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    # NuGet package IDs are case-insensitive.
    if ecosystem == "NuGet":
        return name.lower()
    return name

def tokenize(version):
    """
    Loose cross-ecosystem comparator.

    This handles the majority of semver, PEP 440-like, NuGet, and Maven versions.
    Exact affected.versions matches are checked before range comparisons.
    """
    value = str(version).strip()
    if value.startswith(("v", "V")) and len(value) > 1 and value[1].isdigit():
        value = value[1:]

    value = value.replace("+", ".")
    parts = re.findall(r"\d+|[A-Za-z]+", value)

    rank = {
        "dev": -50,
        "snapshot": -40,
        "alpha": -30,
        "a": -30,
        "beta": -20,
        "b": -20,
        "milestone": -15,
        "m": -15,
        "rc": -10,
        "cr": -10,
        "pre": -10,
        "preview": -10,
        "final": 0,
        "ga": 0,
        "release": 0,
        "sp": 10,
        "post": 10,
    }

    result = []
    for part in parts:
        if part.isdigit():
            result.append((1, int(part)))
        else:
            low = part.lower()
            result.append((0, rank.get(low, 0), low))

    # Trim trailing numeric zeroes and neutral release words.
    while result and (
        result[-1] == (1, 0)
        or result[-1] in {(0, 0, "final"), (0, 0, "ga"), (0, 0, "release")}
    ):
        result.pop()

    return result

def compare_versions(left, right):
    a = tokenize(left)
    b = tokenize(right)
    length = max(len(a), len(b))

    for i in range(length):
        x = a[i] if i < len(a) else (1, 0)
        y = b[i] if i < len(b) else (1, 0)

        # Numeric vs textual token: prerelease text sorts before numeric release.
        if x[0] != y[0]:
            if x[0] == 0:
                return -1
            return 1

        if x < y:
            return -1
        if x > y:
            return 1

    return 0

def version_in_events(version, events):
    active = False

    for event in events:
        if "introduced" in event:
            introduced = str(event["introduced"])
            if introduced == "0" or compare_versions(version, introduced) >= 0:
                active = True

        if "fixed" in event and active:
            if compare_versions(version, str(event["fixed"])) >= 0:
                active = False

        if "last_affected" in event and active:
            if compare_versions(version, str(event["last_affected"])) > 0:
                active = False

        if "limit" in event and active:
            if compare_versions(version, str(event["limit"])) >= 0:
                active = False

    return active

def affected_version(version, advisory):
    exact = {str(v) for v in advisory.get("versions") or []}
    if str(version) in exact:
        return True

    for range_obj in advisory.get("ranges") or []:
        range_type = range_obj.get("type")
        if range_type not in {"ECOSYSTEM", "SEMVER"}:
            continue
        if version_in_events(str(version), range_obj.get("events") or []):
            return True

    return False

index = defaultdict(list)
with index_path.open(encoding="utf-8") as handle:
    for line in handle:
        if not line.strip():
            continue
        row = json.loads(line)
        key = (
            row["ecosystem"],
            normalize_package(row["ecosystem"], row["package"]),
        )
        index[key].append(row)

component_count = 0
finding_count = 0

with components_path.open(encoding="utf-8") as components, \
     findings_path.open("w", encoding="utf-8") as findings:

    for line in components:
        if not line.strip():
            continue

        component = json.loads(line)
        component_count += 1
        key = (
            component["ecosystem"],
            normalize_package(component["ecosystem"], component["package"]),
        )

        for advisory in index.get(key, []):
            if not affected_version(component["version"], advisory):
                continue

            finding = {
                "repository": component["repository"],
                "format": component["format"],
                "component_id": component["component_id"],
                "group": component["group"],
                "name": component["name"],
                "package": component["package"],
                "ecosystem": component["ecosystem"],
                "version": component["version"],
                "advisory_id": advisory["id"],
                "aliases": advisory.get("aliases") or [],
                "summary": advisory.get("summary") or "",
                "severity": advisory.get("severity") or "",
                "is_malware": bool(advisory.get("is_malware")),
                "category": advisory.get("category") or "",
                "source_file": advisory.get("source_file") or "",
            }
            findings.write(json.dumps(finding, separators=(",", ":"), ensure_ascii=False) + "\n")
            finding_count += 1

print(f"Matched {component_count} components; generated {finding_count} findings", file=sys.stderr)
PY
}

###############################################################################
# Scan Nexus repositories
###############################################################################

scan_repository() {
    local repository="$1"
    local format="$2"

    log "Scanning proxy repository: ${repository} (${format})"

    local continuation_token=""
    local page_number=0
    local repository_components=0
    local repository_assets=0

    while true; do
        page_number=$((page_number + 1))
        local response

        if [[ -n "$continuation_token" ]]; then
            response="$(
                nexus_curl \
                    --get \
                    --data-urlencode "repository=${repository}" \
                    --data-urlencode "continuationToken=${continuation_token}" \
                    "${NEXUS_URL%/}/service/rest/v1/components"
            )" || {
                record_error "Unable to list components: repository=${repository}, page=${page_number}"
                printf '%s\t%s\tfailed\t%s\t%s\t0\t0\n' \
                    "$repository" "$format" "$repository_components" "$repository_assets" \
                    >> "$REPOSITORIES_TSV"
                return 1
            }
        else
            response="$(
                nexus_curl \
                    --get \
                    --data-urlencode "repository=${repository}" \
                    "${NEXUS_URL%/}/service/rest/v1/components"
            )" || {
                record_error "Unable to list components: repository=${repository}, page=${page_number}"
                printf '%s\t%s\tfailed\t%s\t%s\t0\t0\n' \
                    "$repository" "$format" "$repository_components" "$repository_assets" \
                    >> "$REPOSITORIES_TSV"
                return 1
            }
        fi

        jq -e '(.items | type == "array")' <<< "$response" >/dev/null 2>&1 ||
            fatal "Invalid Nexus response: repository=${repository}, page=${page_number}"

        local page_item_count
        page_item_count="$(jq '.items | length' <<< "$response")"

        local component_json
        while IFS= read -r component_json; do
            [[ -n "$component_json" ]] || continue
            repository_components=$((repository_components + 1))

            local component_id
            component_id="$(jq -r '.id // ""' <<< "$component_json")"

            local asset_json
            while IFS= read -r asset_json; do
                [[ -n "$asset_json" ]] || continue
                repository_assets=$((repository_assets + 1))
                write_asset_csv "$repository" "$format" "$component_id" "$asset_json"
            done < <(jq -c '.assets[]?' <<< "$component_json")

            local prepared
            if prepared="$(prepare_component "$repository" "$format" "$component_json")"; then
                printf '%s\n' "$prepared" >> "$COMPONENTS_JSONL"
            fi
        done < <(jq -c '.items[]?' <<< "$response")

        continuation_token="$(jq -r '.continuationToken // empty' <<< "$response")"

        log "Repository progress: ${repository}, page=${page_number}, page_items=${page_item_count}, components=${repository_components}, assets=${repository_assets}"

        [[ -n "$continuation_token" ]] || break
    done

    printf '%s\t%s\tinventoried\t%s\t%s\t0\t0\n' \
        "$repository" "$format" "$repository_components" "$repository_assets" \
        >> "$REPOSITORIES_TSV"
}

###############################################################################
# Generate reports
###############################################################################

generate_reports() {
    # Build component summary CSV from complete inventory plus findings.
    python3 - "$COMPONENTS_JSONL" "$FINDINGS_JSONL" "$COMPONENTS_CSV" <<'PY'
import csv
import json
import sys
from collections import Counter
from pathlib import Path

components_path = Path(sys.argv[1])
findings_path = Path(sys.argv[2])
output_path = Path(sys.argv[3])

finding_counts = Counter()
malware_counts = Counter()

if findings_path.exists():
    with findings_path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            finding = json.loads(line)
            key = (finding["repository"], finding["component_id"])
            finding_counts[key] += 1
            if finding["is_malware"]:
                malware_counts[key] += 1

with components_path.open(encoding="utf-8") as components, \
     output_path.open("w", newline="", encoding="utf-8") as output:

    writer = csv.writer(output)
    writer.writerow([
        "repository", "format", "component_id", "group", "name", "version",
        "github_ecosystem", "github_package", "finding_count", "malware_count"
    ])

    for line in components:
        if not line.strip():
            continue
        c = json.loads(line)
        key = (c["repository"], c["component_id"])
        writer.writerow([
            c["repository"], c["format"], c["component_id"], c["group"],
            c["name"], c["version"], c["ecosystem"], c["package"],
            finding_counts[key], malware_counts[key]
        ])
PY

    # Vulnerability and malware TSV reports.
    while IFS= read -r finding; do
        [[ -n "$finding" ]] || continue

        local repository format package version advisory_id aliases severity summary is_malware
        repository="$(jq -r '.repository' <<< "$finding")"
        format="$(jq -r '.format' <<< "$finding")"
        package="$(jq -r '.package' <<< "$finding")"
        version="$(jq -r '.version' <<< "$finding")"
        advisory_id="$(jq -r '.advisory_id' <<< "$finding")"
        aliases="$(jq -r '(.aliases // []) | join(";")' <<< "$finding")"
        severity="$(jq -r '.severity // ""' <<< "$finding")"
        summary="$(jq -r '.summary // "" | gsub("[\\r\\n\\t]+"; " ")' <<< "$finding")"
        is_malware="$(jq -r '.is_malware' <<< "$finding")"

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$repository" "$format" "$package" "$version" "$advisory_id" \
            "$aliases" "$severity" "$summary" >> "$VULNERABILITIES_TSV"

        if [[ "$is_malware" == "true" ]]; then
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$repository" "$format" "$package" "$version" "$advisory_id" \
                "$aliases" "$summary" >> "$MALWARE_TSV"
        fi
    done < "$FINDINGS_JSONL"

    {
        printf 'count\trepository\n'
        awk -F'\t' '
            NR > 1 { count[$1]++ }
            END {
                for (repository in count) {
                    print count[repository] "\t" repository
                }
            }
        ' "$MALWARE_TSV" | sort -t $'\t' -k1,1nr -k2,2
    } > "$MALWARE_BY_REPOSITORY_TSV"

    # Replace inventory status rows with final counts.
    local updated="${TEMP_DIR}/repositories-final.tsv"
    head -n1 "$REPOSITORIES_TSV" > "$updated"

    tail -n +2 "$REPOSITORIES_TSV" |
    while IFS=$'\t' read -r repository format status components assets _ _; do
        local findings malware
        findings="$(
            awk -F'\t' -v repo="$repository" '
                NR > 1 && $1 == repo { count++ }
                END { print count + 0 }
            ' "$VULNERABILITIES_TSV"
        )"
        malware="$(
            awk -F'\t' -v repo="$repository" '
                NR > 1 && $1 == repo { count++ }
                END { print count + 0 }
            ' "$MALWARE_TSV"
        )"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$repository" "$format" "$status" "$components" "$assets" "$findings" "$malware" \
            >> "$updated"
    done
    mv "$updated" "$REPOSITORIES_TSV"

    local repository_count component_count asset_count finding_count malware_count error_count
    repository_count="$(awk 'NR>1{n++}END{print n+0}' "$REPOSITORIES_TSV")"
    component_count="$(wc -l < "$COMPONENTS_JSONL" | tr -d ' ')"
    asset_count="$(awk 'NR>1{n++}END{print n+0}' "$ASSETS_CSV")"
    finding_count="$(awk 'NR>1{n++}END{print n+0}' "$VULNERABILITIES_TSV")"
    malware_count="$(awk 'NR>1{n++}END{print n+0}' "$MALWARE_TSV")"
    error_count="$(wc -l < "$ERROR_LOG" | tr -d ' ')"

    {
        printf 'Nexus Repository CE scan using GitHub Advisory Database\n'
        printf 'Generated: %s\n' "$(date -u +%FT%TZ)"
        printf 'Nexus: %s\n' "$NEXUS_URL"
        printf 'Advisory archive SHA-256: %s\n' "$(cat "$GITHUB_ADVISORY_SOURCE_ID_FILE" 2>/dev/null || printf unknown)"
        printf 'Advisory categories: %s\n' "$ADVISORY_CATEGORIES"
        printf 'Selected formats: %s\n' "$SCAN_FORMATS"
        printf 'Repository regex: %s\n' "$SCAN_REPOSITORY_REGEX"
        printf '\nRepositories scanned: %s\n' "$repository_count"
        printf 'Components matched/indexed: %s\n' "$component_count"
        printf 'Assets inventoried: %s\n' "$asset_count"
        printf 'Vulnerability/malware findings: %s\n' "$finding_count"
        printf 'Malware findings: %s\n' "$malware_count"
        printf 'Errors: %s\n' "$error_count"
        printf '\nMalware findings by repository:\n'
        if (( malware_count == 0 )); then
            printf '  No GitHub malware advisories matched.\n'
        else
            awk -F'\t' 'NR>1{printf "  %s: %s\n",$2,$1}' "$MALWARE_BY_REPOSITORY_TSV"
        fi
        printf '\nImportant:\n'
        printf '  Vulnerability findings do not automatically mean malware.\n'
        printf '  GitHub malware advisories are currently concentrated in npm.\n'
        printf '  No finding does not prove that a repository is clean.\n'
        printf '  Version range matching is local and best-effort across ecosystems.\n'
    } > "$SUMMARY_FILE"
}

###############################################################################
# Main
###############################################################################

main() {
    initialize_reports
    validate_configuration
    sync_advisory_database
    build_advisory_index

    log "Retrieving Nexus repository inventory"
    local repositories
    repositories="$(nexus_curl "${NEXUS_URL%/}/service/rest/v1/repositories")" ||
        fatal "Unable to retrieve Nexus repository inventory"

    jq -e 'type == "array"' <<< "$repositories" >/dev/null 2>&1 ||
        fatal "Nexus repository inventory is not a JSON array"

    local total_proxy_count
    total_proxy_count="$(jq '[.[] | select(.type == "proxy")] | length' <<< "$repositories")"
    log "Found ${total_proxy_count} proxy repositories"

    local selected=0 repository format
    while IFS=$'\t' read -r repository format; do
        [[ -n "$repository" ]] || continue

        format_is_selected "$format" || {
            log "Skipping repository format: ${repository} (${format})"
            continue
        }

        # Exclude repository names that begin with:
        # rahyab, negah, iransign, or ekyc
        [[ ! "$repository" =~ ^(rahyab|negah|iransign|ekyc) ]] || {
            log "Skipping excluded repository: ${repository}"
            continue
        }

        [[ "$repository" =~ $SCAN_REPOSITORY_REGEX ]] || {
            log "Skipping repository by regex: ${repository}"
            continue
        }

        repository_is_selected "$repository" || {
            log "Skipping repository not in explicit list: ${repository}"
            continue
        }

        selected=$((selected + 1))
        scan_repository "$repository" "$format" || true
    done < <(
        jq -r '.[] | select(.type == "proxy") | [.name,.format] | @tsv' <<< "$repositories"
    )

    (( selected > 0 )) || record_error "No proxy repositories matched the configured filters"

    match_components
    generate_reports

    find "$TEMP_DIR" -type f -delete 2>/dev/null || true
    rmdir "$TEMP_DIR" 2>/dev/null || true

    log "Scan completed"
    printf '\nReports generated:\n'
    printf '  Summary:                %s\n' "$SUMMARY_FILE"
    printf '  Repository status:      %s\n' "$REPOSITORIES_TSV"
    printf '  Components:             %s\n' "$COMPONENTS_CSV"
    printf '  Assets and hashes:      %s\n' "$ASSETS_CSV"
    printf '  All finding details:    %s\n' "$FINDINGS_JSONL"
    printf '  Vulnerabilities:        %s\n' "$VULNERABILITIES_TSV"
    printf '  Malware:                %s\n' "$MALWARE_TSV"
    printf '  Malware by repository:  %s\n' "$MALWARE_BY_REPOSITORY_TSV"
    printf '  Errors:                 %s\n' "$ERROR_LOG"
}

main "$@"
