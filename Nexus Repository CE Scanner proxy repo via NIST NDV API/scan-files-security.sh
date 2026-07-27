```bash
#!/usr/bin/env bash

set -Eeuo pipefail

# ==============================================================================
# File Malware and NIST NVD CVE Scanner
#
# This script:
#   1. Iterates over regular files in the current directory.
#   2. Calculates a SHA-256 checksum for every file.
#   3. Detects the file type.
#   4. Scans the file with ClamAV when clamscan is installed.
#   5. Extracts CVE identifiers from the filename and readable file content.
#   6. Queries the NIST NVD CVE API for discovered CVE identifiers.
#   7. Optionally searches NVD using the filename as a keyword.
#   8. Creates text, CSV and JSON reports.
#
# The script NEVER deletes, moves, quarantines, renames or modifies scanned files.
# ==============================================================================

readonly NVD_API_BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"

SCAN_DIRECTORY="${SCAN_DIRECTORY:-.}"
REPORT_DIRECTORY="${REPORT_DIRECTORY:-./security-scan-reports}"

# Optional NIST NVD API key.
#
# Export it before running:
#
#   export NVD_API_KEY="your-api-key"
#
NVD_API_KEY="${NVD_API_KEY:-}"

# Set to 1 to search NVD using sanitized filenames.
#
# Filename searches can produce false positives because a filename does not
# reliably identify the product or version contained in a file.
NVD_KEYWORD_LOOKUP="${NVD_KEYWORD_LOOKUP:-0}"

# Maximum number of CVEs recorded from a filename keyword search.
NVD_KEYWORD_LIMIT="${NVD_KEYWORD_LIMIT:-10}"

# Maximum amount of readable file content inspected for embedded CVE IDs.
# This does not limit the ClamAV scan.
CONTENT_SCAN_BYTES="${CONTENT_SCAN_BYTES:-10485760}"

# Skip files larger than this value when searching their content for CVE IDs.
# ClamAV still scans them.
MAX_CONTENT_INSPECTION_BYTES="${MAX_CONTENT_INSPECTION_BYTES:-104857600}"

# NVD recommends spacing automated requests.
#
# Without an API key, use at least six seconds.
# With an API key, the default below uses one second.
if [[ -n "$NVD_API_KEY" ]]; then
    NVD_REQUEST_DELAY="${NVD_REQUEST_DELAY:-1}"
else
    NVD_REQUEST_DELAY="${NVD_REQUEST_DELAY:-6}"
fi

TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"

TEXT_REPORT="${REPORT_DIRECTORY}/security-scan-${TIMESTAMP}.txt"
CSV_REPORT="${REPORT_DIRECTORY}/security-scan-${TIMESTAMP}.csv"
JSON_REPORT="${REPORT_DIRECTORY}/security-scan-${TIMESTAMP}.json"
NVD_CACHE_DIRECTORY="${REPORT_DIRECTORY}/nvd-cache"

TEMP_DIRECTORY=""

declare -A QUERIED_CVES=()

FILES_SCANNED=0
MALWARE_DETECTIONS=0
CVE_REFERENCES_FOUND=0
NVD_ERRORS=0
KEYWORD_MATCHES=0

log()
{
    local message="$1"

    printf '[%s] %s\n' "$(date '+%F %T')" "$message" |
        tee -a "$TEXT_REPORT"
}

warn()
{
    local message="$1"

    printf '[%s] WARNING: %s\n' "$(date '+%F %T')" "$message" |
        tee -a "$TEXT_REPORT" >&2
}

fatal()
{
    local message="$1"

    printf '[%s] ERROR: %s\n' "$(date '+%F %T')" "$message" |
        tee -a "$TEXT_REPORT" >&2

    exit 1
}

command_exists()
{
    command -v "$1" >/dev/null 2>&1
}

cleanup()
{
    if [[ -n "$TEMP_DIRECTORY" && -d "$TEMP_DIRECTORY" ]]; then
        rm -rf -- "$TEMP_DIRECTORY"
    fi
}

trap cleanup EXIT
trap 'fatal "Interrupted while scanning."' INT TERM

csv_escape()
{
    local value="${1:-}"

    value="${value//$'\r'/ }"
    value="${value//$'\n'/ }"
    value="${value//\"/\"\"}"

    printf '"%s"' "$value"
}

json_escape()
{
    local value="${1:-}"

    if command_exists jq; then
        jq -Rn --arg value "$value" '$value'
        return
    fi

    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"

    printf '"%s"' "$value"
}

url_encode()
{
    local value="$1"

    jq -rn --arg value "$value" '$value | @uri'
}

safe_cache_name()
{
    local value="$1"

    printf '%s' "$value" |
        tr '[:lower:]' '[:upper:]' |
        tr -cd 'A-Z0-9._-'
}

get_file_size()
{
    local file="$1"

    if stat --version >/dev/null 2>&1; then
        stat -c '%s' -- "$file"
    else
        stat -f '%z' -- "$file"
    fi
}

get_sha256()
{
    local file="$1"

    if command_exists sha256sum; then
        sha256sum -- "$file" | awk '{print $1}'
    elif command_exists shasum; then
        shasum -a 256 -- "$file" | awk '{print $1}'
    else
        printf 'unavailable'
    fi
}

get_file_type()
{
    local file="$1"

    if command_exists file; then
        file --brief --mime-type -- "$file" 2>/dev/null || printf 'unknown'
    else
        printf 'unknown'
    fi
}

nvd_request()
{
    local url="$1"
    local output_file="$2"
    local http_code
    local curl_arguments=(
        --silent
        --show-error
        --location
        --connect-timeout 15
        --max-time 90
        --retry 3
        --retry-delay 3
        --retry-all-errors
        --output "$output_file"
        --write-out '%{http_code}'
        --header 'Accept: application/json'
        --user-agent 'local-file-security-scanner/1.0'
    )

    if [[ -n "$NVD_API_KEY" ]]; then
        curl_arguments+=(--header "apiKey: ${NVD_API_KEY}")
    fi

    http_code="$(curl "${curl_arguments[@]}" "$url")" || {
        NVD_ERRORS=$((NVD_ERRORS + 1))
        return 1
    }

    case "$http_code" in
        200)
            sleep "$NVD_REQUEST_DELAY"
            return 0
            ;;

        403)
            warn "NVD returned HTTP 403. Check the API key or request rate."
            ;;

        404)
            warn "NVD returned HTTP 404 for: $url"
            ;;

        429)
            warn "NVD rate limit reached. Increase NVD_REQUEST_DELAY."
            ;;

        *)
            warn "NVD request failed with HTTP ${http_code}: $url"
            ;;
    esac

    NVD_ERRORS=$((NVD_ERRORS + 1))
    sleep "$NVD_REQUEST_DELAY"

    return 1
}

get_cvss_details()
{
    local json_file="$1"

    jq -r '
        .vulnerabilities[0].cve.metrics as $metrics
        |
        if ($metrics.cvssMetricV40 // [] | length) > 0 then
            [
                $metrics.cvssMetricV40[0].cvssData.baseScore,
                $metrics.cvssMetricV40[0].cvssData.baseSeverity,
                $metrics.cvssMetricV40[0].cvssData.vectorString,
                "CVSS 4.0"
            ]
        elif ($metrics.cvssMetricV31 // [] | length) > 0 then
            [
                $metrics.cvssMetricV31[0].cvssData.baseScore,
                $metrics.cvssMetricV31[0].cvssData.baseSeverity,
                $metrics.cvssMetricV31[0].cvssData.vectorString,
                "CVSS 3.1"
            ]
        elif ($metrics.cvssMetricV30 // [] | length) > 0 then
            [
                $metrics.cvssMetricV30[0].cvssData.baseScore,
                $metrics.cvssMetricV30[0].cvssData.baseSeverity,
                $metrics.cvssMetricV30[0].cvssData.vectorString,
                "CVSS 3.0"
            ]
        elif ($metrics.cvssMetricV2 // [] | length) > 0 then
            [
                $metrics.cvssMetricV2[0].cvssData.baseScore,
                ($metrics.cvssMetricV2[0].baseSeverity // "UNKNOWN"),
                $metrics.cvssMetricV2[0].cvssData.vectorString,
                "CVSS 2.0"
            ]
        else
            ["", "UNKNOWN", "", "Unavailable"]
        end
        | @tsv
    ' "$json_file"
}

query_cve()
{
    local cve_id="$1"
    local source_file="$2"
    local detection_method="$3"

    local normalized_cve
    local cache_file
    local url
    local description
    local published
    local modified
    local status
    local cvss_score
    local severity
    local vector
    local cvss_version
    local weakness
    local references
    local cvss_details

    normalized_cve="$(printf '%s' "$cve_id" | tr '[:lower:]' '[:upper:]')"

    if [[ -n "${QUERIED_CVES[$normalized_cve]:-}" ]]; then
        log "CVE already queried during this run: ${normalized_cve}"
        return
    fi

    QUERIED_CVES["$normalized_cve"]=1
    CVE_REFERENCES_FOUND=$((CVE_REFERENCES_FOUND + 1))

    cache_file="${NVD_CACHE_DIRECTORY}/$(safe_cache_name "$normalized_cve").json"
    url="${NVD_API_BASE}?cveId=${normalized_cve}"

    log "Querying NIST NVD for ${normalized_cve}"

    if [[ ! -s "$cache_file" ]]; then
        if ! nvd_request "$url" "$cache_file"; then
            warn "Unable to retrieve ${normalized_cve} from NVD."
            return
        fi
    fi

    if ! jq -e '.vulnerabilities | type == "array"' "$cache_file" >/dev/null 2>&1; then
        warn "Invalid NVD response for ${normalized_cve}."
        return
    fi

    if [[ "$(jq -r '.totalResults // 0' "$cache_file")" -eq 0 ]]; then
        warn "No NVD record found for ${normalized_cve}."
        return
    fi

    description="$(
        jq -r '
            .vulnerabilities[0].cve.descriptions
            | (
                map(select(.lang == "en"))[0].value
                // .[0].value
                // "No description available"
            )
        ' "$cache_file"
    )"

    published="$(
        jq -r '.vulnerabilities[0].cve.published // "unknown"' "$cache_file"
    )"

    modified="$(
        jq -r '.vulnerabilities[0].cve.lastModified // "unknown"' "$cache_file"
    )"

    status="$(
        jq -r '.vulnerabilities[0].cve.vulnStatus // "unknown"' "$cache_file"
    )"

    weakness="$(
        jq -r '
            [
                .vulnerabilities[0].cve.weaknesses[]?
                .description[]?
                | select(.lang == "en")
                | .value
            ]
            | unique
            | join("; ")
        ' "$cache_file"
    )"

    references="$(
        jq -r '
            [
                .vulnerabilities[0].cve.references[]?.url
            ][0:5]
            | join(" | ")
        ' "$cache_file"
    )"

    cvss_details="$(get_cvss_details "$cache_file")"

    IFS=$'\t' read -r \
        cvss_score \
        severity \
        vector \
        cvss_version <<< "$cvss_details"

    {
        printf '\n'
        printf 'CVE: %s\n' "$normalized_cve"
        printf 'Source file: %s\n' "$source_file"
        printf 'Detection method: %s\n' "$detection_method"
        printf 'Status: %s\n' "$status"
        printf 'Published: %s\n' "$published"
        printf 'Last modified: %s\n' "$modified"
        printf 'CVSS version: %s\n' "$cvss_version"
        printf 'CVSS score: %s\n' "${cvss_score:-unavailable}"
        printf 'Severity: %s\n' "${severity:-UNKNOWN}"
        printf 'Vector: %s\n' "${vector:-unavailable}"
        printf 'Weakness: %s\n' "${weakness:-unavailable}"
        printf 'Description: %s\n' "$description"
        printf 'References: %s\n' "${references:-unavailable}"
        printf '%s\n' '------------------------------------------------------------------'
    } >> "$TEXT_REPORT"

    {
        csv_escape "$source_file"
        printf ','
        csv_escape "CVE"
        printf ','
        csv_escape "$normalized_cve"
        printf ','
        csv_escape "${severity:-UNKNOWN}"
        printf ','
        csv_escape "${cvss_score:-}"
        printf ','
        csv_escape "$status"
        printf ','
        csv_escape "$detection_method"
        printf ','
        csv_escape "$description"
        printf '\n'
    } >> "$CSV_REPORT"
}

extract_cves()
{
    local file="$1"
    local file_size="$2"
    local cve_output="$3"

    : > "$cve_output"

    printf '%s\n' "$file" |
        grep -Eio 'CVE-[0-9]{4}-[0-9]{4,}' \
        >> "$cve_output" || true

    if (( file_size <= MAX_CONTENT_INSPECTION_BYTES )); then
        if command_exists strings; then
            strings -a -n 4 -- "$file" 2>/dev/null |
                head -c "$CONTENT_SCAN_BYTES" |
                grep -Eio 'CVE-[0-9]{4}-[0-9]{4,}' \
                >> "$cve_output" || true
        else
            head -c "$CONTENT_SCAN_BYTES" -- "$file" 2>/dev/null |
                grep -aEio 'CVE-[0-9]{4}-[0-9]{4,}' \
                >> "$cve_output" || true
        fi
    fi

    tr '[:lower:]' '[:upper:]' < "$cve_output" |
        sort -u > "${cve_output}.sorted"

    mv -- "${cve_output}.sorted" "$cve_output"
}

scan_with_clamav()
{
    local file="$1"
    local scan_output
    local exit_code
    local malware_name

    if ! command_exists clamscan; then
        printf 'NOT_AVAILABLE\tClamAV is not installed'
        return
    fi

    set +e
    scan_output="$(
        clamscan \
            --infected \
            --no-summary \
            -- "$file" 2>&1
    )"
    exit_code=$?
    set -e

    case "$exit_code" in
        0)
            printf 'CLEAN\tNo malware detected'
            ;;

        1)
            malware_name="$(
                printf '%s\n' "$scan_output" |
                    sed -n 's/^.*: \(.*\) FOUND$/\1/p' |
                    head -n 1
            )"

            MALWARE_DETECTIONS=$((MALWARE_DETECTIONS + 1))

            printf 'INFECTED\t%s' "${malware_name:-Malware detected}"
            ;;

        *)
            scan_output="$(
                printf '%s' "$scan_output" |
                    tr '\r\n' '  ' |
                    sed 's/[[:space:]][[:space:]]*/ /g'
            )"

            printf 'ERROR\t%s' "${scan_output:-ClamAV scan failed}"
            ;;
    esac
}

sanitize_filename_keyword()
{
    local filename="$1"
    local keyword

    keyword="${filename##*/}"

    keyword="$(
        printf '%s' "$keyword" |
            sed -E '
                s/\.(tar\.gz|tar\.bz2|tar\.xz|tgz|zip|gz|bz2|xz|rpm|deb|jar|war|ear|exe|dll|so|bin|txt|log|csv|json|yaml|yml)$//I;
                s/[_+.:-]+/ /g;
                s/[[:space:]]+/ /g;
                s/^[[:space:]]+//;
                s/[[:space:]]+$//;
            '
    )"

    printf '%s' "$keyword"
}

query_filename_keyword()
{
    local file="$1"
    local keyword
    local encoded_keyword
    local response_file
    local total_results
    local result_count
    local index
    local cve_id

    keyword="$(sanitize_filename_keyword "$file")"

    if [[ ${#keyword} -lt 4 ]]; then
        log "Skipping NVD keyword search for short filename keyword: $keyword"
        return
    fi

    encoded_keyword="$(url_encode "$keyword")"
    response_file="${TEMP_DIRECTORY}/keyword-$RANDOM.json"

    log "Searching NIST NVD using filename keyword: ${keyword}"

    if ! nvd_request \
        "${NVD_API_BASE}?keywordSearch=${encoded_keyword}&resultsPerPage=${NVD_KEYWORD_LIMIT}" \
        "$response_file"; then
        return
    fi

    total_results="$(jq -r '.totalResults // 0' "$response_file")"
    result_count="$(jq -r '.vulnerabilities | length' "$response_file")"

    {
        printf '\n'
        printf 'NVD filename keyword search\n'
        printf 'File: %s\n' "$file"
        printf 'Keyword: %s\n' "$keyword"
        printf 'Total NVD matches: %s\n' "$total_results"
        printf 'Recorded matches: %s\n' "$result_count"
        printf 'Important: keyword matches are candidates, not proof that the file is vulnerable.\n'
    } >> "$TEXT_REPORT"

    for ((index = 0; index < result_count; index++)); do
        cve_id="$(
            jq -r \
                --argjson index "$index" \
                '.vulnerabilities[$index].cve.id' \
                "$response_file"
        )"

        [[ "$cve_id" == CVE-* ]] || continue

        KEYWORD_MATCHES=$((KEYWORD_MATCHES + 1))
        query_cve "$cve_id" "$file" "filename-keyword:${keyword}"
    done
}

initialize_reports()
{
    mkdir -p -- "$REPORT_DIRECTORY" "$NVD_CACHE_DIRECTORY"

    TEMP_DIRECTORY="$(mktemp -d)"

    {
        printf 'File Malware and NIST NVD CVE Scan\n'
        printf 'Started: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
        printf 'Scan directory: %s\n' "$SCAN_DIRECTORY"
        printf 'ClamAV available: '

        if command_exists clamscan; then
            printf 'yes\n'
        else
            printf 'no\n'
        fi

        printf 'NVD API key configured: '

        if [[ -n "$NVD_API_KEY" ]]; then
            printf 'yes\n'
        else
            printf 'no\n'
        fi

        printf 'Filename keyword lookup: %s\n' "$NVD_KEYWORD_LOOKUP"
        printf '%s\n' '=================================================================='
    } > "$TEXT_REPORT"

    printf '%s\n' \
        '"file","record_type","identifier","severity","score","status","detection_method","description"' \
        > "$CSV_REPORT"

    printf '[]\n' > "$JSON_REPORT"
}

validate_requirements()
{
    command_exists curl ||
        fatal "Required command not found: curl"

    command_exists jq ||
        fatal "Required command not found: jq"

    command_exists grep ||
        fatal "Required command not found: grep"

    command_exists tar ||
        warn "tar is not installed, but it is not required for scanning."

    [[ -d "$SCAN_DIRECTORY" ]] ||
        fatal "Scan directory does not exist: $SCAN_DIRECTORY"

    [[ "$NVD_KEYWORD_LOOKUP" =~ ^[01]$ ]] ||
        fatal "NVD_KEYWORD_LOOKUP must be 0 or 1."

    [[ "$NVD_KEYWORD_LIMIT" =~ ^[0-9]+$ ]] ||
        fatal "NVD_KEYWORD_LIMIT must be a positive integer."
}

scan_file()
{
    local file="$1"
    local base
    local file_size
    local file_hash
    local file_type
    local malware_status
    local malware_details
    local clamav_result
    local cve_file
    local cve_id

    base="${file##*/}"
    file_size="$(get_file_size "$file")"
    file_hash="$(get_sha256 "$file")"
    file_type="$(get_file_type "$file")"

    FILES_SCANNED=$((FILES_SCANNED + 1))

    log "Scanning file: $file"

    clamav_result="$(scan_with_clamav "$file")"

    IFS=$'\t' read -r \
        malware_status \
        malware_details <<< "$clamav_result"

    {
        printf '\n'
        printf 'File: %s\n' "$file"
        printf 'Size: %s bytes\n' "$file_size"
        printf 'Type: %s\n' "$file_type"
        printf 'SHA-256: %s\n' "$file_hash"
        printf 'Malware status: %s\n' "$malware_status"
        printf 'Malware details: %s\n' "$malware_details"
        printf '%s\n' '------------------------------------------------------------------'
    } >> "$TEXT_REPORT"

    {
        csv_escape "$file"
        printf ','
        csv_escape "MALWARE"
        printf ','
        csv_escape "$file_hash"
        printf ','
        csv_escape ""
        printf ','
        csv_escape ""
        printf ','
        csv_escape "$malware_status"
        printf ','
        csv_escape "ClamAV"
        printf ','
        csv_escape "$malware_details"
        printf '\n'
    } >> "$CSV_REPORT"

    jq \
        --arg file "$file" \
        --arg filename "$base" \
        --argjson size "$file_size" \
        --arg type "$file_type" \
        --arg sha256 "$file_hash" \
        --arg malwareStatus "$malware_status" \
        --arg malwareDetails "$malware_details" \
        '. += [{
            file: $file,
            filename: $filename,
            sizeBytes: $size,
            mimeType: $type,
            sha256: $sha256,
            malware: {
                scanner: "ClamAV",
                status: $malwareStatus,
                details: $malwareDetails
            }
        }]' \
        "$JSON_REPORT" > "${JSON_REPORT}.tmp"

    mv -- "${JSON_REPORT}.tmp" "$JSON_REPORT"

    cve_file="${TEMP_DIRECTORY}/cves-$FILES_SCANNED.txt"

    extract_cves "$file" "$file_size" "$cve_file"

    if [[ -s "$cve_file" ]]; then
        while IFS= read -r cve_id; do
            [[ -n "$cve_id" ]] || continue

            query_cve "$cve_id" "$file" "embedded-cve-reference"
        done < "$cve_file"
    else
        log "No embedded CVE identifiers found in: $file"
    fi

    if [[ "$NVD_KEYWORD_LOOKUP" == "1" ]]; then
        query_filename_keyword "$file"
    fi
}

main()
{
    local file
    local report_real_path=""

    initialize_reports
    validate_requirements

    log "Starting non-destructive security scan."
    log "No files will be deleted, moved or modified."

    if command_exists realpath; then
        report_real_path="$(realpath -m "$REPORT_DIRECTORY")"
    fi

    while IFS= read -r -d '' file; do
        if [[ -n "$report_real_path" ]] && command_exists realpath; then
            case "$(realpath -m "$file")" in
                "$report_real_path"/*)
                    continue
                    ;;
            esac
        fi

        scan_file "$file"
    done < <(
        find "$SCAN_DIRECTORY" \
            -maxdepth 1 \
            -type f \
            -print0
    )

    {
        printf '\n'
        printf '%s\n' '=================================================================='
        printf 'Scan summary\n'
        printf 'Completed: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
        printf 'Files scanned: %d\n' "$FILES_SCANNED"
        printf 'Malware detections: %d\n' "$MALWARE_DETECTIONS"
        printf 'Unique CVE records queried: %d\n' "${#QUERIED_CVES[@]}"
        printf 'CVE references found: %d\n' "$CVE_REFERENCES_FOUND"
        printf 'Filename keyword matches: %d\n' "$KEYWORD_MATCHES"
        printf 'NVD request errors: %d\n' "$NVD_ERRORS"
        printf 'Files deleted: 0\n'
        printf 'Files modified: 0\n'
    } | tee -a "$TEXT_REPORT"

    printf '\nReports:\n'
    printf '  Text: %s\n' "$TEXT_REPORT"
    printf '  CSV:  %s\n' "$CSV_REPORT"
    printf '  JSON: %s\n' "$JSON_REPORT"

    if (( MALWARE_DETECTIONS > 0 )); then
        exit 2
    fi

    if (( NVD_ERRORS > 0 )); then
        exit 3
    fi
}

main "$@"
```
