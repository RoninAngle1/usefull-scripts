#!/usr/bin/env bash

set -Eeuo pipefail

###############################################################################
# Nexus Repository CE proxy security scanner
#
# Open-source data source:
#   - OSV API
#
# Features:
#   - Discovers Nexus proxy repositories
#   - Filters repositories by format, regex, or explicit name
#   - Enumerates components and assets
#   - Records Nexus-provided checksums
#   - Queries OSV using batches
#   - Retries HTTP 403, 408, 425, 429, 5xx and connection failures
#   - Respects Retry-After headers
#   - Separates malware advisories from ordinary CVE/GHSA advisories
#   - Never deletes Nexus content
#
# Requirements:
#   bash
#   curl
#   jq
#   awk
#   sed
#   sort
#   cut
#   mktemp
#   find
###############################################################################

###############################################################################
# Nexus configuration
###############################################################################

NEXUS_URL="${NEXUS_URL:-https://nexus.example.com}"
NEXUS_USER="${NEXUS_USER:-scanner}"
NEXUS_PASSWORD="${NEXUS_PASSWORD:-}"

# Comma-separated Nexus formats.
#
# Recommended malware-focused scan:
#   npm,pypi
#
# Other supported mappings:
#   maven2,nuget,golang,rubygems,cargo,composer,cocoapods
SCAN_FORMATS="${SCAN_FORMATS:-npm,pypi}"

# Extended regular expression matched against repository names.
SCAN_REPOSITORY_REGEX="${SCAN_REPOSITORY_REGEX:-.*}"

# Optional comma-separated exact repository names.
#
# Example:
#   npm-proxy-org,pypi-proxy
#
# Empty means all repositories matching SCAN_FORMATS and regex.
SCAN_REPOSITORIES="${SCAN_REPOSITORIES:-}"

###############################################################################
# OSV configuration
###############################################################################

ENABLE_OSV="${ENABLE_OSV:-true}"

OSV_BATCH_URL="${OSV_BATCH_URL:-https://api.osv.dev/v1/querybatch}"

# Number of Nexus components in each OSV request.
OSV_BATCH_SIZE="${OSV_BATCH_SIZE:-100}"

OSV_MAX_RETRIES="${OSV_MAX_RETRIES:-10}"

# General retry delay.
OSV_RETRY_BASE_SECONDS="${OSV_RETRY_BASE_SECONDS:-10}"
OSV_RETRY_MAX_SECONDS="${OSV_RETRY_MAX_SECONDS:-300}"

# HTTP 403-specific cooldown.
OSV_403_BASE_COOLDOWN="${OSV_403_BASE_COOLDOWN:-120}"
OSV_403_MAX_COOLDOWN="${OSV_403_MAX_COOLDOWN:-900}"

# After this many consecutive 403 responses, stop calling OSV for this run.
# Unchecked components are written to failed-osv-queries.jsonl.
OSV_MAX_CONSECUTIVE_403="${OSV_MAX_CONSECUTIVE_403:-5}"

# Delay after a successful OSV request.
OSV_REQUEST_DELAY="${OSV_REQUEST_DELAY:-2}"

OSV_RESPECT_RETRY_AFTER="${OSV_RESPECT_RETRY_AFTER:-true}"

OSV_USER_AGENT="${OSV_USER_AGENT:-nexus-ce-security-scanner/2.1}"

###############################################################################
# HTTP configuration
###############################################################################

CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-30}"
REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-300}"

NEXUS_CURL_RETRIES="${NEXUS_CURL_RETRIES:-3}"

# Set true only when Nexus uses a self-signed certificate and the CA cannot be
# configured correctly.
INSECURE_TLS="${INSECURE_TLS:-false}"

###############################################################################
# Output configuration
###############################################################################

OUTPUT_ROOT="${OUTPUT_ROOT:-.}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUTPUT_DIR="${OUTPUT_DIR:-${OUTPUT_ROOT}/nexus-security-scan-${RUN_ID}}"

TEMP_DIR="${OUTPUT_DIR}/tmp"

REPOSITORIES_TSV="${OUTPUT_DIR}/repositories.tsv"
COMPONENTS_JSONL="${OUTPUT_DIR}/components.jsonl"
COMPONENTS_CSV="${OUTPUT_DIR}/components.csv"
ASSETS_CSV="${OUTPUT_DIR}/assets.csv"

OSV_RESULTS_JSONL="${OUTPUT_DIR}/osv-results.jsonl"
VULNERABILITIES_TSV="${OUTPUT_DIR}/vulnerabilities.tsv"
MALWARE_TSV="${OUTPUT_DIR}/malware.tsv"
MALWARE_BY_REPOSITORY_TSV="${OUTPUT_DIR}/malware-by-repository.tsv"

FAILED_OSV_QUERIES_JSONL="${OUTPUT_DIR}/failed-osv-queries.jsonl"
ERROR_LOG="${OUTPUT_DIR}/errors.log"
SUMMARY_FILE="${OUTPUT_DIR}/summary.txt"

###############################################################################
# Runtime state
###############################################################################

OSV_CONSECUTIVE_403=0
OSV_DISABLED_FOR_RUN=false

declare -a CURL_TLS_ARGS=()

if [[ "$INSECURE_TLS" == "true" ]]; then
    CURL_TLS_ARGS=(-k)
fi

###############################################################################
# Initialization
###############################################################################

initialize_reports() {
    mkdir -p "$OUTPUT_DIR" "$TEMP_DIR"

    : > "$COMPONENTS_JSONL"
    : > "$OSV_RESULTS_JSONL"
    : > "$FAILED_OSV_QUERIES_JSONL"
    : > "$ERROR_LOG"

    printf '%s\n' \
        $'repository\tformat\tstatus\tcomponents\tassets\tosv_findings\tmalware_findings' \
        > "$REPOSITORIES_TSV"

    printf '%s\n' \
        '"repository","format","component_id","group","name","version","osv_ecosystem","osv_package","osv_ids","osv_finding_count","malware_ids","malware_count"' \
        > "$COMPONENTS_CSV"

    printf '%s\n' \
        '"repository","format","component_id","asset_id","path","content_type","file_size","sha1","sha256","md5","download_url"' \
        > "$ASSETS_CSV"

    printf '%s\n' \
        $'repository\tformat\tpackage\tversion\tosv_id' \
        > "$VULNERABILITIES_TSV"

    printf '%s\n' \
        $'repository\tformat\tpackage\tversion\tmalware_id' \
        > "$MALWARE_TSV"

    printf '%s\n' \
        $'count\trepository' \
        > "$MALWARE_BY_REPOSITORY_TSV"
}

###############################################################################
# Logging and validation
###############################################################################

log() {
    printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" >&2
}

record_error() {
    local message="$*"

    printf '[%s] %s\n' \
        "$(date -u +%FT%TZ)" \
        "$message" \
        >> "$ERROR_LOG"

    log "ERROR: $message"
}

fatal() {
    record_error "$*"
    exit 1
}

require_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Required command is missing: %s\n' "$command_name" >&2
        exit 1
    fi
}

is_positive_integer() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && (( 10#$1 > 0 ))
}

validate_configuration() {
    local command_name

    for command_name in \
        bash curl jq awk sed sort cut mktemp tr wc find
    do
        require_command "$command_name"
    done

    [[ -n "$NEXUS_URL" ]] ||
        fatal "NEXUS_URL is empty"

    [[ -n "$NEXUS_USER" ]] ||
        fatal "NEXUS_USER is empty"

    [[ -n "$NEXUS_PASSWORD" ]] ||
        fatal "NEXUS_PASSWORD is empty"

    is_positive_integer "$OSV_BATCH_SIZE" ||
        fatal "OSV_BATCH_SIZE must be a positive integer"

    is_positive_integer "$OSV_MAX_RETRIES" ||
        fatal "OSV_MAX_RETRIES must be a positive integer"

    is_positive_integer "$OSV_RETRY_BASE_SECONDS" ||
        fatal "OSV_RETRY_BASE_SECONDS must be a positive integer"

    is_positive_integer "$OSV_RETRY_MAX_SECONDS" ||
        fatal "OSV_RETRY_MAX_SECONDS must be a positive integer"

    is_positive_integer "$OSV_403_BASE_COOLDOWN" ||
        fatal "OSV_403_BASE_COOLDOWN must be a positive integer"

    is_positive_integer "$OSV_403_MAX_COOLDOWN" ||
        fatal "OSV_403_MAX_COOLDOWN must be a positive integer"

    is_positive_integer "$OSV_MAX_CONSECUTIVE_403" ||
        fatal "OSV_MAX_CONSECUTIVE_403 must be a positive integer"

    if (( OSV_403_BASE_COOLDOWN > OSV_403_MAX_COOLDOWN )); then
        fatal "OSV_403_BASE_COOLDOWN cannot exceed OSV_403_MAX_COOLDOWN"
    fi
}

###############################################################################
# General helpers
###############################################################################

csv_escape() {
    local value="${1:-}"

    value="${value//$'\r'/ }"
    value="${value//$'\n'/ }"
    value="${value//\"/\"\"}"

    printf '"%s"' "$value"
}

contains_csv_value() {
    local csv="$1"
    local expected="$2"

    [[ ",${csv}," == *",${expected},"* ]]
}

format_is_selected() {
    local format="$1"

    contains_csv_value "$SCAN_FORMATS" "$format"
}

repository_is_selected() {
    local repository="$1"

    if [[ -z "$SCAN_REPOSITORIES" ]]; then
        return 0
    fi

    contains_csv_value "$SCAN_REPOSITORIES" "$repository"
}

calculate_exponential_delay() {
    local base="$1"
    local attempt="$2"
    local maximum="$3"

    local exponent=$((attempt - 1))
    local delay="$base"
    local i

    for ((i = 0; i < exponent; i++)); do
        delay=$((delay * 2))

        if (( delay >= maximum )); then
            delay="$maximum"
            break
        fi
    done

    if (( delay > maximum )); then
        delay="$maximum"
    fi

    awk -v delay="$delay" '
        BEGIN {
            srand()
            printf "%.2f", delay + (rand() * 3)
        }
    '
}

read_retry_after_seconds() {
    local header_file="$1"
    local retry_after=""

    retry_after="$(
        awk '
            BEGIN {
                IGNORECASE = 1
            }

            /^Retry-After:/ {
                sub(/\r$/, "", $0)
                sub(/^[^:]+:[[:space:]]*/, "", $0)
                value = $0
            }

            END {
                print value
            }
        ' "$header_file"
    )"

    if is_positive_integer "$retry_after"; then
        printf '%s\n' "$retry_after"
    else
        printf '\n'
    fi
}

response_preview() {
    local response_file="$1"

    if [[ ! -s "$response_file" ]]; then
        printf '<empty response>'
        return 0
    fi

    tr '\r\n' '  ' < "$response_file" |
        sed 's/[[:space:]][[:space:]]*/ /g' |
        cut -c1-1000
}

save_failed_batch() {
    local batch_file="$1"

    [[ -s "$batch_file" ]] || return 0

    jq -c '.' "$batch_file" >> "$FAILED_OSV_QUERIES_JSONL"
}

###############################################################################
# Nexus HTTP helper
###############################################################################

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

###############################################################################
# Nexus format to OSV ecosystem mapping
###############################################################################

map_to_osv() {
    local format="$1"
    local group="$2"
    local name="$3"

    case "$format" in
        npm)
            if [[ "$name" == @*/* ]]; then
                printf 'npm\t%s\n' "$name"
            elif [[ -n "$group" && "$group" != "null" ]]; then
                group="${group#@}"
                printf 'npm\t@%s/%s\n' "$group" "$name"
            else
                printf 'npm\t%s\n' "$name"
            fi
            ;;

        pypi)
            printf 'PyPI\t%s\n' "$name"
            ;;

        maven2)
            if [[ -n "$group" && "$group" != "null" ]]; then
                printf 'Maven\t%s:%s\n' "$group" "$name"
            else
                printf '\t\n'
            fi
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

        cocoapods)
            printf 'CocoaPods\t%s\n' "$name"
            ;;

        *)
            printf '\t\n'
            ;;
    esac
}

###############################################################################
# Nexus asset inventory
###############################################################################

write_asset_csv() {
    local repository="$1"
    local format="$2"
    local component_id="$3"
    local asset_json="$4"

    local asset_id
    local path
    local content_type
    local file_size
    local sha1
    local sha256
    local md5
    local download_url

    asset_id="$(jq -r '.id // ""' <<< "$asset_json")"
    path="$(jq -r '.path // ""' <<< "$asset_json")"
    content_type="$(jq -r '.contentType // ""' <<< "$asset_json")"
    file_size="$(jq -r '.fileSize // 0' <<< "$asset_json")"
    sha1="$(jq -r '.checksum.sha1 // ""' <<< "$asset_json")"
    sha256="$(jq -r '.checksum.sha256 // ""' <<< "$asset_json")"
    md5="$(jq -r '.checksum.md5 // ""' <<< "$asset_json")"
    download_url="$(jq -r '.downloadUrl // ""' <<< "$asset_json")"

    {
        csv_escape "$repository"
        printf ','

        csv_escape "$format"
        printf ','

        csv_escape "$component_id"
        printf ','

        csv_escape "$asset_id"
        printf ','

        csv_escape "$path"
        printf ','

        csv_escape "$content_type"
        printf ','

        csv_escape "$file_size"
        printf ','

        csv_escape "$sha1"
        printf ','

        csv_escape "$sha256"
        printf ','

        csv_escape "$md5"
        printf ','

        csv_escape "$download_url"
        printf '\n'
    } >> "$ASSETS_CSV"
}

###############################################################################
# Component preparation
###############################################################################

prepare_component() {
    local repository="$1"
    local format="$2"
    local component_json="$3"

    local component_id
    local group
    local name
    local version

    component_id="$(jq -r '.id // ""' <<< "$component_json")"
    group="$(jq -r '.group // ""' <<< "$component_json")"
    name="$(jq -r '.name // ""' <<< "$component_json")"
    version="$(jq -r '.version // ""' <<< "$component_json")"

    if [[ -z "$name" ||
          -z "$version" ||
          "$name" == "null" ||
          "$version" == "null" ]]; then
        return 1
    fi

    local mapping
    local ecosystem
    local package

    mapping="$(map_to_osv "$format" "$group" "$name")"
    ecosystem="$(cut -f1 <<< "$mapping")"
    package="$(cut -f2- <<< "$mapping")"

    if [[ -z "$ecosystem" || -z "$package" ]]; then
        return 1
    fi

    # Important:
    # Explicitly pass component_json to jq. Without this input, jq consumes
    # the stdin of the surrounding "while read" loop and skips the remaining
    # Nexus components on the current page.
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
# OSV result processing
###############################################################################

process_osv_result() {
    local component_json="$1"
    local result_json="$2"

    local repository
    local format
    local component_id
    local group
    local name
    local version
    local ecosystem
    local package

    repository="$(jq -r '.repository' <<< "$component_json")"
    format="$(jq -r '.format' <<< "$component_json")"
    component_id="$(jq -r '.component_id' <<< "$component_json")"
    group="$(jq -r '.group // ""' <<< "$component_json")"
    name="$(jq -r '.name' <<< "$component_json")"
    version="$(jq -r '.version' <<< "$component_json")"
    ecosystem="$(jq -r '.ecosystem' <<< "$component_json")"
    package="$(jq -r '.package' <<< "$component_json")"

    local osv_ids_json
    local malware_ids_json

    osv_ids_json="$(
        jq -c '
            [
                .vulns[]?.id
                | select(type == "string")
            ]
            | unique
        ' <<< "$result_json"
    )"

    malware_ids_json="$(
        jq -c '
            [
                .vulns[]?
                | select(
                    (
                        (.id // "") |
                        startswith("MAL-")
                    )
                    or
                    (
                        [
                            .aliases[]?,
                            .related[]?
                        ]
                        | any(
                            type == "string" and
                            startswith("MAL-")
                        )
                    )
                    or
                    (
                        .database_specific.malicious //
                        false
                    ) == true
                )
                | (
                    if (
                        (.id // "") |
                        startswith("MAL-")
                    )
                    then
                        .id
                    else
                        (
                            [
                                .aliases[]?,
                                .related[]?
                            ]
                            | map(
                                select(
                                    type == "string" and
                                    startswith("MAL-")
                                )
                            )
                            | first
                        ) // .id
                    end
                )
            ]
            | map(select(type == "string"))
            | unique
        ' <<< "$result_json"
    )"

    local osv_ids
    local malware_ids
    local finding_count
    local malware_count

    osv_ids="$(jq -r 'join(";")' <<< "$osv_ids_json")"
    malware_ids="$(jq -r 'join(";")' <<< "$malware_ids_json")"
    finding_count="$(jq -r 'length' <<< "$osv_ids_json")"
    malware_count="$(jq -r 'length' <<< "$malware_ids_json")"

    jq -cn \
        --arg repository "$repository" \
        --arg nexus_format "$format" \
        --arg component_id "$component_id" \
        --arg group "$group" \
        --arg name "$name" \
        --arg version "$version" \
        --arg ecosystem "$ecosystem" \
        --arg package "$package" \
        --argjson osv_ids "$osv_ids_json" \
        --argjson malware_ids "$malware_ids_json" \
        --argjson osv_result "$result_json" \
        '{
            repository: $repository,
            nexus_format: $nexus_format,
            component_id: $component_id,
            group: $group,
            name: $name,
            version: $version,
            ecosystem: $ecosystem,
            package: $package,
            osv_ids: $osv_ids,
            malware_ids: $malware_ids,
            finding_count: ($osv_ids | length),
            malware_count: ($malware_ids | length),
            osv_result: $osv_result
        }' >> "$OSV_RESULTS_JSONL"

    {
        csv_escape "$repository"
        printf ','

        csv_escape "$format"
        printf ','

        csv_escape "$component_id"
        printf ','

        csv_escape "$group"
        printf ','

        csv_escape "$name"
        printf ','

        csv_escape "$version"
        printf ','

        csv_escape "$ecosystem"
        printf ','

        csv_escape "$package"
        printf ','

        csv_escape "$osv_ids"
        printf ','

        csv_escape "$finding_count"
        printf ','

        csv_escape "$malware_ids"
        printf ','

        csv_escape "$malware_count"
        printf '\n'
    } >> "$COMPONENTS_CSV"

    while IFS= read -r osv_id; do
        [[ -n "$osv_id" ]] || continue

        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$repository" \
            "$format" \
            "$package" \
            "$version" \
            "$osv_id" \
            >> "$VULNERABILITIES_TSV"
    done < <(jq -r '.[]' <<< "$osv_ids_json")

    while IFS= read -r malware_id; do
        [[ -n "$malware_id" ]] || continue

        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$repository" \
            "$format" \
            "$package" \
            "$version" \
            "$malware_id" \
            >> "$MALWARE_TSV"
    done < <(jq -r '.[]' <<< "$malware_ids_json")
}

###############################################################################
# OSV batch query
###############################################################################

query_osv_batch() {
    local batch_file="$1"

    [[ -s "$batch_file" ]] || return 0

    if [[ "$ENABLE_OSV" != "true" ]]; then
        return 0
    fi

    if [[ "$OSV_DISABLED_FOR_RUN" == "true" ]]; then
        log "OSV disabled for this run; saving batch for later retry"
        save_failed_batch "$batch_file"
        return 1
    fi

    local payload_file
    local response_file
    local header_file
    local result_lines_file

    payload_file="$(mktemp "${TEMP_DIR}/osv-payload.XXXXXX")"
    response_file="$(mktemp "${TEMP_DIR}/osv-response.XXXXXX")"
    header_file="$(mktemp "${TEMP_DIR}/osv-headers.XXXXXX")"
    result_lines_file="$(mktemp "${TEMP_DIR}/osv-results.XXXXXX")"

    jq -s '
        {
            queries: map({
                package: {
                    ecosystem: .ecosystem,
                    name: .package
                },
                version: .version
            })
        }
    ' "$batch_file" > "$payload_file"

    local query_count
    query_count="$(jq '.queries | length' "$payload_file")"

    log "Submitting OSV batch: components=${query_count}"

    local attempt=1
    local http_code=""
    local curl_exit_code=0
    local success=false

    while (( attempt <= OSV_MAX_RETRIES )); do
        : > "$response_file"
        : > "$header_file"

        set +e

        http_code="$(
            curl \
                "${CURL_TLS_ARGS[@]}" \
                --silent \
                --show-error \
                --location \
                --connect-timeout "$CONNECT_TIMEOUT" \
                --max-time "$REQUEST_TIMEOUT" \
                --output "$response_file" \
                --dump-header "$header_file" \
                --write-out '%{http_code}' \
                --header 'Accept: application/json' \
                --header 'Content-Type: application/json' \
                --header "User-Agent: ${OSV_USER_AGENT}" \
                --data-binary "@${payload_file}" \
                "$OSV_BATCH_URL"
        )"

        curl_exit_code=$?

        set -e

        if (( curl_exit_code != 0 )); then
            http_code="000"
        fi

        case "$http_code" in
            200)
                if jq -e \
                    --argjson expected "$query_count" \
                    '
                    (.results | type == "array") and
                    ((.results | length) == $expected)
                    ' \
                    "$response_file" >/dev/null 2>&1
                then
                    success=true
                    OSV_CONSECUTIVE_403=0
                    break
                fi

                record_error \
                    "OSV returned invalid response; expected=${query_count}"

                local invalid_delay
                invalid_delay="$(
                    calculate_exponential_delay \
                        "$OSV_RETRY_BASE_SECONDS" \
                        "$attempt" \
                        "$OSV_RETRY_MAX_SECONDS"
                )"

                log "Retrying invalid OSV response in ${invalid_delay}s"
                sleep "$invalid_delay"
                ;;

            400)
                record_error \
                    "OSV rejected batch with HTTP 400: $(response_preview "$response_file")"

                save_failed_batch "$batch_file"

                rm -f \
                    "$payload_file" \
                    "$response_file" \
                    "$header_file" \
                    "$result_lines_file"

                return 1
                ;;

            401)
                record_error \
                    "OSV returned HTTP 401; check outbound proxy authentication: $(response_preview "$response_file")"

                save_failed_batch "$batch_file"

                rm -f \
                    "$payload_file" \
                    "$response_file" \
                    "$header_file" \
                    "$result_lines_file"

                return 1
                ;;

            403)
                OSV_CONSECUTIVE_403=$((OSV_CONSECUTIVE_403 + 1))

                local retry_after=""
                local cooldown=""

                if [[ "$OSV_RESPECT_RETRY_AFTER" == "true" ]]; then
                    retry_after="$(
                        read_retry_after_seconds "$header_file"
                    )"
                fi

                if [[ -n "$retry_after" ]]; then
                    cooldown="$retry_after"
                else
                    cooldown="$(
                        calculate_exponential_delay \
                            "$OSV_403_BASE_COOLDOWN" \
                            "$OSV_CONSECUTIVE_403" \
                            "$OSV_403_MAX_COOLDOWN"
                    )"
                fi

                record_error \
                    "OSV HTTP 403; consecutive=${OSV_CONSECUTIVE_403}/${OSV_MAX_CONSECUTIVE_403}; attempt=${attempt}/${OSV_MAX_RETRIES}; response=$(response_preview "$response_file")"

                if (( OSV_CONSECUTIVE_403 >= OSV_MAX_CONSECUTIVE_403 )); then
                    record_error \
                        "Too many consecutive OSV 403 responses; disabling OSV for remainder of run"

                    OSV_DISABLED_FOR_RUN=true
                    save_failed_batch "$batch_file"

                    rm -f \
                        "$payload_file" \
                        "$response_file" \
                        "$header_file" \
                        "$result_lines_file"

                    return 1
                fi

                log "OSV returned 403; retrying in ${cooldown}s"
                sleep "$cooldown"
                ;;

            408|425|429|500|502|503|504|000)
                local retry_after=""
                local delay=""

                if [[ "$OSV_RESPECT_RETRY_AFTER" == "true" ]]; then
                    retry_after="$(
                        read_retry_after_seconds "$header_file"
                    )"
                fi

                if [[ -n "$retry_after" ]]; then
                    delay="$retry_after"
                else
                    delay="$(
                        calculate_exponential_delay \
                            "$OSV_RETRY_BASE_SECONDS" \
                            "$attempt" \
                            "$OSV_RETRY_MAX_SECONDS"
                    )"
                fi

                log \
                    "OSV temporary failure HTTP=${http_code}, curl=${curl_exit_code}; attempt=${attempt}/${OSV_MAX_RETRIES}; retrying in ${delay}s"

                sleep "$delay"
                ;;

            *)
                record_error \
                    "OSV batch failed permanently: HTTP=${http_code}, curl=${curl_exit_code}, response=$(response_preview "$response_file")"

                save_failed_batch "$batch_file"

                rm -f \
                    "$payload_file" \
                    "$response_file" \
                    "$header_file" \
                    "$result_lines_file"

                return 1
                ;;
        esac

        attempt=$((attempt + 1))
    done

    if [[ "$success" != "true" ]]; then
        record_error \
            "OSV retries exhausted for batch containing ${query_count} components"

        save_failed_batch "$batch_file"

        rm -f \
            "$payload_file" \
            "$response_file" \
            "$header_file" \
            "$result_lines_file"

        return 1
    fi

    jq -c '.results[]' "$response_file" > "$result_lines_file"

    exec 3< "$batch_file"
    exec 4< "$result_lines_file"

    local component_json
    local result_json
    local alignment_error=false

    while IFS= read -r component_json <&3; do
        if ! IFS= read -r result_json <&4; then
            alignment_error=true
            record_error "OSV results became misaligned with input batch"
            break
        fi

        process_osv_result \
            "$component_json" \
            "$result_json"
    done

    exec 3<&-
    exec 4<&-

    if [[ "$alignment_error" == "true" ]]; then
        save_failed_batch "$batch_file"
    fi

    rm -f \
        "$payload_file" \
        "$response_file" \
        "$header_file" \
        "$result_lines_file"

    sleep "$OSV_REQUEST_DELAY"
}

###############################################################################
# Nexus repository scanning
###############################################################################

scan_repository() {
    local repository="$1"
    local format="$2"

    log "Scanning proxy repository: ${repository} (${format})"

    local continuation_token=""
    local page_number=0

    local repository_components=0
    local repository_assets=0

    # This batch persists across Nexus pages.
    local batch_file
    local batch_count=0

    batch_file="$(mktemp "${TEMP_DIR}/component-batch.XXXXXX")"

    while true; do
        page_number=$((page_number + 1))

        local response

        if [[ -n "$continuation_token" ]]; then
            if ! response="$(
                nexus_curl \
                    --get \
                    --data-urlencode "repository=${repository}" \
                    --data-urlencode "continuationToken=${continuation_token}" \
                    "${NEXUS_URL%/}/service/rest/v1/components"
            )"; then
                record_error \
                    "Unable to list components: repository=${repository}, page=${page_number}"

                if [[ -s "$batch_file" ]]; then
                    save_failed_batch "$batch_file"
                fi

                rm -f "$batch_file"

                printf '%s\t%s\tfailed\t%s\t%s\t0\t0\n' \
                    "$repository" \
                    "$format" \
                    "$repository_components" \
                    "$repository_assets" \
                    >> "$REPOSITORIES_TSV"

                return 1
            fi
        else
            if ! response="$(
                nexus_curl \
                    --get \
                    --data-urlencode "repository=${repository}" \
                    "${NEXUS_URL%/}/service/rest/v1/components"
            )"; then
                record_error \
                    "Unable to list components: repository=${repository}, page=${page_number}"

                if [[ -s "$batch_file" ]]; then
                    save_failed_batch "$batch_file"
                fi

                rm -f "$batch_file"

                printf '%s\t%s\tfailed\t%s\t%s\t0\t0\n' \
                    "$repository" \
                    "$format" \
                    "$repository_components" \
                    "$repository_assets" \
                    >> "$REPOSITORIES_TSV"

                return 1
            fi
        fi

        if ! jq -e \
            '(.items | type == "array")' \
            <<< "$response" >/dev/null 2>&1
        then
            record_error \
                "Invalid Nexus component response: repository=${repository}, page=${page_number}"

            if [[ -s "$batch_file" ]]; then
                save_failed_batch "$batch_file"
            fi

            rm -f "$batch_file"

            printf '%s\t%s\tfailed\t%s\t%s\t0\t0\n' \
                "$repository" \
                "$format" \
                "$repository_components" \
                "$repository_assets" \
                >> "$REPOSITORIES_TSV"

            return 1
        fi

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

                write_asset_csv \
                    "$repository" \
                    "$format" \
                    "$component_id" \
                    "$asset_json"
            done < <(jq -c '.assets[]?' <<< "$component_json")

            local prepared_component

            if ! prepared_component="$(
                prepare_component \
                    "$repository" \
                    "$format" \
                    "$component_json"
            )"; then
                continue
            fi

            printf '%s\n' \
                "$prepared_component" \
                >> "$COMPONENTS_JSONL"

            printf '%s\n' \
                "$prepared_component" \
                >> "$batch_file"

            batch_count=$((batch_count + 1))

            if (( batch_count >= OSV_BATCH_SIZE )); then
                query_osv_batch "$batch_file" || true

                : > "$batch_file"
                batch_count=0
            fi

        done < <(jq -c '.items[]?' <<< "$response")

        continuation_token="$(
            jq -r \
                '.continuationToken // empty' \
                <<< "$response"
        )"

        log \
            "Repository progress: ${repository}, page=${page_number}, page_items=${page_item_count}, components=${repository_components}, assets=${repository_assets}, pending_osv_batch=${batch_count}"

        [[ -n "$continuation_token" ]] || break
    done

    # Submit the final partial batch only after all Nexus pages are processed.
    if [[ -s "$batch_file" ]]; then
        query_osv_batch "$batch_file" || true
    fi

    rm -f "$batch_file"

    local repository_findings
    local repository_malware

    repository_findings="$(
        awk -F'\t' -v repository="$repository" '
            NR > 1 && $1 == repository {
                count++
            }

            END {
                print count + 0
            }
        ' "$VULNERABILITIES_TSV"
    )"

    repository_malware="$(
        awk -F'\t' -v repository="$repository" '
            NR > 1 && $1 == repository {
                count++
            }

            END {
                print count + 0
            }
        ' "$MALWARE_TSV"
    )"

    printf '%s\t%s\tcompleted\t%s\t%s\t%s\t%s\n' \
        "$repository" \
        "$format" \
        "$repository_components" \
        "$repository_assets" \
        "$repository_findings" \
        "$repository_malware" \
        >> "$REPOSITORIES_TSV"
}

###############################################################################
# Report generation
###############################################################################

generate_reports() {
    {
        printf 'count\trepository\n'

        awk -F'\t' '
            NR > 1 {
                count[$1]++
            }

            END {
                for (repository in count) {
                    print count[repository] "\t" repository
                }
            }
        ' "$MALWARE_TSV" |
            sort -t $'\t' -k1,1nr -k2,2
    } > "$MALWARE_BY_REPOSITORY_TSV"

    local repositories_selected
    local repositories_completed
    local repositories_failed
    local components_count
    local assets_count
    local vulnerability_count
    local malware_count
    local failed_osv_count
    local error_count

    repositories_selected="$(
        awk '
            NR > 1 {
                count++
            }

            END {
                print count + 0
            }
        ' "$REPOSITORIES_TSV"
    )"

    repositories_completed="$(
        awk -F'\t' '
            NR > 1 && $3 == "completed" {
                count++
            }

            END {
                print count + 0
            }
        ' "$REPOSITORIES_TSV"
    )"

    repositories_failed="$(
        awk -F'\t' '
            NR > 1 && $3 == "failed" {
                count++
            }

            END {
                print count + 0
            }
        ' "$REPOSITORIES_TSV"
    )"

    components_count="$(
        awk '
            END {
                print NR + 0
            }
        ' "$COMPONENTS_JSONL"
    )"

    assets_count="$(
        awk '
            NR > 1 {
                count++
            }

            END {
                print count + 0
            }
        ' "$ASSETS_CSV"
    )"

    vulnerability_count="$(
        awk '
            NR > 1 {
                count++
            }

            END {
                print count + 0
            }
        ' "$VULNERABILITIES_TSV"
    )"

    malware_count="$(
        awk '
            NR > 1 {
                count++
            }

            END {
                print count + 0
            }
        ' "$MALWARE_TSV"
    )"

    failed_osv_count="$(
        awk '
            END {
                print NR + 0
            }
        ' "$FAILED_OSV_QUERIES_JSONL"
    )"

    error_count="$(
        awk '
            END {
                print NR + 0
            }
        ' "$ERROR_LOG"
    )"

    {
        printf 'Nexus Repository CE security scan\n'
        printf 'Generated: %s\n' "$(date -u +%FT%TZ)"
        printf 'Nexus: %s\n' "$NEXUS_URL"
        printf 'Selected formats: %s\n' "$SCAN_FORMATS"
        printf 'Repository regex: %s\n' "$SCAN_REPOSITORY_REGEX"
        printf 'OSV batch size: %s\n' "$OSV_BATCH_SIZE"

        if [[ -n "$SCAN_REPOSITORIES" ]]; then
            printf 'Explicit repositories: %s\n' "$SCAN_REPOSITORIES"
        fi

        printf '\n'
        printf 'Repositories selected: %s\n' "$repositories_selected"
        printf 'Repositories completed: %s\n' "$repositories_completed"
        printf 'Repositories failed: %s\n' "$repositories_failed"
        printf 'Components mapped to OSV: %s\n' "$components_count"
        printf 'Assets inventoried: %s\n' "$assets_count"
        printf 'OSV advisory matches: %s\n' "$vulnerability_count"
        printf 'OSV malware matches: %s\n' "$malware_count"
        printf 'Failed/deferred OSV queries: %s\n' "$failed_osv_count"
        printf 'Recorded errors: %s\n' "$error_count"
        printf 'OSV disabled during run: %s\n' "$OSV_DISABLED_FOR_RUN"

        printf '\nMalware findings by Nexus repository:\n'

        if (( malware_count == 0 )); then
            printf '  No OSV malware records were found.\n'
        else
            awk -F'\t' '
                NR > 1 {
                    printf "  %s: %s\n", $2, $1
                }
            ' "$MALWARE_BY_REPOSITORY_TSV"
        fi

        printf '\nInterpretation:\n'
        printf '  CVE/GHSA records indicate vulnerabilities, not necessarily malware.\n'
        printf '  malware.tsv contains MAL-* or explicitly malicious OSV records.\n'
        printf '  Empty malware results do not prove that a repository is clean.\n'
        printf '  Sonatype may use proprietary malware intelligence unavailable in OSV.\n'

        if (( failed_osv_count > 0 )); then
            printf '  Some components were not checked because OSV requests failed.\n'
        fi
    } > "$SUMMARY_FILE"
}

###############################################################################
# Main
###############################################################################

main() {
    initialize_reports
    validate_configuration

    log "Retrieving Nexus repository inventory"

    local repositories

    if ! repositories="$(
        nexus_curl \
            "${NEXUS_URL%/}/service/rest/v1/repositories"
    )"; then
        fatal "Unable to retrieve Nexus repository inventory"
    fi

    if ! jq -e \
        'type == "array"' \
        <<< "$repositories" >/dev/null 2>&1
    then
        fatal "Nexus repository inventory is not a JSON array"
    fi

    local total_proxy_count

    total_proxy_count="$(
        jq '
            [
                .[] |
                select(.type == "proxy")
            ] |
            length
        ' <<< "$repositories"
    )"

    log "Found ${total_proxy_count} proxy repositories"

    local selected_count=0
    local repository
    local format

    while IFS=$'\t' read -r repository format; do
        [[ -n "$repository" ]] || continue

        if ! format_is_selected "$format"; then
            log "Skipping repository format: ${repository} (${format})"
            continue
        fi

        if [[ ! "$repository" =~ $SCAN_REPOSITORY_REGEX ]]; then
            log "Skipping repository by regex: ${repository} (${format})"
            continue
        fi

        if ! repository_is_selected "$repository"; then
            log "Skipping repository not in explicit list: ${repository}"
            continue
        fi

        selected_count=$((selected_count + 1))

        scan_repository "$repository" "$format" || true

    done < <(
        jq -r '
            .[] |
            select(.type == "proxy") |
            [
                .name,
                .format
            ] |
            @tsv
        ' <<< "$repositories"
    )

    if (( selected_count == 0 )); then
        record_error "No proxy repositories matched the configured filters"
    fi

    generate_reports

    find "$TEMP_DIR" -type f -delete 2>/dev/null || true
    rmdir "$TEMP_DIR" 2>/dev/null || true

    log "Scan completed"

    printf '\nReports generated:\n'
    printf '  Summary:                 %s\n' "$SUMMARY_FILE"
    printf '  Repository status:       %s\n' "$REPOSITORIES_TSV"
    printf '  Components:              %s\n' "$COMPONENTS_CSV"
    printf '  Component source JSONL:  %s\n' "$COMPONENTS_JSONL"
    printf '  Asset hashes:            %s\n' "$ASSETS_CSV"
    printf '  OSV result details:      %s\n' "$OSV_RESULTS_JSONL"
    printf '  Vulnerabilities:         %s\n' "$VULNERABILITIES_TSV"
    printf '  Malware packages:        %s\n' "$MALWARE_TSV"
    printf '  Malware by repository:   %s\n' \
        "$MALWARE_BY_REPOSITORY_TSV"
    printf '  Failed OSV queries:      %s\n' \
        "$FAILED_OSV_QUERIES_JSONL"
    printf '  Errors:                  %s\n' "$ERROR_LOG"
}

main "$@"
