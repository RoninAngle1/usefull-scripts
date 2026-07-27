#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

###############################################################################
# Mirror images listed by the Kubernetes node-image collector into Harbor.
#
# Supported input format:
#
#   source_image image_name version digest nodes
#
# Columns may be separated by spaces or tabs.
#
# Example:
#
# docker.io/grafana/grafana:11.6.1 docker.io/grafana/grafana 11.6.1 sha256:abc... ec-wrk-02
# docker.io/library/nginx:1.25.2-alpine docker.io/library/nginx 1.25.2-alpine UNKNOWN ec-wrk-01,ec-wrk-02
#
# Requirements:
#
#   skopeo
#   awk
#   sed
#   flock
#
# Usage:
#
#   ./mirror-images-to-harbor.sh images.txt
###############################################################################

###############################################################################
# Input
###############################################################################

INVENTORY_FILE="${1:-./images.txt}"

###############################################################################
# Harbor configuration
###############################################################################

HARBOR_REGISTRY="${HARBOR_REGISTRY:-regdc.negahcloud.ir}"
HARBOR_PROJECT="${HARBOR_PROJECT:-public}"

HARBOR_USERNAME="${HARBOR_USERNAME:-}"
HARBOR_PASSWORD="${HARBOR_PASSWORD:-}"

###############################################################################
# Destination naming
###############################################################################

# true:
# docker.io/grafana/grafana:11.6.1
# ->
# regdc.negahcloud.ir/public/docker.io/grafana/grafana:11.6.1
#
# false:
# docker.io/grafana/grafana:11.6.1
# ->
# regdc.negahcloud.ir/public/grafana/grafana:11.6.1
PRESERVE_SOURCE_REGISTRY="${PRESERVE_SOURCE_REGISTRY:-true}"

###############################################################################
# Registry filtering
###############################################################################

# Empty means every external source registry is allowed.
PUBLIC_REGISTRY_ALLOWLIST="${PUBLIC_REGISTRY_ALLOWLIST:-docker.io,registry.k8s.io,quay.io,ghcr.io,gcr.io,public.ecr.aws,mcr.microsoft.com}"

REGISTRY_DENYLIST="${REGISTRY_DENYLIST:-localhost,127.0.0.1}"

###############################################################################
# Copy behavior
###############################################################################

COPY_ALL_ARCHITECTURES="${COPY_ALL_ARCHITECTURES:-true}"

VERIFY_EXISTING_DIGEST="${VERIFY_EXISTING_DIGEST:-true}"

OVERWRITE_DIGEST_MISMATCH="${OVERWRITE_DIGEST_MISMATCH:-false}"

MIRROR_DIGEST_ONLY_IMAGES="${MIRROR_DIGEST_ONLY_IMAGES:-true}"

# When true, Script 2 stops before processing when one source tag appears with
# multiple different digests.
FAIL_ON_TAG_DIGEST_CONFLICT="${FAIL_ON_TAG_DIGEST_CONFLICT:-true}"

###############################################################################
# Source registry authentication
###############################################################################

SOURCE_AUTHFILE="${SOURCE_AUTHFILE:-}"
SOURCE_CREDS="${SOURCE_CREDS:-}"

###############################################################################
# TLS
###############################################################################

SOURCE_TLS_INSECURE="${SOURCE_TLS_INSECURE:-false}"
HARBOR_TLS_INSECURE="${HARBOR_TLS_INSECURE:-false}"

###############################################################################
# Proxy configuration
#
# Skopeo automatically uses these standard environment variables:
#
# HTTP_PROXY
# HTTPS_PROXY
# NO_PROXY
# http_proxy
# https_proxy
# no_proxy
#
# This script does not modify them unless HARBOR_NO_PROXY=true.
###############################################################################

# Add Harbor to NO_PROXY only when Harbor must be accessed directly.
#
# Based on your current direct TLS test, leave this false unless the network
# team confirms a working direct Harbor route.
HARBOR_NO_PROXY="${HARBOR_NO_PROXY:-false}"

###############################################################################
# Retry
###############################################################################

MAX_RETRIES="${MAX_RETRIES:-4}"
RETRY_DELAY_SECONDS="${RETRY_DELAY_SECONDS:-10}"

###############################################################################
# Logging
###############################################################################

LOG_DIR="${LOG_DIR:-/var/log/k8s-image-mirror}"
LOG_FILE="${LOG_FILE:-${LOG_DIR}/harbor-mirror.log}"
LOCK_FILE="${LOCK_FILE:-/var/run/k8s-image-mirror.lock}"

###############################################################################
# Runtime counters
###############################################################################

TOTAL_RECORDS=0
UNIQUE_RECORDS=0
EXISTING_IMAGES=0
PUSHED_IMAGES=0
UPDATED_IMAGES=0
SKIPPED_IMAGES=0
FAILED_IMAGES=0
DIGEST_MISMATCHES=0
TAG_DIGEST_CONFLICTS=0

declare -A PROCESSED_RECORDS=()

###############################################################################
# Logging
###############################################################################

log() {
    local level="$1"
    shift

    printf '[%s] [level=%s] %s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        "$level" \
        "$*" | tee -a "$LOG_FILE"
}

info() {
    log "INFO" "$@"
}

warn() {
    log "WARN" "$@"
}

error() {
    log "ERROR" "$@"
}

###############################################################################
# Signal handling
###############################################################################

handle_interrupt() {
    error "MIRROR_INTERRUPTED signal=SIGINT"
    exit 130
}

handle_termination() {
    error "MIRROR_INTERRUPTED signal=SIGTERM"
    exit 143
}

trap handle_interrupt INT
trap handle_termination TERM

###############################################################################
# Validation
###############################################################################

require_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Required command is missing: %s\n' "$command_name" >&2
        exit 1
    fi
}

is_true() {
    case "${1,,}" in
        true|yes|1|on)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

validate_configuration() {
    require_command skopeo
    require_command awk
    require_command sed
    require_command flock
    require_command sort
    require_command grep
    require_command wc
    require_command tr
    require_command mktemp

    if [[ ! -r "$INVENTORY_FILE" ]]; then
        printf 'Inventory file is not readable: %s\n' \
            "$INVENTORY_FILE" >&2
        exit 1
    fi

    if [[ -z "$HARBOR_REGISTRY" ]]; then
        printf 'HARBOR_REGISTRY is empty\n' >&2
        exit 1
    fi

    if [[ -z "$HARBOR_PROJECT" ]]; then
        printf 'HARBOR_PROJECT is empty\n' >&2
        exit 1
    fi

    if [[ -z "$HARBOR_USERNAME" ]]; then
        printf 'HARBOR_USERNAME is not set\n' >&2
        exit 1
    fi

    if [[ -z "$HARBOR_PASSWORD" ]]; then
        printf 'HARBOR_PASSWORD is not set\n' >&2
        exit 1
    fi

    if [[ -n "$SOURCE_AUTHFILE" && ! -r "$SOURCE_AUTHFILE" ]]; then
        printf 'SOURCE_AUTHFILE is not readable: %s\n' \
            "$SOURCE_AUTHFILE" >&2
        exit 1
    fi

    mkdir -p "$LOG_DIR"
    touch "$LOG_FILE"
    chmod 0600 "$LOG_FILE"
}

###############################################################################
# General helpers
###############################################################################

trim() {
    local value="$1"

    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    printf '%s' "$value"
}

list_contains() {
    local comma_separated_list="$1"
    local expected="$2"
    local item
    local -a items=()

    IFS=',' read -ra items <<< "$comma_separated_list"

    for item in "${items[@]}"; do
        item="$(trim "$item")"

        if [[ "$item" == "$expected" ]]; then
            return 0
        fi
    done

    return 1
}

mask_proxy_credentials() {
    local proxy_url="$1"

    printf '%s' "$proxy_url" |
        sed -E 's#(https?://)[^/@]+:[^/@]+@#\1***:***@#'
}

retry() {
    local attempt=1
    local result=0

    while true; do
        if "$@"; then
            return 0
        else
            result=$?
        fi

        if (( attempt >= MAX_RETRIES )); then
            return "$result"
        fi

        warn "COMMAND_RETRY attempt=$((attempt + 1))/${MAX_RETRIES} delay=${RETRY_DELAY_SECONDS}s"

        sleep "$RETRY_DELAY_SECONDS"
        attempt=$((attempt + 1))
    done
}

###############################################################################
# Proxy handling
###############################################################################

append_no_proxy_entry() {
    local value="$1"
    local entry="$2"

    if [[ -z "$value" ]]; then
        printf '%s' "$entry"
        return
    fi

    if list_contains "$value" "$entry"; then
        printf '%s' "$value"
    else
        printf '%s,%s' "$value" "$entry"
    fi
}

configure_proxy_environment() {
    local effective_http_proxy
    local effective_https_proxy
    local effective_no_proxy

    effective_http_proxy="${HTTP_PROXY:-${http_proxy:-}}"
    effective_https_proxy="${HTTPS_PROXY:-${https_proxy:-}}"
    effective_no_proxy="${NO_PROXY:-${no_proxy:-}}"

    if [[ -n "$effective_http_proxy" ]]; then
        export HTTP_PROXY="$effective_http_proxy"
        export http_proxy="$effective_http_proxy"

        info "HTTP_PROXY_CONFIGURED proxy=$(mask_proxy_credentials "$effective_http_proxy")"
    else
        warn "HTTP_PROXY_NOT_CONFIGURED"
    fi

    if [[ -n "$effective_https_proxy" ]]; then
        export HTTPS_PROXY="$effective_https_proxy"
        export https_proxy="$effective_https_proxy"

        info "HTTPS_PROXY_CONFIGURED proxy=$(mask_proxy_credentials "$effective_https_proxy")"
    else
        warn "HTTPS_PROXY_NOT_CONFIGURED"
    fi

    if is_true "$HARBOR_NO_PROXY"; then
        effective_no_proxy="$(
            append_no_proxy_entry \
                "$effective_no_proxy" \
                "$HARBOR_REGISTRY"
        )"
    fi

    if [[ -n "$effective_no_proxy" ]]; then
        export NO_PROXY="$effective_no_proxy"
        export no_proxy="$effective_no_proxy"

        info "NO_PROXY_CONFIGURED value=${effective_no_proxy}"
    else
        unset NO_PROXY no_proxy 2>/dev/null || true

        info "NO_PROXY_EMPTY harbor_uses_proxy=true"
    fi

    if is_true "$HARBOR_NO_PROXY"; then
        info "HARBOR_PROXY_MODE mode=direct harbor=${HARBOR_REGISTRY}"
    else
        info "HARBOR_PROXY_MODE mode=environment-dependent harbor=${HARBOR_REGISTRY}"
    fi
}

###############################################################################
# Image parsing
###############################################################################

normalize_source_image() {
    local image="$1"
    local first_component

    image="${image#docker-pullable://}"
    image="${image#docker://}"

    image="${image/#index.docker.io\//docker.io/}"
    image="${image/#registry-1.docker.io\//docker.io/}"

    first_component="${image%%/*}"

    if [[ "$image" != */* ]]; then
        image="docker.io/library/${image}"

    elif [[ "$first_component" != *.* &&
            "$first_component" != *:* &&
            "$first_component" != "localhost" ]]; then
        image="docker.io/${image}"
    fi

    printf '%s' "$image"
}

get_source_registry() {
    local source_image="$1"

    printf '%s' "${source_image%%/*}"
}

is_digest_reference() {
    [[ "$1" == *@sha256:* ]]
}

get_repository_without_registry() {
    local source_image="$1"
    local repository_with_reference
    local final_component

    repository_with_reference="${source_image#*/}"

    if is_digest_reference "$source_image"; then
        printf '%s' "${repository_with_reference%@sha256:*}"
        return
    fi

    final_component="${repository_with_reference##*/}"

    if [[ "$final_component" == *:* ]]; then
        printf '%s' "${repository_with_reference%:*}"
    else
        printf '%s' "$repository_with_reference"
    fi
}

get_source_version() {
    local source_image="$1"
    local final_component

    if is_digest_reference "$source_image"; then
        printf '%s' "${source_image#*@}"
        return
    fi

    final_component="${source_image##*/}"

    if [[ "$final_component" == *:* ]]; then
        printf '%s' "${final_component##*:}"
    else
        printf '%s' "latest"
    fi
}

get_digest_from_reference() {
    local source_image="$1"

    if is_digest_reference "$source_image"; then
        printf '%s' "${source_image#*@}"
    else
        printf '%s' ""
    fi
}

digest_to_tag() {
    local source_image="$1"
    local digest
    local algorithm
    local digest_value

    digest="${source_image#*@}"
    algorithm="${digest%%:*}"
    digest_value="${digest#*:}"

    printf 'digest-%s-%s' \
        "$algorithm" \
        "${digest_value:0:20}"
}

sanitize_repository() {
    local repository="$1"

    repository="${repository,,}"

    printf '%s' "$repository" |
        sed -E '
            s/[^a-z0-9._\/-]+/-/g;
            s#/{2,}#/#g;
            s#^/+##;
            s#/+$##
        '
}

build_destination_image() {
    local source_image="$1"
    local source_registry
    local source_repository
    local destination_repository
    local destination_tag

    source_registry="$(get_source_registry "$source_image")"

    source_repository="$(
        get_repository_without_registry "$source_image"
    )"

    if is_digest_reference "$source_image"; then
        destination_tag="$(digest_to_tag "$source_image")"
    else
        destination_tag="$(get_source_version "$source_image")"
    fi

    if is_true "$PRESERVE_SOURCE_REGISTRY"; then
        destination_repository="${source_registry}/${source_repository}"
    else
        destination_repository="$source_repository"
    fi

    destination_repository="$(
        sanitize_repository "$destination_repository"
    )"

    printf '%s/%s/%s:%s' \
        "$HARBOR_REGISTRY" \
        "$HARBOR_PROJECT" \
        "$destination_repository" \
        "$destination_tag"
}

###############################################################################
# Filtering
###############################################################################

registry_is_allowed() {
    local source_registry="$1"

    if [[ "$source_registry" == "$HARBOR_REGISTRY" ]]; then
        return 1
    fi

    if list_contains "$REGISTRY_DENYLIST" "$source_registry"; then
        return 1
    fi

    if [[ -z "$PUBLIC_REGISTRY_ALLOWLIST" ]]; then
        return 0
    fi

    list_contains \
        "$PUBLIC_REGISTRY_ALLOWLIST" \
        "$source_registry"
}

###############################################################################
# Skopeo argument builders
###############################################################################

build_source_inspect_args() {
    SOURCE_INSPECT_ARGS=()

    if is_true "$SOURCE_TLS_INSECURE"; then
        SOURCE_INSPECT_ARGS+=(--tls-verify=false)
    else
        SOURCE_INSPECT_ARGS+=(--tls-verify=true)
    fi

    if [[ -n "$SOURCE_AUTHFILE" ]]; then
        SOURCE_INSPECT_ARGS+=(
            --authfile "$SOURCE_AUTHFILE"
        )
    fi

    if [[ -n "$SOURCE_CREDS" ]]; then
        SOURCE_INSPECT_ARGS+=(
            --creds "$SOURCE_CREDS"
        )
    fi
}

build_harbor_inspect_args() {
    HARBOR_INSPECT_ARGS=(
        --creds "${HARBOR_USERNAME}:${HARBOR_PASSWORD}"
    )

    if is_true "$HARBOR_TLS_INSECURE"; then
        HARBOR_INSPECT_ARGS+=(--tls-verify=false)
    else
        HARBOR_INSPECT_ARGS+=(--tls-verify=true)
    fi
}

build_copy_args() {
    COPY_ARGS=(
        --dest-creds "${HARBOR_USERNAME}:${HARBOR_PASSWORD}"
    )

    if is_true "$SOURCE_TLS_INSECURE"; then
        COPY_ARGS+=(--src-tls-verify=false)
    else
        COPY_ARGS+=(--src-tls-verify=true)
    fi

    if is_true "$HARBOR_TLS_INSECURE"; then
        COPY_ARGS+=(--dest-tls-verify=false)
    else
        COPY_ARGS+=(--dest-tls-verify=true)
    fi

    if [[ -n "$SOURCE_AUTHFILE" ]]; then
        COPY_ARGS+=(
            --src-authfile "$SOURCE_AUTHFILE"
        )
    fi

    if [[ -n "$SOURCE_CREDS" ]]; then
        COPY_ARGS+=(
            --src-creds "$SOURCE_CREDS"
        )
    fi

    if is_true "$COPY_ALL_ARCHITECTURES"; then
        COPY_ARGS+=(--all)
    fi
}

###############################################################################
# Registry operations
###############################################################################

inspect_source_digest() {
    local source_image="$1"

    build_source_inspect_args

    skopeo inspect \
        "${SOURCE_INSPECT_ARGS[@]}" \
        --format '{{.Digest}}' \
        "docker://${source_image}"
}

inspect_harbor_digest() {
    local destination_image="$1"

    build_harbor_inspect_args

    skopeo inspect \
        "${HARBOR_INSPECT_ARGS[@]}" \
        --format '{{.Digest}}' \
        "docker://${destination_image}"
}

source_exists() {
    local source_image="$1"

    build_source_inspect_args

    skopeo inspect \
        "${SOURCE_INSPECT_ARGS[@]}" \
        "docker://${source_image}" \
        >/dev/null
}

destination_exists() {
    local destination_image="$1"

    build_harbor_inspect_args

    skopeo inspect \
        "${HARBOR_INSPECT_ARGS[@]}" \
        "docker://${destination_image}" \
        >/dev/null
}

copy_to_harbor() {
    local source_image="$1"
    local destination_image="$2"

    build_copy_args

    skopeo copy \
        "${COPY_ARGS[@]}" \
        "docker://${source_image}" \
        "docker://${destination_image}"
}

###############################################################################
# Validate input records
#
# The collector output may contain spaces or tabs. AWK parses generic
# whitespace and emits normalized TSV internally.
###############################################################################

normalize_inventory() {
    local normalized_file="$1"

    awk '
        BEGIN {
            OFS = "\t"
        }

        /^[[:space:]]*#/ {
            next
        }

        /^[[:space:]]*$/ {
            next
        }

        NF < 5 {
            print "INVALID_LINE\t" NR "\t" NF "\t" $0 > "/dev/stderr"
            next
        }

        {
            print $1, $2, $3, $4, $5
        }
    ' "$INVENTORY_FILE" > "$normalized_file"
}

validate_normalized_inventory() {
    local normalized_file="$1"
    local invalid_count

    invalid_count="$(
        awk -F '\t' '
            NF != 5 {
                count++
            }

            END {
                print count + 0
            }
        ' "$normalized_file"
    )"

    if (( invalid_count > 0 )); then
        error "INVENTORY_FORMAT_INVALID invalid_records=${invalid_count}"
        return 1
    fi

    if [[ ! -s "$normalized_file" ]]; then
        error "INVENTORY_EMPTY file=${INVENTORY_FILE}"
        return 1
    fi

    info "INVENTORY_FORMAT_VALID parser=whitespace fields=5"
}

###############################################################################
# Detect same tag with multiple digests
###############################################################################

validate_tag_digest_conflicts() {
    local normalized_file="$1"
    local conflicts_file
    local source_image
    local digests

    conflicts_file="$(mktemp)"

    awk -F '\t' '
        BEGIN {
            OFS = "\t"
        }

        NF != 5 {
            next
        }

        $1 ~ /@sha256:/ {
            next
        }

        $4 == "" || $4 == "UNKNOWN" {
            next
        }

        {
            source = $1
            digest = $4
            key = source SUBSEP digest

            if (!(key in seen)) {
                seen[key] = 1
                count[source]++

                if (list[source] == "") {
                    list[source] = digest
                } else {
                    list[source] = list[source] "," digest
                }
            }
        }

        END {
            for (source in count) {
                if (count[source] > 1) {
                    print source, list[source]
                }
            }
        }
    ' "$normalized_file" |
        sort > "$conflicts_file"

    TAG_DIGEST_CONFLICTS="$(
        wc -l < "$conflicts_file" |
        tr -d ' '
    )"

    while IFS=$'\t' read -r source_image digests; do
        [[ -z "$source_image" ]] && continue

        warn "MULTIPLE_NODE_DIGESTS source=${source_image} node_digests=${digests} action=USE_SOURCE_REGISTRY_DIGEST"
    done < "$conflicts_file"

    rm -f "$conflicts_file"

    return 0
}

###############################################################################
# Process one image
###############################################################################

process_image() {
    local inventory_source="$1"
    local inventory_name="$2"
    local inventory_version="$3"
    local observed_digest="$4"
    local source_nodes="$5"

    local source_image
    local source_registry
    local source_repository
    local source_version
    local destination_image
    local processing_key
    local source_registry_digest=""
    local harbor_digest=""
    local source_reference_digest=""

    TOTAL_RECORDS=$((TOTAL_RECORDS + 1))

    source_image="$(
        normalize_source_image "$inventory_source"
    )"

    source_registry="$(
        get_source_registry "$source_image"
    )"

    source_repository="$(
        get_repository_without_registry "$source_image"
    )"

    source_version="$(
        get_source_version "$source_image"
    )"

    source_reference_digest="$(
        get_digest_from_reference "$source_image"
    )"

    [[ -z "$inventory_name" ]] &&
        inventory_name="UNKNOWN"

    [[ -z "$inventory_version" ]] &&
        inventory_version="$source_version"

    [[ -z "$observed_digest" ]] &&
        observed_digest="UNKNOWN"

    [[ -z "$source_nodes" ]] &&
        source_nodes="UNKNOWN"

    if [[ -n "$source_reference_digest" ]]; then
        observed_digest="$source_reference_digest"
    fi

    processing_key="${source_image}|${observed_digest}"

    if [[ -n "${PROCESSED_RECORDS[$processing_key]+x}" ]]; then
        SKIPPED_IMAGES=$((SKIPPED_IMAGES + 1))

        info "SKIPPED_DUPLICATE_INVENTORY source=${source_image} version=${source_version} digest=${observed_digest} nodes=${source_nodes}"

        return 0
    fi

    PROCESSED_RECORDS["$processing_key"]=1
    UNIQUE_RECORDS=$((UNIQUE_RECORDS + 1))

    if [[ "$source_registry" == "$HARBOR_REGISTRY" ]]; then
        SKIPPED_IMAGES=$((SKIPPED_IMAGES + 1))

        info "SKIPPED_ALREADY_IN_HARBOR source=${source_image} nodes=${source_nodes}"

        return 0
    fi

    if ! registry_is_allowed "$source_registry"; then
        SKIPPED_IMAGES=$((SKIPPED_IMAGES + 1))

        warn "SKIPPED_REGISTRY_NOT_ALLOWED source=${source_image} source_registry=${source_registry} nodes=${source_nodes}"

        return 0
    fi

    if is_digest_reference "$source_image" &&
       ! is_true "$MIRROR_DIGEST_ONLY_IMAGES"; then

        SKIPPED_IMAGES=$((SKIPPED_IMAGES + 1))

        warn "SKIPPED_DIGEST_ONLY_IMAGE source=${source_image} digest=${observed_digest} nodes=${source_nodes}"

        return 0
    fi

    destination_image="$(
        build_destination_image "$source_image"
    )"

    info "CHECKING_IMAGE source=${source_image} source_registry=${source_registry} source_repository=${source_repository} source_version=${source_version} observed_digest=${observed_digest} source_nodes=${source_nodes} harbor_project=${HARBOR_PROJECT} harbor_image=${destination_image}"

    if destination_exists "$destination_image" 2>>"$LOG_FILE"; then
        EXISTING_IMAGES=$((EXISTING_IMAGES + 1))

        harbor_digest="$(
            inspect_harbor_digest "$destination_image" \
                2>>"$LOG_FILE" || true
        )"

        if is_true "$VERIFY_EXISTING_DIGEST"; then
            source_registry_digest="$(
                inspect_source_digest "$source_image" \
                    2>>"$LOG_FILE" || true
            )"

            if [[ -n "$source_registry_digest" &&
                  -n "$harbor_digest" &&
                  "$source_registry_digest" != "$harbor_digest" ]]; then

                DIGEST_MISMATCHES=$((DIGEST_MISMATCHES + 1))

                warn "IMAGE_EXISTS_DIGEST_MISMATCH source=${source_image} source_registry_digest=${source_registry_digest} observed_digest=${observed_digest} harbor_image=${destination_image} harbor_digest=${harbor_digest} source_nodes=${source_nodes}"

                if ! is_true "$OVERWRITE_DIGEST_MISMATCH"; then
                    warn "IMAGE_NOT_OVERWRITTEN source=${source_image} harbor_image=${destination_image}"

                    return 0
                fi

                info "UPDATING_EXISTING_IMAGE source=${source_image} harbor_image=${destination_image}"

                if ! retry \
                    copy_to_harbor \
                    "$source_image" \
                    "$destination_image" \
                    2>>"$LOG_FILE"; then

                    FAILED_IMAGES=$((FAILED_IMAGES + 1))

                    error "IMAGE_UPDATE_FAILED source=${source_image} harbor_image=${destination_image}"

                    return 1
                fi

                UPDATED_IMAGES=$((UPDATED_IMAGES + 1))

                info "IMAGE_UPDATED_SUCCESSFULLY source=${source_image} harbor_image=${destination_image}"

                return 0
            fi
        fi

        info "IMAGE_EXISTS_IN_HARBOR source=${source_image} source_version=${source_version} observed_digest=${observed_digest} harbor_project=${HARBOR_PROJECT} harbor_image=${destination_image} harbor_digest=${harbor_digest:-UNKNOWN} source_nodes=${source_nodes}"

        return 0
    fi

    info "IMAGE_NOT_FOUND_IN_HARBOR source=${source_image} source_version=${source_version} observed_digest=${observed_digest} harbor_project=${HARBOR_PROJECT} harbor_image=${destination_image} source_nodes=${source_nodes}"

    if ! retry source_exists "$source_image" 2>>"$LOG_FILE"; then
        FAILED_IMAGES=$((FAILED_IMAGES + 1))

        error "SOURCE_IMAGE_UNAVAILABLE source=${source_image} source_registry=${source_registry} source_version=${source_version} observed_digest=${observed_digest} source_nodes=${source_nodes}"

        return 1
    fi

    source_registry_digest="$(
        inspect_source_digest "$source_image" \
            2>>"$LOG_FILE" || true
    )"

    info "RETAGGING_AND_PUSHING source=${source_image} source_registry=${source_registry} source_repository=${source_repository} source_version=${source_version} source_registry_digest=${source_registry_digest:-UNKNOWN} observed_digest=${observed_digest} source_nodes=${source_nodes} harbor_project=${HARBOR_PROJECT} harbor_image=${destination_image}"

    if ! retry \
        copy_to_harbor \
        "$source_image" \
        "$destination_image" \
        2>>"$LOG_FILE"; then

        FAILED_IMAGES=$((FAILED_IMAGES + 1))

        error "IMAGE_PUSH_FAILED source=${source_image} source_version=${source_version} harbor_image=${destination_image} source_nodes=${source_nodes}"

        return 1
    fi

    if ! retry \
        destination_exists \
        "$destination_image" \
        2>>"$LOG_FILE"; then

        FAILED_IMAGES=$((FAILED_IMAGES + 1))

        error "IMAGE_PUSH_VERIFICATION_FAILED source=${source_image} harbor_image=${destination_image}"

        return 1
    fi

    harbor_digest="$(
        inspect_harbor_digest "$destination_image" \
            2>>"$LOG_FILE" || true
    )"

    PUSHED_IMAGES=$((PUSHED_IMAGES + 1))

    info "IMAGE_PUSHED_SUCCESSFULLY source=${source_image} source_registry=${source_registry} source_repository=${source_repository} source_version=${source_version} source_registry_digest=${source_registry_digest:-UNKNOWN} observed_digest=${observed_digest} source_nodes=${source_nodes} harbor_project=${HARBOR_PROJECT} harbor_image=${destination_image} harbor_digest=${harbor_digest:-UNKNOWN}"

    return 0
}

###############################################################################
# Process normalized inventory
###############################################################################

process_inventory() {
    local normalized_file="$1"

    local source_image
    local image_name
    local version
    local observed_digest
    local source_nodes
    local processing_failed=0

    while IFS=$'\t' read -r \
        source_image \
        image_name \
        version \
        observed_digest \
        source_nodes
    do
        [[ -z "${source_image:-}" ]] && continue

        if ! process_image \
            "$source_image" \
            "$image_name" \
            "$version" \
            "$observed_digest" \
            "$source_nodes"; then

            processing_failed=1
        fi
    done < "$normalized_file"

    return "$processing_failed"
}

###############################################################################
# Summary
###############################################################################

print_summary() {
    info "MIRROR_SUMMARY inventory_records=${TOTAL_RECORDS} unique_records=${UNIQUE_RECORDS} existing=${EXISTING_IMAGES} pushed=${PUSHED_IMAGES} updated=${UPDATED_IMAGES} digest_mismatches=${DIGEST_MISMATCHES} tag_digest_conflicts=${TAG_DIGEST_CONFLICTS} skipped=${SKIPPED_IMAGES} failed=${FAILED_IMAGES} harbor_registry=${HARBOR_REGISTRY} harbor_project=${HARBOR_PROJECT}"
}

on_exit() {
    local exit_code=$?

    print_summary

    if (( exit_code == 0 )); then
        info "MIRROR_COMPLETED_SUCCESSFULLY"
    else
        error "MIRROR_COMPLETED_WITH_ERRORS exit_code=${exit_code}"
    fi
}

trap on_exit EXIT

###############################################################################
# Main
###############################################################################

main() {
    local tmp_dir
    local normalized_inventory

    validate_configuration
    configure_proxy_environment

    exec 9>"$LOCK_FILE"

    if ! flock -n 9; then
        warn "ANOTHER_MIRROR_PROCESS_IS_RUNNING lock_file=${LOCK_FILE}"
        exit 0
    fi

    tmp_dir="$(mktemp -d)"
    normalized_inventory="${tmp_dir}/normalized-images.tsv"

    trap 'rm -rf "$tmp_dir"' RETURN

    info "MIRROR_STARTED inventory=${INVENTORY_FILE} harbor_registry=${HARBOR_REGISTRY} harbor_project=${HARBOR_PROJECT}"

    normalize_inventory "$normalized_inventory"

    if ! validate_normalized_inventory "$normalized_inventory"; then
        exit 1
    fi

    if ! validate_tag_digest_conflicts "$normalized_inventory"; then
        exit 1
    fi

    if ! process_inventory "$normalized_inventory"; then
        exit 1
    fi
}

main "$@"
