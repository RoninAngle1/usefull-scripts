#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

###############################################################################
# Collect every cached image reported by every Kubernetes node.
#
# This reads Node.status.images through the Kubernetes API. Nothing is
# installed or executed on Kubernetes nodes.
#
# Captures:
#   - All worker-node cached images
#   - All control-plane/master cached images
#   - Multiple versions of the same repository
#   - Tagged references
#   - Digest-pinned references
#   - Tags associated with the digest reported in the same Node image record
#
# Output format:
#   source_image<TAB>image_name<TAB>version<TAB>digest<TAB>nodes
#
# Example:
#   registry.k8s.io/pause:3.9<TAB>registry.k8s.io/pause<TAB>3.9<TAB>sha256:...<TAB>master-01,worker-01
#   registry.k8s.io/pause:3.10<TAB>registry.k8s.io/pause<TAB>3.10<TAB>sha256:...<TAB>master-01
#
# Requirements on the management host:
#   kubectl
#   jq
#
# Required Kubernetes permission:
#   get/list nodes
#
# Usage:
#   ./collect-node-images.sh
#   ./collect-node-images.sh /opt/k8s-image-mirror/k8s-images.txt
#
# Optional environment:
#   KUBECONFIG=/path/to/kubeconfig
#   KUBE_CONTEXT=production
#
# Optional behavior:
#   INCLUDE_DIGEST_ONLY=true
#
# When INCLUDE_DIGEST_ONLY=true, images that have no tag alias are included
# using their repository@sha256 reference.
###############################################################################

OUTPUT_FILE="${1:-./k8s-images.txt}"

KUBE_CONTEXT="${KUBE_CONTEXT:-}"
INCLUDE_DIGEST_ONLY="${INCLUDE_DIGEST_ONLY:-true}"

TMP_DIR=""
NODES_JSON=""
RAW_FILE=""
AGGREGATED_FILE=""

TOTAL_NODES=0
TOTAL_NODE_IMAGE_OBJECTS=0
TOTAL_REFERENCES=0
UNIQUE_RECORDS=0
UNIQUE_SOURCE_IMAGES=0
DIGEST_ONLY_RECORDS=0
UNKNOWN_DIGEST_RECORDS=0
TAG_DIGEST_CONFLICTS=0

###############################################################################
# Logging
###############################################################################

log() {
    local level="$1"
    shift

    printf '[%s] [level=%s] %s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        "$level" \
        "$*" >&2
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
# Cleanup
###############################################################################

cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT

###############################################################################
# Validation
###############################################################################

require_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        error "Required command is missing: ${command_name}"
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

validate_requirements() {
    require_command kubectl
    require_command jq
    require_command awk
    require_command sort
    require_command sed
    require_command grep
    require_command mktemp
    require_command wc
    require_command tr

    mkdir -p "$(dirname "$OUTPUT_FILE")"
}

###############################################################################
# kubectl wrapper
###############################################################################

run_kubectl() {
    local -a args=()

    if [[ -n "$KUBE_CONTEXT" ]]; then
        args+=(--context "$KUBE_CONTEXT")
    fi

    kubectl "${args[@]}" "$@"
}

###############################################################################
# Image parsing
###############################################################################

normalize_image() {
    local image="$1"
    local first_component

    image="${image#docker-pullable://}"
    image="${image#docker://}"

    image="${image/#index.docker.io\//docker.io/}"
    image="${image/#registry-1.docker.io\//docker.io/}"

    first_component="${image%%/*}"

    # redis:7 -> docker.io/library/redis:7
    if [[ "$image" != */* ]]; then
        image="docker.io/library/${image}"

    # bitnami/redis:7 -> docker.io/bitnami/redis:7
    elif [[ "$first_component" != *.* &&
            "$first_component" != *:* &&
            "$first_component" != "localhost" ]]; then
        image="docker.io/${image}"
    fi

    printf '%s' "$image"
}

get_image_name() {
    local image="$1"
    local final_component

    if [[ "$image" == *@sha256:* ]]; then
        printf '%s' "${image%@sha256:*}"
        return
    fi

    final_component="${image##*/}"

    if [[ "$final_component" == *:* ]]; then
        printf '%s' "${image%:*}"
    else
        printf '%s' "$image"
    fi
}

get_image_version() {
    local image="$1"
    local final_component

    if [[ "$image" == *@sha256:* ]]; then
        printf '%s' "${image#*@}"
        return
    fi

    final_component="${image##*/}"

    if [[ "$final_component" == *:* ]]; then
        printf '%s' "${final_component##*:}"
    else
        printf '%s' "latest"
    fi
}

get_repository_from_reference() {
    local image="$1"
    local final_component

    if [[ "$image" == *@sha256:* ]]; then
        printf '%s' "${image%@sha256:*}"
        return
    fi

    final_component="${image##*/}"

    if [[ "$final_component" == *:* ]]; then
        printf '%s' "${image%:*}"
    else
        printf '%s' "$image"
    fi
}

get_digest_from_reference() {
    local image="$1"

    if [[ "$image" == *@sha256:* ]]; then
        printf '%s' "${image#*@}"
    elif [[ "$image" == sha256:* ]]; then
        printf '%s' "$image"
    else
        printf '%s' ""
    fi
}

is_digest_reference() {
    [[ "$1" == *@sha256:* || "$1" == sha256:* ]]
}

is_tag_reference() {
    local image="$1"
    local final_component

    if is_digest_reference "$image"; then
        return 1
    fi

    final_component="${image##*/}"

    [[ "$final_component" == *:* ]]
}

###############################################################################
# Select digest associated with a Node.status.images entry
#
# A node image record may look like:
#
# names:
#   - docker.io/library/redis:7
#   - docker.io/library/redis@sha256:abc...
#
# The digest alias is associated with every tag in the same image object.
###############################################################################

extract_image_objects() {
    jq -r '
        .items[]? as $node |

        ($node.status.images // [])[]? |

        [
            ($node.metadata.name // "unknown"),
            ((.sizeBytes // 0) | tostring),
            ((.names // []) | @json)
        ] |

        @tsv
    ' "$NODES_JSON"
}

###############################################################################
# Store one source image record
###############################################################################

store_record() {
    local node_name="$1"
    local source_reference="$2"
    local digest="$3"

    local normalized_source
    local image_name
    local image_version

    [[ -z "$source_reference" ]] && return 0
    [[ "$source_reference" == "<none>" ]] && return 0
    [[ "$source_reference" == "null" ]] && return 0

    normalized_source="$(normalize_image "$source_reference")"
    image_name="$(get_image_name "$normalized_source")"
    image_version="$(get_image_version "$normalized_source")"

    [[ -z "$digest" ]] && digest="UNKNOWN"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$normalized_source" \
        "$image_name" \
        "$image_version" \
        "$digest" \
        "$node_name" >> "$RAW_FILE"

    TOTAL_REFERENCES=$((TOTAL_REFERENCES + 1))

    info "DISCOVERED_NODE_IMAGE node=${node_name} source=${normalized_source} image_name=${image_name} version=${image_version} digest=${digest}"
}

###############################################################################
# Process Node.status.images
###############################################################################

collect_all_node_images() {
    local node_name
    local size_bytes
    local names_json

    local -a names=()
    local -a tag_references=()
    local -a digest_references=()

    local name
    local normalized_name
    local digest_reference
    local digest
    local tag_reference
    local tag_repository
    local digest_repository
    local matched_digest
    local emitted_digest_reference

    while IFS=$'\t' read -r node_name size_bytes names_json; do
        TOTAL_NODE_IMAGE_OBJECTS=$((TOTAL_NODE_IMAGE_OBJECTS + 1))

        mapfile -t names < <(
            jq -r '.[]?' <<< "$names_json"
        )

        tag_references=()
        digest_references=()

        for name in "${names[@]}"; do
            [[ -z "$name" ]] && continue

            normalized_name="$(normalize_image "$name")"

            if is_digest_reference "$normalized_name"; then
                digest_references+=("$normalized_name")
            else
                tag_references+=("$normalized_name")
            fi
        done

        # Emit every tag/version separately.
        #
        # Example:
        #   redis:6
        #   redis:7
        #
        # become two separate output records.
        for tag_reference in "${tag_references[@]}"; do
            tag_repository="$(get_repository_from_reference "$tag_reference")"
            matched_digest=""

            # Find a digest alias for the same repository in this node image
            # object.
            for digest_reference in "${digest_references[@]}"; do
                digest_repository="$(
                    get_repository_from_reference "$digest_reference"
                )"

                if [[ "$tag_repository" == "$digest_repository" ]]; then
                    matched_digest="$(
                        get_digest_from_reference "$digest_reference"
                    )"
                    break
                fi
            done

            # Some runtimes may format aliases differently. When the image
            # object contains exactly one digest, use it as the associated
            # digest for all tags in this image object.
            if [[ -z "$matched_digest" &&
                  "${#digest_references[@]}" -eq 1 ]]; then
                matched_digest="$(
                    get_digest_from_reference "${digest_references[0]}"
                )"
            fi

            [[ -z "$matched_digest" ]] && matched_digest="UNKNOWN"

            store_record \
                "$node_name" \
                "$tag_reference" \
                "$matched_digest"
        done

        # Include digest-only image objects that do not expose any tag.
        if is_true "$INCLUDE_DIGEST_ONLY" &&
           [[ "${#tag_references[@]}" -eq 0 ]]; then

            emitted_digest_reference="false"

            for digest_reference in "${digest_references[@]}"; do
                digest="$(
                    get_digest_from_reference "$digest_reference"
                )"

                store_record \
                    "$node_name" \
                    "$digest_reference" \
                    "$digest"

                emitted_digest_reference="true"
            done

            if [[ "$emitted_digest_reference" == "false" ]]; then
                warn "NODE_IMAGE_WITHOUT_USABLE_NAME node=${node_name} size_bytes=${size_bytes}"
            fi
        fi

    done < <(extract_image_objects)
}

###############################################################################
# Aggregate identical records across nodes
#
# Deduplication key:
#   source_image + digest
#
# Therefore:
#
#   redis:6 + sha256:aaa
#   redis:7 + sha256:bbb
#
# remain separate records.
#
# Also, if the same tag resolves to different digests on different nodes:
#
#   redis:7 + sha256:aaa
#   redis:7 + sha256:bbb
#
# both remain visible as separate records.
###############################################################################

aggregate_records() {
    sort -t $'\t' \
        -k1,1 \
        -k4,4 \
        -k5,5 \
        "$RAW_FILE" > "${TMP_DIR}/records.sorted.tsv"

    awk -F '\t' '
        BEGIN {
            OFS = "\t"
        }

        NF < 5 {
            next
        }

        {
            key = $1 SUBSEP $4

            if (!(key in seen)) {
                seen[key] = 1
                order[++count] = key

                source[key] = $1
                image_name[key] = $2
                version[key] = $3
                digest[key] = $4
                nodes[key] = $5
            } else {
                node_key = key SUBSEP $5

                if (!(node_key in node_seen)) {
                    node_seen[node_key] = 1
                    nodes[key] = nodes[key] "," $5
                }
            }

            node_seen[key SUBSEP $5] = 1
        }

        END {
            for (i = 1; i <= count; i++) {
                key = order[i]

                print source[key],
                      image_name[key],
                      version[key],
                      digest[key],
                      nodes[key]
            }
        }
    ' "${TMP_DIR}/records.sorted.tsv" |
        sort -t $'\t' -k2,2 -k3,3V -k4,4 \
        > "$AGGREGATED_FILE"
}

###############################################################################
# Detect mutable-tag inconsistencies
#
# Same source tag with several different digests means that nodes have
# different content behind the same tag.
###############################################################################

detect_tag_digest_conflicts() {
    local conflicts_file="${TMP_DIR}/tag-digest-conflicts.txt"

    awk -F '\t' '
        NF >= 5 && $4 != "UNKNOWN" {
            image = $1
            digest = $4
            digest_key = image SUBSEP digest

            if (!(digest_key in digest_seen)) {
                digest_seen[digest_key] = 1
                digest_count[image]++

                if (digests[image] == "") {
                    digests[image] = digest
                } else {
                    digests[image] = digests[image] "," digest
                }
            }
        }

        END {
            for (image in digest_count) {
                if (digest_count[image] > 1) {
                    print image "\t" digests[image]
                }
            }
        }
    ' "$AGGREGATED_FILE" |
        sort > "$conflicts_file"

    TAG_DIGEST_CONFLICTS="$(
        wc -l < "$conflicts_file" |
        tr -d ' '
    )"

    while IFS=$'\t' read -r source digests; do
        [[ -z "$source" ]] && continue

        warn "TAG_DIGEST_CONFLICT source=${source} digests=${digests}"
    done < "$conflicts_file"
}

###############################################################################
# Write inventory
###############################################################################

write_output() {
    {
        printf '# source_image\timage_name\tversion\tdigest\tnodes\n'
        cat "$AGGREGATED_FILE"
    } > "$OUTPUT_FILE"
}

###############################################################################
# Summary
###############################################################################

calculate_summary() {
    TOTAL_NODES="$(
        jq -r '.items | length' "$NODES_JSON"
    )"

    UNIQUE_RECORDS="$(
        awk -F '\t' '
            !/^#/ && NF >= 5 {
                count++
            }

            END {
                print count + 0
            }
        ' "$OUTPUT_FILE"
    )"

    UNIQUE_SOURCE_IMAGES="$(
        awk -F '\t' '
            !/^#/ && NF >= 5 {
                sources[$1] = 1
            }

            END {
                for (source in sources) {
                    count++
                }

                print count + 0
            }
        ' "$OUTPUT_FILE"
    )"

    DIGEST_ONLY_RECORDS="$(
        awk -F '\t' '
            !/^#/ && NF >= 5 && $1 ~ /@sha256:/ {
                count++
            }

            END {
                print count + 0
            }
        ' "$OUTPUT_FILE"
    )"

    UNKNOWN_DIGEST_RECORDS="$(
        awk -F '\t' '
            !/^#/ && NF >= 5 && $4 == "UNKNOWN" {
                count++
            }

            END {
                print count + 0
            }
        ' "$OUTPUT_FILE"
    )"
}

print_summary() {
    calculate_summary

    info "INVENTORY_COMPLETE output=${OUTPUT_FILE} nodes=${TOTAL_NODES} node_image_objects=${TOTAL_NODE_IMAGE_OBJECTS} discovered_references=${TOTAL_REFERENCES} unique_records=${UNIQUE_RECORDS} unique_source_images=${UNIQUE_SOURCE_IMAGES} digest_only=${DIGEST_ONLY_RECORDS} unknown_digests=${UNKNOWN_DIGEST_RECORDS} tag_digest_conflicts=${TAG_DIGEST_CONFLICTS}"
}

###############################################################################
# Main
###############################################################################

main() {
    validate_requirements

    TMP_DIR="$(mktemp -d)"
    NODES_JSON="${TMP_DIR}/nodes.json"
    RAW_FILE="${TMP_DIR}/node-images.raw.tsv"
    AGGREGATED_FILE="${TMP_DIR}/node-images.aggregated.tsv"

    : > "$RAW_FILE"
    : > "$AGGREGATED_FILE"

    info "Checking permission to list Kubernetes nodes"

    local can_list_nodes
    can_list_nodes="$(
        run_kubectl auth can-i list nodes 2>/dev/null || true
    )"

    if [[ "$can_list_nodes" != "yes" ]]; then
        error "Current Kubernetes identity cannot list nodes"
        exit 1
    fi

    info "Reading cached image inventory from all Kubernetes nodes"

    if ! run_kubectl get nodes -o json > "$NODES_JSON"; then
        error "Failed to retrieve Kubernetes Node objects"
        exit 1
    fi

    TOTAL_NODES="$(
        jq -r '.items | length' "$NODES_JSON"
    )"

    if (( TOTAL_NODES == 0 )); then
        warn "No Kubernetes nodes were returned"

        printf '# source_image\timage_name\tversion\tdigest\tnodes\n' \
            > "$OUTPUT_FILE"

        print_summary
        exit 0
    fi

    collect_all_node_images

    if [[ ! -s "$RAW_FILE" ]]; then
        warn "No cached images were reported by Kubernetes nodes"

        printf '# source_image\timage_name\tversion\tdigest\tnodes\n' \
            > "$OUTPUT_FILE"

        print_summary
        exit 0
    fi

    aggregate_records
    detect_tag_digest_conflicts
    write_output
    print_summary
}

main "$@"
