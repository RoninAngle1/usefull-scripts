#!/usr/bin/env bash

set -Eeuo pipefail

INTERVAL="${INTERVAL:-5}"
TOP_PROCESS_COUNT="${TOP_PROCESS_COUNT:-10}"

OUTPUT_FILE="${1:-system_metrics.csv}"
PROCESS_FILE="${PROCESS_FILE:-${OUTPUT_FILE%.csv}_processes.csv}"

NETWORK_INTERFACE="${NETWORK_INTERFACE:-}"
DISK_DEVICE="${DISK_DEVICE:-}"

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

detect_network_interface() {
    awk '
        NR > 1 && $2 == "00000000" {
            print $1
            exit
        }
    ' /proc/net/route 2>/dev/null
}

resolve_disk_device() {
    local requested="$1"
    local resolved=""

    requested="${requested#/dev/}"

    if [[ -e "/dev/mapper/${requested}" ]]; then
        resolved="$(readlink -f "/dev/mapper/${requested}" 2>/dev/null || true)"
    elif [[ -e "/dev/${requested}" ]]; then
        resolved="$(readlink -f "/dev/${requested}" 2>/dev/null || true)"
    fi

    if [[ -n "$resolved" ]]; then
        printf '%s\n' "${resolved##*/}"
    else
        printf '%s\n' "$requested"
    fi
}

detect_disk_device() {
    local root_source=""
    local resolved=""

    root_source="$(
        awk '
            $2 == "/" {
                print $1
                exit
            }
        ' /proc/mounts 2>/dev/null
    )"

    if [[ "$root_source" != /dev/* ]]; then
        return
    fi

    resolved="$(readlink -f "$root_source" 2>/dev/null || true)"

    if [[ -z "$resolved" ]]; then
        resolved="$root_source"
    fi

    printf '%s\n' "${resolved##*/}"
}

read_cpu_counters() {
    awk '
        /^cpu / {
            idle=$5+$6
            total=0

            for (i=2; i<=NF; i++) {
                total+=$i
            }

            print total, idle
        }
    ' /proc/stat
}

read_memory_metrics() {
    awk '
        /^MemTotal:/ {
            total=$2
        }

        /^MemAvailable:/ {
            available=$2
        }

        END {
            used=total-available
            used_percent=0

            if (total > 0) {
                used_percent=used*100/total
            }

            printf "%.2f %.2f %.2f\n",
                used/1024,
                total/1024,
                used_percent
        }
    ' /proc/meminfo
}

read_load_average() {
    awk '{print $1, $2, $3}' /proc/loadavg
}

read_network_counters() {
    local interface="$1"
    local rx_file="/sys/class/net/${interface}/statistics/rx_bytes"
    local tx_file="/sys/class/net/${interface}/statistics/tx_bytes"

    if [[ ! -r "$rx_file" || ! -r "$tx_file" ]]; then
        echo "0 0"
        return
    fi

    printf '%s %s\n' \
        "$(cat "$rx_file")" \
        "$(cat "$tx_file")"
}

read_disk_counters() {
    local device="$1"
    local stat_file=""

    if [[ -r "/sys/class/block/${device}/stat" ]]; then
        stat_file="/sys/class/block/${device}/stat"
    elif [[ -r "/sys/block/${device}/stat" ]]; then
        stat_file="/sys/block/${device}/stat"
    else
        echo "0 0"
        return
    fi

    # Field 3: sectors read
    # Field 7: sectors written
    awk '{print $3, $7}' "$stat_file"
}

read_gpu_metrics() {
    if ! command_exists nvidia-smi; then
        echo "0 0 0 0 0"
        return
    fi

    nvidia-smi \
        --query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw \
        --format=csv,noheader,nounits 2>/dev/null |
    awk -F',' '
        {
            for (i=1; i<=NF; i++) {
                gsub(/^[ \t]+/, "", $i)
                gsub(/[ \t]+$/, "", $i)

                if ($i == "" || $i == "N/A" || $i == "[N/A]") {
                    $i=0
                }
            }

            gpu_utilization+=$1
            memory_used+=$2
            memory_total+=$3
            temperature+=$4
            power+=$5
            gpu_count++
        }

        END {
            if (gpu_count == 0) {
                print "0 0 0 0 0"
            } else {
                printf "%.2f %.2f %.2f %.2f %.2f\n",
                    gpu_utilization/gpu_count,
                    memory_used,
                    memory_total,
                    temperature/gpu_count,
                    power
            }
        }
    '
}

sanitize_command() {
    tr '\t,\r\n|' '     '
}

record_cpu_processes() {
    local timestamp="$1"
    local pid=""
    local ppid=""
    local user=""
    local cpu=""
    local memory=""
    local command=""

    if ! command_exists ps; then
        return
    fi

    ps -eo pid=,ppid=,user=,pcpu=,pmem=,args= --sort=-pcpu 2>/dev/null |
    awk -v limit="$TOP_PROCESS_COUNT" '
        NF > 0 && count < limit {
            print
            count++
        }
    ' |
    while read -r pid ppid user cpu memory command; do
        command="$(printf '%s' "$command" | sanitize_command)"

        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$timestamp" \
            "CPU" \
            "$pid" \
            "$ppid" \
            "$user" \
            "$cpu" \
            "$memory" \
            "0" \
            "$command" \
            >> "$PROCESS_FILE"
    done
}

record_memory_processes() {
    local timestamp="$1"
    local pid=""
    local ppid=""
    local user=""
    local cpu=""
    local memory=""
    local command=""

    if ! command_exists ps; then
        return
    fi

    ps -eo pid=,ppid=,user=,pcpu=,pmem=,args= --sort=-pmem 2>/dev/null |
    awk -v limit="$TOP_PROCESS_COUNT" '
        NF > 0 && count < limit {
            print
            count++
        }
    ' |
    while read -r pid ppid user cpu memory command; do
        command="$(printf '%s' "$command" | sanitize_command)"

        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$timestamp" \
            "MEMORY" \
            "$pid" \
            "$ppid" \
            "$user" \
            "$cpu" \
            "$memory" \
            "0" \
            "$command" \
            >> "$PROCESS_FILE"
    done
}

record_gpu_processes() {
    local timestamp="$1"
    local pid=""
    local gpu_memory=""
    local process_name=""
    local ppid=""
    local user=""
    local cpu=""
    local memory=""
    local command=""

    if ! command_exists nvidia-smi; then
        return
    fi

    nvidia-smi \
        --query-compute-apps=pid,used_memory,process_name \
        --format=csv,noheader,nounits 2>/dev/null |
    awk -F',' -v limit="$TOP_PROCESS_COUNT" '
        NF > 0 && count < limit {
            for (i=1; i<=NF; i++) {
                gsub(/^[ \t]+/, "", $i)
                gsub(/[ \t]+$/, "", $i)
            }

            print $1 "|" $2 "|" $3
            count++
        }
    ' |
    while IFS='|' read -r pid gpu_memory process_name; do
        if [[ -z "$pid" ]]; then
            continue
        fi

        ppid="$(
            ps -p "$pid" -o ppid= 2>/dev/null |
            awk '{$1=$1; print}'
        )"

        user="$(
            ps -p "$pid" -o user= 2>/dev/null |
            awk '{$1=$1; print}'
        )"

        cpu="$(
            ps -p "$pid" -o pcpu= 2>/dev/null |
            awk '{$1=$1; print}'
        )"

        memory="$(
            ps -p "$pid" -o pmem= 2>/dev/null |
            awk '{$1=$1; print}'
        )"

        command="$(
            ps -p "$pid" -o args= 2>/dev/null |
            head -n1
        )"

        if [[ -z "$command" ]]; then
            command="$process_name"
        fi

        command="$(printf '%s' "$command" | sanitize_command)"

        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$timestamp" \
            "GPU" \
            "$pid" \
            "${ppid:-0}" \
            "${user:-unknown}" \
            "${cpu:-0}" \
            "${memory:-0}" \
            "${gpu_memory:-0}" \
            "$command" \
            >> "$PROCESS_FILE"
    done
}

record_processes() {
    local timestamp="$1"

    record_cpu_processes "$timestamp"
    record_memory_processes "$timestamp"
    record_gpu_processes "$timestamp"
}

cleanup() {
    echo
    echo "Monitoring stopped."
    echo "System metrics saved to: $OUTPUT_FILE"
    echo "Process metrics saved to: $PROCESS_FILE"
}

trap cleanup EXIT INT TERM

if [[ -z "$NETWORK_INTERFACE" ]]; then
    NETWORK_INTERFACE="$(detect_network_interface)"
fi

if [[ -z "$DISK_DEVICE" ]]; then
    DISK_DEVICE="$(detect_disk_device)"
fi

DISK_DEVICE="$(resolve_disk_device "$DISK_DEVICE")"

if [[ -z "$NETWORK_INTERFACE" ]]; then
    echo "Unable to detect network interface." >&2
    echo "Set it explicitly, for example:" >&2
    echo "NETWORK_INTERFACE=ens14f1np1 $0 $OUTPUT_FILE" >&2
    exit 1
fi

if [[ -z "$DISK_DEVICE" ]]; then
    echo "Unable to detect disk device." >&2
    echo "Set it explicitly, for example:" >&2
    echo "DISK_DEVICE=dm-1 $0 $OUTPUT_FILE" >&2
    exit 1
fi

if [[ ! -r "/sys/class/block/${DISK_DEVICE}/stat" ]] &&
   [[ ! -r "/sys/block/${DISK_DEVICE}/stat" ]]; then
    echo "Disk device does not exist in sysfs: $DISK_DEVICE" >&2
    echo "Available devices:" >&2
    ls /sys/class/block >&2
    exit 1
fi

if [[ ! -s "$OUTPUT_FILE" ]]; then
    printf '%s\n' \
'timestamp,epoch,cpu_percent,memory_used_mib,memory_total_mib,memory_percent,load_1m,load_5m,load_15m,gpu_percent,gpu_memory_used_mib,gpu_memory_total_mib,gpu_temperature_c,gpu_power_w,disk_read_mib_s,disk_write_mib_s,network_rx_mib_s,network_tx_mib_s,network_interface,disk_device' \
        > "$OUTPUT_FILE"
fi

if [[ ! -s "$PROCESS_FILE" ]]; then
    printf '%s\n' \
'timestamp,category,pid,ppid,user,cpu_percent,memory_percent,gpu_memory_mib,command' \
        > "$PROCESS_FILE"
fi

read -r previous_cpu_total previous_cpu_idle < <(read_cpu_counters)

read -r previous_rx previous_tx < <(
    read_network_counters "$NETWORK_INTERFACE"
)

read -r previous_read_sectors previous_write_sectors < <(
    read_disk_counters "$DISK_DEVICE"
)

previous_epoch="$(date +%s)"

echo "Collecting metrics every ${INTERVAL} seconds"
echo "System metrics file: $OUTPUT_FILE"
echo "Process metrics file: $PROCESS_FILE"
echo "Network interface:   $NETWORK_INTERFACE"
echo "Disk device:         $DISK_DEVICE"
echo "Top processes:       $TOP_PROCESS_COUNT per category"
echo "Press Ctrl+C to stop."

while true; do
    sleep "$INTERVAL"

    current_epoch="$(date +%s)"
    timestamp="$(date --iso-8601=seconds)"

    elapsed=$((current_epoch - previous_epoch))

    if (( elapsed <= 0 )); then
        elapsed="$INTERVAL"
    fi

    read -r current_cpu_total current_cpu_idle < <(read_cpu_counters)

    cpu_total_delta=$((current_cpu_total - previous_cpu_total))
    cpu_idle_delta=$((current_cpu_idle - previous_cpu_idle))

    cpu_percent="$(
        awk \
            -v total="$cpu_total_delta" \
            -v idle="$cpu_idle_delta" '
            BEGIN {
                value=0

                if (total > 0) {
                    value=(total-idle)*100/total
                }

                printf "%.2f", value
            }
        '
    )"

    read -r \
        memory_used \
        memory_total \
        memory_percent \
        < <(read_memory_metrics)

    read -r \
        load_1m \
        load_5m \
        load_15m \
        < <(read_load_average)

    read -r \
        gpu_percent \
        gpu_memory_used \
        gpu_memory_total \
        gpu_temperature \
        gpu_power \
        < <(read_gpu_metrics)

    read -r current_rx current_tx < <(
        read_network_counters "$NETWORK_INTERFACE"
    )

    rx_delta=$((current_rx - previous_rx))
    tx_delta=$((current_tx - previous_tx))

    if (( rx_delta < 0 )); then
        rx_delta=0
    fi

    if (( tx_delta < 0 )); then
        tx_delta=0
    fi

    network_rx_mib_s="$(
        awk \
            -v bytes="$rx_delta" \
            -v seconds="$elapsed" '
            BEGIN {
                value=0

                if (seconds > 0) {
                    value=bytes/seconds/1048576
                }

                printf "%.4f", value
            }
        '
    )"

    network_tx_mib_s="$(
        awk \
            -v bytes="$tx_delta" \
            -v seconds="$elapsed" '
            BEGIN {
                value=0

                if (seconds > 0) {
                    value=bytes/seconds/1048576
                }

                printf "%.4f", value
            }
        '
    )"

    read -r current_read_sectors current_write_sectors < <(
        read_disk_counters "$DISK_DEVICE"
    )

    read_sectors_delta=$((current_read_sectors - previous_read_sectors))
    write_sectors_delta=$((current_write_sectors - previous_write_sectors))

    if (( read_sectors_delta < 0 )); then
        read_sectors_delta=0
    fi

    if (( write_sectors_delta < 0 )); then
        write_sectors_delta=0
    fi

    disk_read_mib_s="$(
        awk \
            -v sectors="$read_sectors_delta" \
            -v seconds="$elapsed" '
            BEGIN {
                value=0

                if (seconds > 0) {
                    value=sectors*512/seconds/1048576
                }

                printf "%.4f", value
            }
        '
    )"

    disk_write_mib_s="$(
        awk \
            -v sectors="$write_sectors_delta" \
            -v seconds="$elapsed" '
            BEGIN {
                value=0

                if (seconds > 0) {
                    value=sectors*512/seconds/1048576
                }

                printf "%.4f", value
            }
        '
    )"

    printf '%s\n' \
"${timestamp},${current_epoch},${cpu_percent},${memory_used},${memory_total},${memory_percent},${load_1m},${load_5m},${load_15m},${gpu_percent},${gpu_memory_used},${gpu_memory_total},${gpu_temperature},${gpu_power},${disk_read_mib_s},${disk_write_mib_s},${network_rx_mib_s},${network_tx_mib_s},${NETWORK_INTERFACE},${DISK_DEVICE}" \
        >> "$OUTPUT_FILE"

    record_processes "$timestamp"

    printf '\r%s CPU:%6s%% MEM:%6s%% GPU:%6s%% Disk R/W:%8s/%8s MiB/s Net RX/TX:%8s/%8s MiB/s' \
        "$timestamp" \
        "$cpu_percent" \
        "$memory_percent" \
        "$gpu_percent" \
        "$disk_read_mib_s" \
        "$disk_write_mib_s" \
        "$network_rx_mib_s" \
        "$network_tx_mib_s"

    previous_cpu_total="$current_cpu_total"
    previous_cpu_idle="$current_cpu_idle"

    previous_rx="$current_rx"
    previous_tx="$current_tx"

    previous_read_sectors="$current_read_sectors"
    previous_write_sectors="$current_write_sectors"

    previous_epoch="$current_epoch"
done
