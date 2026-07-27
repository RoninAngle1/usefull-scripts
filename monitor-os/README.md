# Linux System Monitoring Toolkit

A lightweight Linux monitoring toolkit for collecting host performance metrics and generating a standalone HTML performance report.

The toolkit consists of two Bash scripts:

| Script | Purpose |
|----------|----------|
| `collect-system-metrics.sh` | Continuously collects system and process metrics into CSV files |
| `generate-monitoring-report.sh` | Generates a standalone HTML report with graphs and process tables |

---

# Features

## System Metrics

Collects:

- CPU utilization
- Memory usage
- Load averages (1, 5, 15 minutes)
- GPU utilization
- GPU memory usage
- GPU temperature
- GPU power consumption
- Disk read throughput
- Disk write throughput
- Network receive throughput
- Network transmit throughput

---

## Process Metrics

Collects:

- Top CPU consuming processes
- Top Memory consuming processes
- GPU compute processes
- PID
- PPID
- Username
- CPU %
- Memory %
- GPU Memory Usage
- Full command line

---

## HTML Report

Produces a standalone HTML report containing:

- Executive summary
- CPU utilization chart
- Memory utilization chart
- GPU utilization chart
- Disk throughput chart
- Network throughput chart
- System load chart
- GPU detail chart
- CPU process table
- Memory process table
- GPU process table
- PID → Command mapping

No external JavaScript libraries are required.

Everything is embedded into a single HTML file.

---

# Directory Layout

```
monitor-system/
│
├── collect-system-metrics.sh
├── generate-monitoring-report.sh
│
├── system_metrics.csv
├── system_metrics_processes.csv
│
└── monitoring-report.html
```

---

# Requirements

## Operating System

Linux

Tested on:

- Ubuntu
- RHEL
- Rocky
- AlmaLinux

---

## Required Packages

### Mandatory

- bash
- awk
- ps
- date

### Optional

For NVIDIA GPU metrics

```
nvidia-smi
```

If unavailable, GPU metrics are automatically recorded as zero.

---

# Script 1

# collect-system-metrics.sh

## Purpose

Continuously collects system performance metrics.

Metrics are written into CSV files every few seconds.

---

## Output Files

### System metrics

```
system_metrics.csv
```

### Process metrics

```
system_metrics_processes.csv
```

---

## Environment Variables

### INTERVAL

Sampling interval.

Default

```
5
```

Example

```
INTERVAL=2
```

---

### TOP_PROCESS_COUNT

Number of processes collected for each category.

Default

```
10
```

Example

```
TOP_PROCESS_COUNT=20
```

---

### NETWORK_INTERFACE

Network interface.

Normally auto detected.

Example

```
NETWORK_INTERFACE=ens160
```

---

### DISK_DEVICE

Linux block device.

Examples

```
sda

nvme0n1

dm-1
```

---

### PROCESS_FILE

Optional process CSV filename.

Default

```
system_metrics_processes.csv
```

---

# Running

Example

```
DISK_DEVICE=dm-1 \
TOP_PROCESS_COUNT=10 \
./collect-system-metrics.sh system_metrics.csv
```

---

# Example Console Output

```
Collecting metrics every 5 seconds

System metrics file:
system_metrics.csv

Process metrics file:
system_metrics_processes.csv

Network interface:
ens14f1np1

Disk device:
dm-1

Top processes:
10

Press Ctrl+C to stop...
```

---

# Example system_metrics.csv

```
timestamp,epoch,cpu_percent,memory_used_mib,memory_total_mib,memory_percent,...
2026-07-26T12:45:00,1785069900,13.42,20581,32768,62.8,...
```

---

# Example system_metrics_processes.csv

```
timestamp,category,pid,ppid,user,cpu_percent,memory_percent,gpu_memory_mib,command

2026-07-26T12:45:00,CPU,31251,1,root,96.3,1.2,0,python main.py

2026-07-26T12:45:00,MEMORY,2287,1,postgres,1.1,18.6,0,postgres

2026-07-26T12:45:00,GPU,31251,1,root,96.3,1.2,15360,python main.py
```

---

# Script 2

# generate-monitoring-report.sh

## Purpose

Converts the collected CSV files into a standalone HTML dashboard.

No internet connection is required.

No external CSS.

No external JavaScript.

No Python.

No NodeJS.

---

# Inputs

### Required

```
system_metrics.csv
```

### Optional

```
system_metrics_processes.csv
```

If the process CSV is unavailable, the report is still generated.

---

# Output

```
monitoring-report.html
```

---

# Running

```
./generate-monitoring-report.sh \
system_metrics.csv \
monitoring-report.html \
system_metrics_processes.csv
```

---

# Report Contents

## Executive Summary

Includes

- Peak CPU
- Peak Memory
- Peak GPU
- Peak Disk Read
- Peak Network Receive
- Total Samples

---

## Charts

### CPU Utilization

Time series chart

---

### Memory Utilization

Time series chart

---

### GPU Utilization

Time series chart

---

### Disk Throughput

Read

Write

---

### Network Throughput

Receive

Transmit

---

### System Load

1 minute

5 minute

15 minute

---

### GPU Details

GPU Memory

Temperature

Power Consumption

---

## Process Tables

Latest CPU Processes

| PID | User | CPU % | Command |
|-----|------|--------|----------|

---

Latest Memory Processes

| PID | User | Memory % | Command |
|-----|------|-----------|----------|

---

Latest GPU Processes

| PID | GPU Memory | Command |
|-----|-------------|----------|

---

PID Mapping

Every PID observed during monitoring.

---

# Typical Workflow

```
Start Monitoring
        │
        ▼
collect-system-metrics.sh
        │
        ├──────────────► system_metrics.csv
        │
        └──────────────► system_metrics_processes.csv
                                │
                                ▼
                generate-monitoring-report.sh
                                │
                                ▼
                 monitoring-report.html
```

---

# Stopping Monitoring

Press

```
CTRL+C
```

The collector exits gracefully and flushes all data to disk.

---

# Performance Impact

Typical overhead

CPU

Less than 1%

Memory

Less than 20 MB

Disk

Very small sequential CSV writes

GPU

One lightweight `nvidia-smi` invocation per sampling interval

---

# Customization

Increase sampling frequency

```
INTERVAL=1
```

Collect more processes

```
TOP_PROCESS_COUNT=25
```

Monitor another interface

```
NETWORK_INTERFACE=bond0
```

Specify another disk

```
DISK_DEVICE=nvme0n1
```

Use another output location

```
./collect-system-metrics.sh /var/log/system_metrics.csv
```

---

# Troubleshooting

## No GPU Metrics

Verify

```
nvidia-smi
```

is available.

---

## No Process Metrics

Verify

```
system_metrics_processes.csv
```

exists.

---

## Empty Charts

Verify

```
system_metrics.csv
```

contains more than one row.

---

## Incorrect Disk Throughput

Specify the correct block device.

Example

```
DISK_DEVICE=dm-1
```

or

```
DISK_DEVICE=nvme0n1
```

---

## Incorrect Network Statistics

Specify

```
NETWORK_INTERFACE
```

explicitly.

---

# Future Improvements

Possible enhancements include:

- Multi-host monitoring
- Prometheus exporter
- Live web dashboard
- Email reports
- Slack notifications
- Threshold-based alerts
- Historical report comparison
- Interactive charts
- Per-core CPU charts
- NUMA statistics
- Container monitoring
- Kubernetes pod monitoring
- NVLink statistics
- PCIe bandwidth monitoring
- JSON export
- PDF report generation

---

# License

Internal Use

Modify and distribute according to your organization's policies.

---
