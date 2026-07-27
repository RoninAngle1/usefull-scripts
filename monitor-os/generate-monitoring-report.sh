#!/usr/bin/env bash

set -Eeuo pipefail

INPUT_FILE="${1:-system_metrics.csv}"
OUTPUT_FILE="${2:-monitoring-report.html}"
PROCESS_FILE="${3:-${INPUT_FILE%.csv}_processes.csv}"

if [[ ! -r "$INPUT_FILE" ]]; then
    echo "Metrics file not found: $INPUT_FILE" >&2
    exit 1
fi

if [[ "$(wc -l < "$INPUT_FILE")" -lt 2 ]]; then
    echo "Metrics file contains no data: $INPUT_FILE" >&2
    exit 1
fi

awk -F',' '
BEGIN {
    width=1400
    height=420
    margin_left=80
    margin_right=30
    margin_top=50
    margin_bottom=70
}

NR == 1 {
    for (i=1; i<=NF; i++) {
        header[$i]=i
    }
    next
}

{
    count++

    timestamp[count]=$(header["timestamp"])
    cpu[count]=$(header["cpu_percent"])+0
    memory[count]=$(header["memory_percent"])+0
    gpu[count]=$(header["gpu_percent"])+0

    gpu_memory[count]=$(header["gpu_memory_used_mib"])+0
    gpu_temperature[count]=$(header["gpu_temperature_c"])+0
    gpu_power[count]=$(header["gpu_power_w"])+0

    disk_read[count]=$(header["disk_read_mib_s"])+0
    disk_write[count]=$(header["disk_write_mib_s"])+0

    network_rx[count]=$(header["network_rx_mib_s"])+0
    network_tx[count]=$(header["network_tx_mib_s"])+0

    load_1m[count]=$(header["load_1m"])+0
    load_5m[count]=$(header["load_5m"])+0
    load_15m[count]=$(header["load_15m"])+0
}

function html_escape(value, result) {
    result=value
    gsub(/&/, "\\&amp;", result)
    gsub(/</, "\\&lt;", result)
    gsub(/>/, "\\&gt;", result)
    gsub(/"/, "\\&quot;", result)
    return result
}

function array_max(values, result, idx) {
    result=0
    for (idx=1; idx<=count; idx++) {
        if (values[idx] > result) {
            result=values[idx]
        }
    }
    return result
}

function max_three(first, second, third, result) {
    result=first
    if (second > result) {
        result=second
    }
    if (third > result) {
        result=third
    }
    return result
}

function coordinate_x(idx, result) {
    if (count <= 1) {
        return margin_left
    }

    result=margin_left+((idx-1)*(width-margin_left-margin_right)/(count-1))
    return result
}

function coordinate_y(value, maximum_value, result) {
    if (maximum_value <= 0) {
        maximum_value=1
    }

    result=margin_top+((height-margin_top-margin_bottom)*(1-value/maximum_value))
    return result
}

function chart_begin(title, subtitle, maximum_value, idx, y, tick_value, sample_index, x, timestamp_label) {
    print "<section class=\"card\">"
    print "<h2>" html_escape(title) "</h2>"
    print "<p class=\"subtitle\">" html_escape(subtitle) "</p>"
    print "<svg viewBox=\"0 0 " width " " height "\">"
    print "<rect width=\"" width "\" height=\"" height "\" fill=\"white\"/>"

    for (idx=0; idx<=5; idx++) {
        y=margin_top+(idx*(height-margin_top-margin_bottom)/5)
        tick_value=maximum_value*(5-idx)/5

        print "<line x1=\"" margin_left "\" y1=\"" y "\" x2=\"" width-margin_right "\" y2=\"" y "\" class=\"grid\"/>"

        printf "<text x=\"%d\" y=\"%.2f\" class=\"axis-label\" text-anchor=\"end\">%.2f</text>\n", margin_left-10, y+4, tick_value
    }

    print "<line x1=\"" margin_left "\" y1=\"" margin_top "\" x2=\"" margin_left "\" y2=\"" height-margin_bottom "\" class=\"axis\"/>"
    print "<line x1=\"" margin_left "\" y1=\"" height-margin_bottom "\" x2=\"" width-margin_right "\" y2=\"" height-margin_bottom "\" class=\"axis\"/>"

    for (idx=1; idx<=6; idx++) {
        sample_index=1+int((count-1)*(idx-1)/5)
        x=coordinate_x(sample_index)
        timestamp_label=timestamp[sample_index]

        print "<text x=\"" x "\" y=\"" height-margin_bottom+25 "\" class=\"time-label\" text-anchor=\"middle\">" html_escape(timestamp_label) "</text>"
    }
}

function draw_polyline(values, maximum_value, css_class, idx, points, x, y) {
    points=""

    for (idx=1; idx<=count; idx++) {
        x=coordinate_x(idx)
        y=coordinate_y(values[idx],maximum_value)
        points=points sprintf("%.2f,%.2f ",x,y)
    }

    print "<polyline points=\"" points "\" class=\"" css_class "\"/>"
}

function draw_legend(x, y, label, css_class) {
    print "<line x1=\"" x "\" y1=\"" y "\" x2=\"" x+30 "\" y2=\"" y "\" class=\"" css_class "\"/>"
    print "<text x=\"" x+40 "\" y=\"" y+4 "\" class=\"legend\">" html_escape(label) "</text>"
}

function chart_end() {
    print "</svg>"
    print "</section>"
}

END {
    if (count == 0) {
        exit 3
    }

    cpu_max=array_max(cpu)
    memory_max=array_max(memory)
    gpu_max=array_max(gpu)

    disk_read_max=array_max(disk_read)
    disk_write_max=array_max(disk_write)

    network_rx_max=array_max(network_rx)
    network_tx_max=array_max(network_tx)

    load_1m_max=array_max(load_1m)
    load_5m_max=array_max(load_5m)
    load_15m_max=array_max(load_15m)

    gpu_memory_max=array_max(gpu_memory)
    gpu_temperature_max=array_max(gpu_temperature)
    gpu_power_max=array_max(gpu_power)

    print "<!doctype html>"
    print "<html lang=\"en\">"
    print "<head>"
    print "<meta charset=\"utf-8\">"
    print "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    print "<title>System Monitoring Report</title>"

    print "<style>"
    print "body{font-family:Arial,sans-serif;background:#f4f6f8;margin:0;padding:24px;color:#1f2937}"
    print ".container{max-width:1500px;margin:auto}"
    print ".card{background:white;padding:20px;margin-bottom:24px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.08);overflow-x:auto}"
    print "h1{margin-top:0}"
    print "h2{margin-bottom:5px}"
    print "h3{margin-top:28px;margin-bottom:10px}"
    print ".subtitle{margin-top:0;color:#6b7280}"
    print "svg{width:100%;height:auto;min-width:900px}"
    print ".grid{stroke:#e5e7eb;stroke-width:1}"
    print ".axis{stroke:#374151;stroke-width:1.2}"
    print ".axis-label,.time-label,.legend{font-size:12px;fill:#374151}"
    print ".line1{fill:none;stroke:#2563eb;stroke-width:2.5}"
    print ".line2{fill:none;stroke:#dc2626;stroke-width:2.5}"
    print ".line3{fill:none;stroke:#16a34a;stroke-width:2.5}"
    print ".summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}"
    print ".summary div{background:white;padding:16px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.06)}"
    print ".summary strong{display:block;font-size:22px;margin-top:6px}"
    print "table{width:100%;border-collapse:collapse;font-size:14px;margin-bottom:24px}"
    print "th,td{text-align:left;padding:9px;border-bottom:1px solid #e5e7eb;vertical-align:top}"
    print "th{background:#f8fafc}"
    print "code{white-space:pre-wrap;word-break:break-word}"
    print ".empty{color:#6b7280;font-style:italic}"
    print "</style>"

    print "</head>"
    print "<body>"
    print "<div class=\"container\">"

    print "<h1>System Monitoring Report</h1>"
    print "<p>Metrics source: " html_escape(ARGV[1]) "</p>"

    print "<div class=\"summary\">"
    printf "<div>Samples<strong>%d</strong></div>\n",count
    printf "<div>Peak CPU<strong>%.2f%%</strong></div>\n",cpu_max
    printf "<div>Peak Memory<strong>%.2f%%</strong></div>\n",memory_max
    printf "<div>Peak GPU<strong>%.2f%%</strong></div>\n",gpu_max
    printf "<div>Peak Disk Read<strong>%.2f MiB/s</strong></div>\n",disk_read_max
    printf "<div>Peak Network RX<strong>%.2f MiB/s</strong></div>\n",network_rx_max
    print "</div>"

    chart_begin("CPU Utilization","System-wide CPU usage percentage over time",100)
    draw_polyline(cpu,100,"line1")
    draw_legend(100,25,"CPU %","line1")
    chart_end()

    chart_begin("Memory Utilization","System-wide memory usage percentage over time",100)
    draw_polyline(memory,100,"line2")
    draw_legend(100,25,"Memory %","line2")
    chart_end()

    chart_begin("GPU Utilization","Average GPU utilization percentage over time",100)
    draw_polyline(gpu,100,"line3")
    draw_legend(100,25,"GPU %","line3")
    chart_end()

    disk_max=disk_read_max
    if (disk_write_max > disk_max) {
        disk_max=disk_write_max
    }
    if (disk_max <= 0) {
        disk_max=1
    }

    chart_begin("Disk I/O Throughput","Disk read and write throughput in MiB/s",disk_max)
    draw_polyline(disk_read,disk_max,"line1")
    draw_polyline(disk_write,disk_max,"line2")
    draw_legend(100,25,"Read MiB/s","line1")
    draw_legend(280,25,"Write MiB/s","line2")
    chart_end()

    network_max=network_rx_max
    if (network_tx_max > network_max) {
        network_max=network_tx_max
    }
    if (network_max <= 0) {
        network_max=1
    }

    chart_begin("Network Throughput","Network receive and transmit throughput in MiB/s",network_max)
    draw_polyline(network_rx,network_max,"line1")
    draw_polyline(network_tx,network_max,"line2")
    draw_legend(100,25,"Receive MiB/s","line1")
    draw_legend(300,25,"Transmit MiB/s","line2")
    chart_end()

    load_max=max_three(load_1m_max,load_5m_max,load_15m_max)
    if (load_max <= 0) {
        load_max=1
    }

    chart_begin("System Load Average","One, five and fifteen minute load averages",load_max)
    draw_polyline(load_1m,load_max,"line1")
    draw_polyline(load_5m,load_max,"line2")
    draw_polyline(load_15m,load_max,"line3")
    draw_legend(100,25,"Load 1m","line1")
    draw_legend(240,25,"Load 5m","line2")
    draw_legend(380,25,"Load 15m","line3")
    chart_end()

    gpu_detail_max=max_three(gpu_memory_max,gpu_temperature_max,gpu_power_max)
    if (gpu_detail_max <= 0) {
        gpu_detail_max=1
    }

    chart_begin("GPU Details","GPU memory, temperature and power usage",gpu_detail_max)
    draw_polyline(gpu_memory,gpu_detail_max,"line1")
    draw_polyline(gpu_temperature,gpu_detail_max,"line2")
    draw_polyline(gpu_power,gpu_detail_max,"line3")
    draw_legend(100,25,"GPU memory MiB","line1")
    draw_legend(310,25,"Temperature C","line2")
    draw_legend(510,25,"Power W","line3")
    chart_end()
}
' "$INPUT_FILE" > "$OUTPUT_FILE"

if [[ -r "$PROCESS_FILE" ]] && [[ "$(wc -l < "$PROCESS_FILE")" -gt 1 ]]; then

awk -F',' '
function html_escape(value, result) {
    result=value
    gsub(/&/, "\\&amp;", result)
    gsub(/</, "\\&lt;", result)
    gsub(/>/, "\\&gt;", result)
    gsub(/"/, "\\&quot;", result)
    return result
}

NR == 1 {
    for (i=1; i<=NF; i++) {
        header[$i]=i
    }
    next
}

{
    row_timestamp=$(header["timestamp"])
    category=$(header["category"])
    pid=$(header["pid"])
    ppid=$(header["ppid"])
    user=$(header["user"])
    cpu_percent=$(header["cpu_percent"])
    memory_percent=$(header["memory_percent"])
    gpu_memory_mib=$(header["gpu_memory_mib"])

    command=""
    command_column=header["command"]

    if (command_column > 0) {
        command=$command_column

        for (i=command_column+1; i<=NF; i++) {
            command=command "," $i
        }
    }

    if (latest_timestamp == "" || row_timestamp > latest_timestamp) {
        latest_timestamp=row_timestamp
    }

    key=category SUBSEP pid

    process_timestamp[key]=row_timestamp
    process_ppid[key]=ppid
    process_user[key]=user
    process_cpu[key]=cpu_percent
    process_memory[key]=memory_percent
    process_gpu_memory[key]=gpu_memory_mib
    process_command[key]=command

    pid_command[pid]=command
    pid_user[pid]=user
    pid_ppid[pid]=ppid
}

END {
    print "<section class=\"card\">"
    print "<h2>Latest Process Tables</h2>"
    print "<p class=\"subtitle\">Latest process sample: " html_escape(latest_timestamp) "</p>"

    categories[1]="CPU"
    categories[2]="MEMORY"
    categories[3]="GPU"

    for (category_index=1; category_index<=3; category_index++) {
        category_name=categories[category_index]

        print "<h3>" html_escape(category_name) " Processes</h3>"
        print "<table>"
        print "<thead>"
        print "<tr>"
        print "<th>PID</th>"
        print "<th>PPID</th>"
        print "<th>User</th>"
        print "<th>CPU %</th>"
        print "<th>Memory %</th>"
        print "<th>GPU Memory MiB</th>"
        print "<th>Command</th>"
        print "</tr>"
        print "</thead>"
        print "<tbody>"

        found=0

        for (key in process_timestamp) {
            split(key,key_parts,SUBSEP)

            stored_category=key_parts[1]
            stored_pid=key_parts[2]

            if (stored_category == category_name && process_timestamp[key] == latest_timestamp) {
                found=1

                print "<tr>"
                print "<td>" html_escape(stored_pid) "</td>"
                print "<td>" html_escape(process_ppid[key]) "</td>"
                print "<td>" html_escape(process_user[key]) "</td>"
                print "<td>" html_escape(process_cpu[key]) "</td>"
                print "<td>" html_escape(process_memory[key]) "</td>"
                print "<td>" html_escape(process_gpu_memory[key]) "</td>"
                print "<td><code>" html_escape(process_command[key]) "</code></td>"
                print "</tr>"
            }
        }

        if (!found) {
            print "<tr><td colspan=\"7\" class=\"empty\">No process data for this category.</td></tr>"
        }

        print "</tbody>"
        print "</table>"
    }

    print "</section>"

    print "<section class=\"card\">"
    print "<h2>PID to Command Mapping</h2>"
    print "<table>"
    print "<thead>"
    print "<tr>"
    print "<th>PID</th>"
    print "<th>PPID</th>"
    print "<th>User</th>"
    print "<th>Command</th>"
    print "</tr>"
    print "</thead>"
    print "<tbody>"

    for (pid in pid_command) {
        print "<tr>"
        print "<td>" html_escape(pid) "</td>"
        print "<td>" html_escape(pid_ppid[pid]) "</td>"
        print "<td>" html_escape(pid_user[pid]) "</td>"
        print "<td><code>" html_escape(pid_command[pid]) "</code></td>"
        print "</tr>"
    }

    print "</tbody>"
    print "</table>"
    print "</section>"
}
' "$PROCESS_FILE" >> "$OUTPUT_FILE"

else

cat >> "$OUTPUT_FILE" <<EOF
<section class="card">
    <h2>Process Tables</h2>
    <p class="empty">
        Process metrics file does not exist or contains no data:
        <code>${PROCESS_FILE}</code>
    </p>
</section>
EOF

fi

cat >> "$OUTPUT_FILE" <<'EOF'
</div>
</body>
</html>
EOF

echo "Monitoring report created successfully."
echo "Metrics input:  $INPUT_FILE"
echo "Process input:  $PROCESS_FILE"
echo "HTML report:    $OUTPUT_FILE"
