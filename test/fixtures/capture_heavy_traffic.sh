#!/bin/bash
# Capture script for generating large mixed HTTP (GET/POST) and UDP traffic.
# Produces sustained load across multiple interfaces to feed benchmarking data.

set -euo pipefail

: "${HTTP_PORT:=8899}"
: "${UDP_PORT:=8898}"
DEFAULT_OUTPUT="large_capture.pcapng"
OUTPUT_FILE=""
OUTPUT_DIR="."
CAPTURE_DURATION=60
INTERFACES=("lo0")
HTTP_WORKERS=6
HTTP_PAYLOAD=2048
HTTP_SLEEP=0.01
UDP_RATE=800
UDP_PAYLOAD=512
REQUEST_NANO=0
WRITE_PCAP_COMPANION=1
DUMPCAP_PCAPNG_PID=""
DUMPCAP_PCAP_PID=""
SERVER_PID=""
UDP_SERVER_PID=""
HTTP_LOAD_PID=""
UDP_LOAD_PID=""

usage() {
  cat <<'EOF'
Usage: ./capture_heavy_traffic.sh [options]

Options:
  -o, --output <file>        Capture filename (default: large_capture.pcapng)
  -d, --duration <seconds>   Capture duration (default: 60)
  -i, --interfaces <list>    Comma-separated interface list (default: lo0)
      --output-dir <dir>     Directory for capture files (default: current dir)
      --no-pcap              Disable companion .pcap output (pcapng only)
      --http-port <port>     HTTP server/listener port (default: 8899)
      --http-workers <n>     HTTP worker threads (default: 6)
      --http-payload <bytes> POST payload size (default: 2048)
      --http-sleep <seconds> Sleep between HTTP cycles (default: 0.01)
      --udp-port <port>      UDP server/listener port (default: 8898)
      --udp-rate <pps>       UDP datagrams per second (default: 800)
      --udp-payload <bytes>  UDP payload size (default: 512)
      --nanosecond           Request nanosecond timestamps (pcapng only)
      --list-interfaces      List available capture interfaces and exit
  -h, --help                 Show this help text and exit

Environment:
  Set HTTP_PORT / UDP_PORT to override default server ports before running.

Examples:
  ./capture_heavy_traffic.sh -d 120 --interfaces lo0,en0
  ./capture_heavy_traffic.sh --output-dir ./captures --no-pcap
EOF
}

require_dumpcap() {
  if ! command -v dumpcap >/dev/null 2>&1; then
    echo "Error: dumpcap not found in PATH" >&2
    echo "Install Wireshark or add dumpcap to your PATH." >&2
    exit 1
  fi
}

parse_args() {
  local positional_done=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output)
        OUTPUT_FILE="$2"
        shift 2
        ;;
      --output-dir)
        OUTPUT_DIR="$2"
        shift 2
        ;;
      -d|--duration)
        CAPTURE_DURATION="$2"
        shift 2
        ;;
      -i|--interfaces)
        IFS=',' read -r -a INTERFACES <<<"$2"
        shift 2
        ;;
      --no-pcap)
        WRITE_PCAP_COMPANION=0
        shift
        ;;
      --http-workers)
        HTTP_WORKERS="$2"
        shift 2
        ;;
      --http-port)
        HTTP_PORT="$2"
        shift 2
        ;;
      --http-payload)
        HTTP_PAYLOAD="$2"
        shift 2
        ;;
      --http-sleep)
        HTTP_SLEEP="$2"
        shift 2
        ;;
      --udp-rate)
        UDP_RATE="$2"
        shift 2
        ;;
      --udp-port)
        UDP_PORT="$2"
        shift 2
        ;;
      --udp-payload)
        UDP_PAYLOAD="$2"
        shift 2
        ;;
      --nanosecond)
        REQUEST_NANO=1
        shift
        ;;
      --list-interfaces)
        require_dumpcap
        dumpcap -D
        exit 0
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        shift
        break
        ;;
      -*)
        echo "Unknown option: $1" >&2
        usage
        exit 1
        ;;
      *)
        if [[ $positional_done -eq 0 ]]; then
          OUTPUT_FILE="$1"
          positional_done=1
          shift
        else
          echo "Unexpected argument: $1" >&2
          usage
          exit 1
        fi
        ;;
    esac
  done
}

ensure_ports_available() {
  if lsof -Pi :"$HTTP_PORT" -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "Error: HTTP port $HTTP_PORT is already in use" >&2
    exit 1
  fi

  if lsof -Pi :"$UDP_PORT" -t >/dev/null 2>&1; then
    echo "Error: UDP port $UDP_PORT is already in use" >&2
    exit 1
  fi
}

prepare_environment() {
  if [[ $REQUEST_NANO -eq 1 ]]; then
    export WIRESHARK_PCAPNG_DEFAULT_TSPRECISION=9
    export WIRESHARK_PCAPNG_DEFAULT_TSRESOL=9
  fi
}

start_servers() {
  echo "Starting HTTP server on port $HTTP_PORT..."
  python3 http_server.py "$HTTP_PORT" &
  SERVER_PID=$!

  echo "Starting UDP server on port $UDP_PORT..."
  python3 udp_server.py "$UDP_PORT" &
  UDP_SERVER_PID=$!

  sleep 1

  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Error: Failed to start HTTP server" >&2
    exit 1
  fi

  if ! kill -0 "$UDP_SERVER_PID" 2>/dev/null; then
    echo "Error: Failed to start UDP server" >&2
    exit 1
  fi
}

stop_servers() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi

  if [[ -n "$UDP_SERVER_PID" ]]; then
    kill "$UDP_SERVER_PID" 2>/dev/null || true
    wait "$UDP_SERVER_PID" 2>/dev/null || true
    UDP_SERVER_PID=""
  fi
}

start_captures() {
  local capture_filter="(tcp port $HTTP_PORT) or (udp port $UDP_PORT)"
  local interface_flags=()

  for iface in "${INTERFACES[@]}"; do
    interface_flags+=("-i" "$iface")
  done

  local pcapng_path="$OUTPUT_DIR/$OUTPUT_FILE"
  mkdir -p "$OUTPUT_DIR"

  local duration_arg
  duration_arg=$(printf "%.0f" "$CAPTURE_DURATION")

  local pcapng_cmd=(dumpcap "${interface_flags[@]}" -f "$capture_filter" -w "$pcapng_path" -q -a "duration:$duration_arg")

  "${pcapng_cmd[@]}" &
  DUMPCAP_PCAPNG_PID=$!

  if [[ $WRITE_PCAP_COMPANION -eq 1 ]]; then
    local pcap_path="${pcapng_path%.pcapng}.pcap"
    local pcap_cmd=(dumpcap "${interface_flags[@]}" -f "$capture_filter" -w "$pcap_path" -q -P -a "duration:$duration_arg")
    "${pcap_cmd[@]}" &
    DUMPCAP_PCAP_PID=$!
  fi

  sleep 1

  if ! kill -0 "$DUMPCAP_PCAPNG_PID" 2>/dev/null; then
    echo "Error: Failed to start PCAPNG capture" >&2
    exit 1
  fi

  if [[ -n "$DUMPCAP_PCAP_PID" ]] && ! kill -0 "$DUMPCAP_PCAP_PID" 2>/dev/null; then
    echo "Error: Failed to start PCAP companion capture" >&2
    exit 1
  fi

  echo "Captures running (PIDs: pcapng=$DUMPCAP_PCAPNG_PID, pcap=$DUMPCAP_PCAP_PID)"
}

stop_captures() {
  if [[ -n "$DUMPCAP_PCAPNG_PID" ]]; then
    wait "$DUMPCAP_PCAPNG_PID" 2>/dev/null || true
    DUMPCAP_PCAPNG_PID=""
  fi

  if [[ -n "$DUMPCAP_PCAP_PID" ]]; then
    wait "$DUMPCAP_PCAP_PID" 2>/dev/null || true
    DUMPCAP_PCAP_PID=""
  fi
}

start_load_generators() {
  local duration="$CAPTURE_DURATION"
  local pcapng_path="$OUTPUT_DIR/$OUTPUT_FILE"
  local capture_dir
  capture_dir=$(dirname "$pcapng_path")

  echo "Starting HTTP load generator (workers=$HTTP_WORKERS, payload=$HTTP_PAYLOAD bytes)..."
  python3 http_load_client.py \
    --host 127.0.0.1 \
    --port "$HTTP_PORT" \
    --duration "$duration" \
    --workers "$HTTP_WORKERS" \
    --payload-bytes "$HTTP_PAYLOAD" \
    --sleep "$HTTP_SLEEP" \
    >"$capture_dir/http_load.log" 2>&1 &
  HTTP_LOAD_PID=$!

  echo "Starting UDP load generator (rate=${UDP_RATE}pps, payload=$UDP_PAYLOAD bytes)..."
  python3 udp_load_client.py \
    --host 127.0.0.1 \
    --port "$UDP_PORT" \
    --duration "$duration" \
    --rate "$UDP_RATE" \
    --payload-bytes "$UDP_PAYLOAD" \
    >"$capture_dir/udp_load.log" 2>&1 &
  UDP_LOAD_PID=$!
}

stop_load_generators() {
  if [[ -n "$HTTP_LOAD_PID" ]]; then
    wait "$HTTP_LOAD_PID" 2>/dev/null || true
    HTTP_LOAD_PID=""
  fi

  if [[ -n "$UDP_LOAD_PID" ]]; then
    wait "$UDP_LOAD_PID" 2>/dev/null || true
    UDP_LOAD_PID=""
  fi
}

cleanup() {
  if [[ -n "$HTTP_LOAD_PID" ]]; then
    kill "$HTTP_LOAD_PID" 2>/dev/null || true
  fi

  if [[ -n "$UDP_LOAD_PID" ]]; then
    kill "$UDP_LOAD_PID" 2>/dev/null || true
  fi

  if [[ -n "$DUMPCAP_PCAPNG_PID" ]]; then
    kill -INT "$DUMPCAP_PCAPNG_PID" 2>/dev/null || true
  fi

  if [[ -n "$DUMPCAP_PCAP_PID" ]]; then
    kill -INT "$DUMPCAP_PCAP_PID" 2>/dev/null || true
  fi

  stop_servers
}

display_summary() {
  local pcapng_path="$OUTPUT_DIR/$OUTPUT_FILE"
  local pcap_path="${pcapng_path%.pcapng}.pcap"

  echo ""
  echo "=== Capture Complete ==="

  if command -v capinfos >/dev/null 2>&1; then
    echo ""
    echo "=== PCAPNG File Info ==="
    capinfos "$pcapng_path" | grep -E "(File name|File size|Number of packets|Capture duration|Data byte rate|Time resolution)"

    if [[ -f "$pcap_path" ]]; then
      echo ""
      echo "=== PCAP File Info ==="
      capinfos "$pcap_path" | grep -E "(File name|File size|Number of packets|Capture duration|Data byte rate)"
    fi
  else
    echo ""
    ls -lh "$pcapng_path"
    [[ -f "$pcap_path" ]] && ls -lh "$pcap_path"
  fi

  echo ""
  echo "Load generator logs:"
  echo "  - $OUTPUT_DIR/http_load.log"
  echo "  - $OUTPUT_DIR/udp_load.log"
}

main() {
  parse_args "$@"

  OUTPUT_FILE="${OUTPUT_FILE:-$DEFAULT_OUTPUT}"

  if [[ "$OUTPUT_FILE" != *.pcapng ]]; then
    OUTPUT_FILE="${OUTPUT_FILE}.pcapng"
  fi

  require_dumpcap
  ensure_ports_available
  prepare_environment

  local interface_list
  interface_list=$(IFS=','; echo "${INTERFACES[*]}")

  echo "=== Heavy Traffic Capture ==="
  echo "Interfaces: $interface_list"
  echo "Duration: ${CAPTURE_DURATION}s"
  echo "HTTP port: $HTTP_PORT (workers=$HTTP_WORKERS payload=$HTTP_PAYLOAD sleep=$HTTP_SLEEP)"
  echo "UDP port: $UDP_PORT (rate=${UDP_RATE}pps payload=$UDP_PAYLOAD)"
  if [[ $REQUEST_NANO -eq 1 ]]; then
    echo "Timestamp mode: nanosecond (requested)"
  else
    echo "Timestamp mode: default"
  fi
  echo "Output directory: $OUTPUT_DIR"
  echo "Output file (pcapng): $OUTPUT_FILE"
  if [[ $WRITE_PCAP_COMPANION -eq 1 ]]; then
    echo "Companion pcap: enabled"
  else
    echo "Companion pcap: disabled"
  fi

  trap cleanup EXIT

  start_servers
  start_captures
  start_load_generators

  stop_load_generators
  stop_captures
  stop_servers

  trap - EXIT

  display_summary
}

main "$@"
