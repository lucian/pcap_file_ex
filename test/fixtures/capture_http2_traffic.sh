#!/bin/bash
# Script to capture test HTTP/2 cleartext (h2c) traffic using dumpcap.
# Generates PCAP/PCAPNG files with HTTP/2 frames for testing.

set -euo pipefail

H2C_PORT=8097
DEFAULT_OUTPUT="http2_sample.pcapng"
OUTPUT_FILE_PCAPNG=""
OUTPUT_FILE_PCAP=""
PACKET_COUNT=100
INTERFACES=()
REQUEST_NANO=0
SERVER_PID=""
DUMPCAP_PCAPNG_PID=""
DUMPCAP_PCAP_PID=""
OS_TYPE=""
DEFAULT_LOOPBACK=""
NUM_REQUESTS=3

usage() {
  cat <<'EOF'
Usage: ./capture_http2_traffic.sh [output_file] [options]

Captures HTTP/2 cleartext (h2c) traffic for testing PcapFileEx.HTTP2 module.

Options:
  -o, --output <file>        Write PCAPNG data to <file> (default: http2_sample.pcapng)
  -i, --interfaces <list>    Comma-separated interface list (default: auto-detect loopback)
  -n, --nanosecond           Request nanosecond timestamp resolution (pcapng)
  -c, --count <num>          Stop after <num> packets per interface (default: 100)
  -r, --requests <num>       Number of request sets to generate (default: 3)
      --list-interfaces      List available interfaces and exit
  -h, --help                 Show this help text and exit

Requirements:
  - Python 3 with h2 library: pip install -r requirements.txt
  - dumpcap (from Wireshark)

Examples:
  ./capture_http2_traffic.sh                       # Generate http2_sample.pcapng
  ./capture_http2_traffic.sh -r 10                 # More requests for larger capture
  ./capture_http2_traffic.sh custom.pcapng -n     # Custom name, nanosecond timestamps
EOF
}

detect_platform() {
  local platform
  platform=$(uname -s)

  case "$platform" in
    Darwin)
      OS_TYPE="macos"
      DEFAULT_LOOPBACK="lo0"
      ;;
    Linux)
      OS_TYPE="linux"
      DEFAULT_LOOPBACK="lo"
      ;;
    *)
      echo "Warning: Unsupported platform '$platform', assuming Linux defaults" >&2
      OS_TYPE="unknown"
      DEFAULT_LOOPBACK="lo"
      ;;
  esac
}

detect_loopback() {
  local loopback=""

  if command -v dumpcap >/dev/null 2>&1; then
    loopback=$(dumpcap -D 2>/dev/null | grep -i loopback | head -n1 | sed -E 's/^[0-9]+\. ([^ ]+).*/\1/')
  fi

  if [[ -z "$loopback" ]]; then
    loopback="$DEFAULT_LOOPBACK"
  fi

  echo "$loopback"
}

validate_interface() {
  local iface=$1

  if ! dumpcap -D 2>/dev/null | grep -qw "$iface"; then
    echo "Error: Interface '$iface' not found" >&2
    echo "Use --list-interfaces to see available interfaces" >&2
    return 1
  fi

  return 0
}

check_dumpcap_permissions() {
  if ! dumpcap -D >/dev/null 2>&1; then
    echo "Error: dumpcap requires elevated privileges" >&2
    echo "See capture_test_traffic.sh for setup instructions" >&2
    return 1
  fi
  return 0
}

require_dumpcap() {
  if ! command -v dumpcap >/dev/null 2>&1; then
    echo "Error: dumpcap not found. Install Wireshark." >&2
    exit 1
  fi
}

require_h2() {
  if ! python3 -c "import h2" 2>/dev/null; then
    echo "Error: Python h2 library not found" >&2
    echo "Install with: pip install h2" >&2
    exit 1
  fi
}

parse_args() {
  local positional_done=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output)
        OUTPUT_FILE_PCAPNG="$2"
        shift 2
        ;;
      -i|--interfaces)
        IFS=',' read -r -a INTERFACES <<<"$2"
        shift 2
        ;;
      -n|--nanosecond)
        REQUEST_NANO=1
        shift
        ;;
      -c|--count)
        PACKET_COUNT="$2"
        shift 2
        ;;
      -r|--requests)
        NUM_REQUESTS="$2"
        shift 2
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
      -*)
        echo "Unknown option: $1" >&2
        usage
        exit 1
        ;;
      *)
        if [[ $positional_done -eq 0 ]]; then
          OUTPUT_FILE_PCAPNG="$1"
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

check_port_in_use() {
  local port=$1

  if command -v ss >/dev/null 2>&1; then
    if ss -ln 2>/dev/null | grep -q ":$port "; then
      return 0
    fi
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -Pi :"$port" -t >/dev/null 2>&1; then
      return 0
    fi
  fi

  return 1
}

ensure_port_available() {
  if check_port_in_use "$H2C_PORT"; then
    echo "Error: H2C port $H2C_PORT is already in use" >&2
    exit 1
  fi
}

start_server() {
  echo "Starting H2C server on port $H2C_PORT..."
  python3 h2c_server.py "$H2C_PORT" &
  SERVER_PID=$!

  sleep 1

  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Error: Failed to start H2C server" >&2
    exit 1
  fi
}

stop_server() {
  if [[ -n "$SERVER_PID" ]]; then
    echo "Stopping H2C server..."
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
}

cleanup() {
  if [[ -n "$DUMPCAP_PCAPNG_PID" ]]; then
    kill -INT "$DUMPCAP_PCAPNG_PID" 2>/dev/null || true
    wait "$DUMPCAP_PCAPNG_PID" 2>/dev/null || true
    DUMPCAP_PCAPNG_PID=""
  fi

  if [[ -n "$DUMPCAP_PCAP_PID" ]]; then
    kill -INT "$DUMPCAP_PCAP_PID" 2>/dev/null || true
    wait "$DUMPCAP_PCAP_PID" 2>/dev/null || true
    DUMPCAP_PCAP_PID=""
  fi

  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
}

prepare_environment() {
  if [[ $REQUEST_NANO -eq 1 ]]; then
    export WIRESHARK_PCAPNG_DEFAULT_TSPRECISION=9
    export WIRESHARK_PCAPNG_DEFAULT_TSRESOL=9
  fi
}

start_captures() {
  local capture_filter="tcp port $H2C_PORT"
  local interface_flags=()

  for iface in "${INTERFACES[@]}"; do
    interface_flags+=("-i" "$iface")
  done

  local pcapng_cmd=(dumpcap "${interface_flags[@]}" -f "$capture_filter" -w "$OUTPUT_FILE_PCAPNG" -q)
  local pcap_cmd=(dumpcap "${interface_flags[@]}" -f "$capture_filter" -w "$OUTPUT_FILE_PCAP" -q -P)

  if [[ "$PACKET_COUNT" =~ ^[0-9]+$ ]] && [[ "$PACKET_COUNT" -gt 0 ]]; then
    pcapng_cmd+=("-c" "$PACKET_COUNT")
    pcap_cmd+=("-c" "$PACKET_COUNT")
  fi

  "${pcapng_cmd[@]}" &
  DUMPCAP_PCAPNG_PID=$!

  "${pcap_cmd[@]}" &
  DUMPCAP_PCAP_PID=$!

  sleep 1

  if ! kill -0 "$DUMPCAP_PCAPNG_PID" 2>/dev/null; then
    echo "Error: Failed to start PCAPNG dumpcap" >&2
    exit 1
  fi

  if ! kill -0 "$DUMPCAP_PCAP_PID" 2>/dev/null; then
    echo "Error: Failed to start PCAP dumpcap" >&2
    exit 1
  fi

  echo "Captures started (PIDs: PCAPNG=$DUMPCAP_PCAPNG_PID, PCAP=$DUMPCAP_PCAP_PID)"
}

stop_captures() {
  echo ""
  echo "Stopping captures..."

  if [[ -n "$DUMPCAP_PCAPNG_PID" ]]; then
    kill -INT "$DUMPCAP_PCAPNG_PID" 2>/dev/null || true
    wait "$DUMPCAP_PCAPNG_PID" 2>/dev/null || true
    DUMPCAP_PCAPNG_PID=""
  fi

  if [[ -n "$DUMPCAP_PCAP_PID" ]]; then
    kill -INT "$DUMPCAP_PCAP_PID" 2>/dev/null || true
    wait "$DUMPCAP_PCAP_PID" 2>/dev/null || true
    DUMPCAP_PCAP_PID=""
  fi
}

generate_traffic() {
  echo ""
  echo "Generating HTTP/2 traffic ($NUM_REQUESTS request sets)..."
  python3 h2c_client.py "$H2C_PORT" "$NUM_REQUESTS"
  sleep 1
}

display_summary() {
  echo ""
  echo "=== HTTP/2 Capture Complete ==="

  if command -v capinfos >/dev/null 2>&1; then
    echo ""
    echo "=== PCAPNG File Info ==="
    capinfos "$OUTPUT_FILE_PCAPNG" | grep -E "(File name|File size|Number of packets|Capture duration)"
    echo ""
    echo "=== PCAP File Info ==="
    capinfos "$OUTPUT_FILE_PCAP" | grep -E "(File name|File size|Number of packets|Capture duration)"
  else
    echo ""
    ls -lh "$OUTPUT_FILE_PCAPNG" "$OUTPUT_FILE_PCAP"
  fi

  echo ""
  echo "HTTP/2 test captures saved:"
  echo "  - $OUTPUT_FILE_PCAPNG (PCAPNG format)"
  echo "  - $OUTPUT_FILE_PCAP (PCAP format)"
  echo ""
  echo "View with: tshark -r $OUTPUT_FILE_PCAPNG"
  echo "Decode:    tshark -r $OUTPUT_FILE_PCAPNG -d 'tcp.port==$H2C_PORT,http2'"
}

main() {
  detect_platform
  parse_args "$@"

  if [[ ${#INTERFACES[@]} -eq 0 ]]; then
    local detected_loopback
    detected_loopback=$(detect_loopback)
    INTERFACES=("$detected_loopback")
  fi

  if [[ -z "$OUTPUT_FILE_PCAPNG" ]]; then
    OUTPUT_FILE_PCAPNG="$DEFAULT_OUTPUT"
  fi

  if [[ "$OUTPUT_FILE_PCAPNG" == *.pcapng ]]; then
    OUTPUT_FILE_PCAP="${OUTPUT_FILE_PCAPNG%.pcapng}.pcap"
  else
    OUTPUT_FILE_PCAP="${OUTPUT_FILE_PCAPNG}.pcap"
  fi

  require_dumpcap
  require_h2
  check_dumpcap_permissions || exit 1

  for iface in "${INTERFACES[@]}"; do
    validate_interface "$iface" || exit 1
  done

  ensure_port_available
  prepare_environment

  local interface_list
  interface_list=$(IFS=','; echo "${INTERFACES[*]}")

  echo "=== Capturing HTTP/2 Cleartext Traffic ==="
  echo "Interface: $interface_list"
  echo "H2C Port: $H2C_PORT"
  echo "Request sets: $NUM_REQUESTS"
  echo "Output files:"
  echo "  - $OUTPUT_FILE_PCAPNG (PCAPNG format)"
  echo "  - $OUTPUT_FILE_PCAP (PCAP format)"

  trap cleanup EXIT

  start_server
  start_captures
  generate_traffic
  stop_captures
  stop_server

  trap - EXIT

  display_summary
}

# Change to script directory
cd "$(dirname "$0")"

main "$@"
