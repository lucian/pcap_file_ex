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
INTERFACES=()  # Will be set after platform detection
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
OS_TYPE=""
DEFAULT_LOOPBACK=""

usage() {
  cat <<'EOF'
Usage: ./capture_heavy_traffic.sh [options]

Options:
  -o, --output <file>        Capture filename (default: large_capture.pcapng)
  -d, --duration <seconds>   Capture duration (default: 60)
  -i, --interfaces <list>    Comma-separated interface list (default: auto-detect loopback)
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
  ./capture_heavy_traffic.sh                           # Use default loopback
  ./capture_heavy_traffic.sh -d 120 --list-interfaces  # Show interfaces
  ./capture_heavy_traffic.sh -d 120 -i lo0,en0         # macOS: multiple interfaces
  ./capture_heavy_traffic.sh -d 120 -i lo,eth0         # Linux: multiple interfaces
  ./capture_heavy_traffic.sh --output-dir ./captures --no-pcap
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

  # Try to find loopback interface from dumpcap output
  if command -v dumpcap >/dev/null 2>&1; then
    # Parse dumpcap -D output for loopback
    # Example: "1. lo (Loopback)" or "1. lo0"
    loopback=$(dumpcap -D 2>/dev/null | grep -i loopback | head -n1 | sed -E 's/^[0-9]+\. ([^ ]+).*/\1/')
  fi

  # Fallback to platform default
  if [[ -z "$loopback" ]]; then
    loopback="$DEFAULT_LOOPBACK"
  fi

  echo "$loopback"
}

validate_interface() {
  local iface=$1

  if ! dumpcap -D 2>/dev/null | grep -qw "$iface"; then
    echo "Error: Interface '$iface' not found" >&2
    echo "" >&2
    echo "Available interfaces:" >&2
    dumpcap -D 2>/dev/null || echo "(dumpcap -D failed)" >&2
    echo "" >&2
    echo "Use --interfaces <name> to specify a different interface" >&2
    echo "Use --list-interfaces to see all available interfaces" >&2
    return 1
  fi

  return 0
}

check_dumpcap_permissions() {
  if ! dumpcap -D >/dev/null 2>&1; then
    echo "Error: dumpcap requires elevated privileges" >&2
    echo "" >&2

    case "$OS_TYPE" in
      macos)
        cat >&2 <<'MACOS_HELP'
macOS Setup:
  1. Install Wireshark via Homebrew (includes ChmodBPF):
     brew install wireshark

  2. Or grant Terminal Input Monitoring permission:
     System Preferences → Security & Privacy → Privacy → Input Monitoring
     → Add Terminal.app

  3. Verify it works:
     dumpcap -D
MACOS_HELP
        ;;

      linux|unknown)
        cat >&2 <<'LINUX_HELP'
Linux Setup (choose one):

  Option 1: Wireshark group (recommended)
    sudo dpkg-reconfigure wireshark-common  # Select 'Yes'
    sudo usermod -aG wireshark $USER
    newgrp wireshark  # Or logout/login

  Option 2: Set capabilities
    sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)

  Option 3: Run with sudo
    sudo ./capture_heavy_traffic.sh

  Verify it works:
    dumpcap -D
LINUX_HELP
        ;;
    esac

    return 1
  fi

  return 0
}

check_port_in_use() {
  local port=$1

  # Try ss first (modern Linux, faster)
  if command -v ss >/dev/null 2>&1; then
    if ss -ln 2>/dev/null | grep -q ":$port "; then
      return 0  # Port in use
    fi
  # Fallback to lsof (macOS, older Linux)
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -Pi :"$port" -t >/dev/null 2>&1; then
      return 0  # Port in use
    fi
  else
    echo "Warning: Neither 'ss' nor 'lsof' available, cannot check port $port" >&2
  fi

  return 1  # Port available or can't check
}

require_dumpcap() {
  if ! command -v dumpcap >/dev/null 2>&1; then
    echo "Error: dumpcap not found in PATH" >&2
    echo "" >&2
    echo "Install Wireshark to get dumpcap:" >&2
    echo "" >&2

    case "$OS_TYPE" in
      macos)
        echo "  macOS:" >&2
        echo "    brew install wireshark" >&2
        ;;
      linux|unknown)
        echo "  Ubuntu/Debian:" >&2
        echo "    sudo apt-get install tshark" >&2
        echo "" >&2
        echo "  Fedora/RHEL:" >&2
        echo "    sudo dnf install wireshark-cli" >&2
        echo "" >&2
        echo "  Arch:" >&2
        echo "    sudo pacman -S wireshark-cli" >&2
        ;;
    esac

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
  if check_port_in_use "$HTTP_PORT"; then
    echo "Error: HTTP port $HTTP_PORT is already in use" >&2
    exit 1
  fi

  if check_port_in_use "$UDP_PORT"; then
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
  # Platform detection must happen first
  detect_platform

  parse_args "$@"

  # Set default interface if not specified by user
  if [[ ${#INTERFACES[@]} -eq 0 ]]; then
    local detected_loopback
    detected_loopback=$(detect_loopback)
    INTERFACES=("$detected_loopback")
  fi

  OUTPUT_FILE="${OUTPUT_FILE:-$DEFAULT_OUTPUT}"

  if [[ "$OUTPUT_FILE" != *.pcapng ]]; then
    OUTPUT_FILE="${OUTPUT_FILE}.pcapng"
  fi

  require_dumpcap
  check_dumpcap_permissions || exit 1

  # Validate all interfaces exist
  for iface in "${INTERFACES[@]}"; do
    validate_interface "$iface" || exit 1
  done

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
