#!/bin/bash
# Script to capture test HTTP/UDP traffic using dumpcap.
# Supports multi-interface PCAPNG captures and optional nanosecond timestamps.

set -euo pipefail

HTTP_PORT=8899
UDP_PORT=8898
DEFAULT_OUTPUT="sample.pcapng"
OUTPUT_FILE_PCAPNG=""
PACKET_COUNT=50
INTERFACES=()  # Will be set after platform detection
REQUEST_NANO=0
SERVER_PID=""
UDP_SERVER_PID=""
DUMPCAP_PCAPNG_PID=""
DUMPCAP_PCAP_PID=""
OS_TYPE=""
DEFAULT_LOOPBACK=""

usage() {
  cat <<'EOF'
Usage: ./capture_test_traffic.sh [output_file] [options]

Options:
  -o, --output <file>        Write PCAPNG data to <file> (default: sample.pcapng)
  -i, --interfaces <list>    Comma-separated interface list (default: auto-detect loopback)
  -n, --nanosecond           Request nanosecond timestamp resolution (pcapng)
  -c, --count <num>          Stop after <num> packets per interface (default: 50)
      --list-interfaces      List available interfaces and exit
  -h, --help                 Show this help text and exit

Examples:
  ./capture_test_traffic.sh                            # Use default loopback
  ./capture_test_traffic.sh --list-interfaces          # Show available interfaces
  ./capture_test_traffic.sh --interfaces lo0,en0 -n    # macOS: multiple interfaces, nanosecond
  ./capture_test_traffic.sh --interfaces lo,eth0 -n    # Linux: multiple interfaces, nanosecond
  ./capture_test_traffic.sh custom_capture.pcapng -c 200
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
    sudo ./capture_test_traffic.sh

  Verify it works:
    dumpcap -D
LINUX_HELP
        ;;
    esac

    return 1
  fi

  return 0
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
    kill "$UDP_SERVER_PID" 2>/dev/null || true
    exit 1
  fi

  if ! kill -0 "$UDP_SERVER_PID" 2>/dev/null; then
    echo "Error: Failed to start UDP server" >&2
    kill "$SERVER_PID" 2>/dev/null || true
    exit 1
  fi
}

stop_servers() {
  echo "Stopping servers..."
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

  if [[ -n "$UDP_SERVER_PID" ]]; then
    kill "$UDP_SERVER_PID" 2>/dev/null || true
    UDP_SERVER_PID=""
  fi
}

prepare_environment() {
  if [[ $REQUEST_NANO -eq 1 ]]; then
    export WIRESHARK_PCAPNG_DEFAULT_TSPRECISION=9
    export WIRESHARK_PCAPNG_DEFAULT_TSRESOL=9
  fi
}

start_captures() {
  local capture_filter="(tcp port $HTTP_PORT) or (udp port $UDP_PORT)"
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
  echo "Generating HTTP/UDP traffic..."
  python3 http_client.py "$HTTP_PORT" 5
  python3 udp_client.py "$UDP_PORT" 5
  sleep 1
}

display_summary() {
  echo ""
  echo "=== Capture Complete ==="

  if command -v capinfos >/dev/null 2>&1; then
    echo ""
    echo "=== PCAPNG File Info ==="
    capinfos "$OUTPUT_FILE_PCAPNG" | grep -E "(File name|File size|Number of packets|Capture duration|Data byte rate|Time resolution)"
    echo ""
    echo "=== PCAP File Info ==="
    capinfos "$OUTPUT_FILE_PCAP" | grep -E "(File name|File size|Number of packets|Capture duration|Data byte rate)"
  else
    echo ""
    ls -lh "$OUTPUT_FILE_PCAPNG" "$OUTPUT_FILE_PCAP"
  fi

  echo ""
  echo "Test captures saved:"
  echo "  - $OUTPUT_FILE_PCAPNG (PCAPNG format)"
  echo "  - $OUTPUT_FILE_PCAP (PCAP format)"
  echo "You can view with: tshark -r $OUTPUT_FILE_PCAPNG"
  echo "                   tshark -r $OUTPUT_FILE_PCAP"
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

  if [[ -z "$OUTPUT_FILE_PCAPNG" ]]; then
    if [[ $REQUEST_NANO -eq 1 && ${#INTERFACES[@]} -gt 1 ]]; then
      OUTPUT_FILE_PCAPNG="sample_multi_nanosecond.pcapng"
    else
      OUTPUT_FILE_PCAPNG="$DEFAULT_OUTPUT"
    fi
  fi

  if [[ "$OUTPUT_FILE_PCAPNG" == *.pcapng ]]; then
    OUTPUT_FILE_PCAP="${OUTPUT_FILE_PCAPNG%.pcapng}.pcap"
  else
    OUTPUT_FILE_PCAP="${OUTPUT_FILE_PCAPNG}.pcap"
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

  echo "=== Capturing Test HTTP + UDP Traffic ==="
  echo "Interfaces: $interface_list"
  echo "HTTP Port: $HTTP_PORT"
  echo "UDP Port: $UDP_PORT"
  if [[ $REQUEST_NANO -eq 1 ]]; then
    echo "Timestamp mode: nanosecond (requested; requires interface support)"
  else
    echo "Timestamp mode: default (interface provided)"
  fi
  echo "Output files:"
  echo "  - $OUTPUT_FILE_PCAPNG (PCAPNG format)"
  echo "  - $OUTPUT_FILE_PCAP (PCAP format)"

  trap cleanup EXIT

  start_servers
  start_captures
  generate_traffic
  stop_captures
  stop_servers

  trap - EXIT

  display_summary
}

main "$@"
