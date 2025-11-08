# Test Fixtures

This directory contains PCAP and PCAPNG files for testing, along with scripts to generate predictable test traffic.

## Platform Compatibility

The capture scripts work on both **macOS** and **Linux** with automatic platform detection:

- **macOS**: Uses `lo0` (loopback), `en0` (ethernet/wifi)
- **Linux**: Uses `lo` (loopback), `eth0`/`wlan0` (ethernet/wifi)

The scripts auto-detect the appropriate loopback interface for your platform. You can override with `--interfaces <name>`.

## Quick Start - Generate Test Files

### Option 1: Automated Test Traffic Capture (Recommended)

Generate a test capture file with known HTTP and UDP telemetry traffic:

```bash
cd test/fixtures
chmod +x capture_test_traffic.sh
./capture_test_traffic.sh sample.pcapng
./capture_test_traffic.sh --interfaces lo0,en0 --nanosecond
```

This script:
1. Starts a simple HTTP server on port 8899
2. Starts a UDP telemetry server on port 8898
3. Starts dumpcap to capture both TCP and UDP traffic on the selected interfaces
4. Generates HTTP GET/JSON requests and UDP telemetry messages
5. Stops capture and saves to `sample.pcapng` (plus `sample.pcap`); when run with `--interfaces ... --nanosecond` it also writes `sample_multi_nanosecond.pcapng`

### Option 1b: High-volume Capture for Benchmarks

Generate a large, multi-interface capture suitable for benchmarking:

```bash
cd test/fixtures
chmod +x capture_heavy_traffic.sh
./capture_heavy_traffic.sh --duration 120 --interfaces lo0,en0
```

Key features:
1. Starts HTTP and UDP servers (configurable via `--http-port` / `--udp-port`)
2. Runs concurrent HTTP load (GET `/hello`, GET `/json`, POST `/submit`) with configurable workers and payload sizes
3. Generates high-rate UDP telemetry streams with adjustable payload sizes and target packet rate
4. Captures traffic across one or more interfaces via `dumpcap`, requesting nanosecond timestamps when `--nanosecond` is set
5. Produces `large_capture.pcapng` (and optionally `large_capture.pcap`) alongside load generator logs for reproducibility

Logs from the HTTP/UDP load generators are written next to the capture file (`http_load.log`, `udp_load.log`) to record request/packet counts.

### Option 2: Manual Capture with dumpcap

Capture packets on any interface:

```bash
# Capture 10 packets to PCAPNG format
dumpcap -i any -w test/fixtures/sample.pcapng -c 10

# Capture on specific interface (list available interfaces first)
dumpcap -D
dumpcap -i en0 -w test/fixtures/sample.pcapng -c 10

# Capture with filter (only HTTP traffic)
dumpcap -i any -f "tcp port 80" -w test/fixtures/http_traffic.pcapng
```

### Option 3: Using tcpdump

```bash
sudo tcpdump -i any -w test/fixtures/sample.pcap -c 10
```

## Test Traffic Generator

The included Python scripts generate predictable HTTP and UDP traffic:

### Start HTTP Server
```bash
python3 http_server.py [port]
# Default port: 8899
# Responds to:
#   GET /hello -> "Hello, World!"
#   GET /json  -> {"message": "test", "status": "ok"}
```

### Run HTTP Client
```bash
python3 http_client.py [port] [count]
# Default port: 8899, count: 5
# Makes HTTP GET requests to /hello and /json (each with a small binary body)
# plus POST /submit with larger binary payloads
```

### Run HTTP Load Generator
```bash
python3 http_load_client.py --duration 60 --workers 4 --payload-bytes 2048
# Sustained concurrent GET/POST traffic with request bodies,
# intended for large benchmark captures
```

### Start UDP Server
```bash
python3 udp_server.py [port]
# Default port: 8898
# Listens for JSON telemetry datagrams and responds with acknowledgements
```

### Run UDP Client
```bash
python3 udp_client.py [port] [count]
# Default port: 8898, count: 5
# Sends JSON telemetry messages and prints server responses
```

### Run UDP Load Generator
```bash
python3 udp_load_client.py --duration 60 --rate 800 --payload-bytes 512
# Generates high-rate UDP telemetry without waiting for responses
```

### Manual Capture Workflow
```bash
# Terminal 1: Start server
python3 http_server.py

# Terminal 2: Start capture
dumpcap -i lo0 -f "tcp port 8899" -w manual_capture.pcapng

# Terminal 3: Generate traffic
python3 http_client.py

# Terminal 2: Stop capture with Ctrl+C
```

## Converting PCAPNG to Legacy PCAP

If you need legacy PCAP format, use `editcap` or `tshark` (part of Wireshark):

```bash
# Using editcap
editcap -F pcap sample.pcapng sample.pcap

# Using tshark
tshark -r sample.pcapng -w sample.pcap -F pcap
```

## Viewing Capture Files

```bash
# Show capture file info
capinfos sample.pcapng

# View packets
tshark -r sample.pcapng

# View with filters
tshark -r sample.pcapng -Y "http"

# Export HTTP objects
tshark -r sample.pcapng --export-objects http,./http_objects/
```

## File Formats

- `*.pcap` - Legacy PCAP format (original libpcap format)
- `*.pcapng` - PCAPNG format (next generation, supports multiple interfaces and metadata)

## Troubleshooting

### dumpcap not found

Install Wireshark to get dumpcap:

**macOS:**
```bash
brew install wireshark
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install tshark  # Includes dumpcap
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install wireshark-cli
```

**Linux (Arch):**
```bash
sudo pacman -S wireshark-cli
```

### Permission denied errors

dumpcap requires elevated privileges for packet capture.

**macOS:**

Install Wireshark via Homebrew - it automatically sets up ChmodBPF:
```bash
brew install wireshark
```

This grants packet capture permissions without needing sudo.

Alternatively, grant Terminal.app Input Monitoring permission:
1. System Preferences → Security & Privacy → Privacy → Input Monitoring
2. Add Terminal.app or iTerm.app

**Linux:**

**Option 1: wireshark group (Recommended)**
```bash
# Setup non-root capture
sudo dpkg-reconfigure wireshark-common  # Select "Yes"
sudo usermod -aG wireshark $USER
newgrp wireshark  # Or logout/login

# Verify it works
dumpcap -D
```

**Option 2: Set capabilities**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)
```

**Option 3: Use sudo**
```bash
sudo ./capture_test_traffic.sh
```

### Interface not found errors

**Symptoms:**
```
Error: Interface 'lo0' not found
```

**Solution:**

The scripts auto-detect the correct loopback interface for your platform. If you see this error:

1. List available interfaces:
   ```bash
   ./capture_test_traffic.sh --list-interfaces
   # Or directly:
   dumpcap -D
   ```

2. Specify the correct interface:
   ```bash
   # macOS examples
   ./capture_test_traffic.sh --interfaces lo0      # Loopback
   ./capture_test_traffic.sh --interfaces en0      # Ethernet/WiFi

   # Linux examples
   ./capture_test_traffic.sh --interfaces lo       # Loopback
   ./capture_test_traffic.sh --interfaces eth0     # Ethernet
   ./capture_test_traffic.sh --interfaces wlan0    # WiFi
   ```

### No packets captured

- Make sure you're capturing on the correct interface
  - macOS: `lo0` for loopback, `en0` for network
  - Linux: `lo` for loopback, `eth0`/`wlan0` for network
- Check the filter syntax: `dumpcap -d`
- Verify traffic is being generated: `lsof -i :8899` or `ss -ln | grep 8899`
- Ensure HTTP/UDP servers started successfully (check script output)

### Script hangs or times out

- Check if ports 8899 (HTTP) or 8898 (UDP) are already in use
- Kill any stale Python processes: `pkill -f http_server.py`
- Ensure Python 3 is installed: `python3 --version`

### For more help

See the main README.md "Troubleshooting" section for detailed platform-specific setup and debugging guidance.
