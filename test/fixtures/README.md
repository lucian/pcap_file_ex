# Test Fixtures

This directory contains PCAP and PCAPNG files for testing, along with scripts to generate predictable test traffic.

## Quick Start - Generate Test Files

### Option 1: Automated Test Traffic Capture (Recommended)

Generate a test capture file with known HTTP traffic:

```bash
cd test/fixtures
chmod +x capture_test_traffic.sh
./capture_test_traffic.sh sample.pcapng
```

This script:
1. Starts a simple HTTP server on port 8899
2. Starts dumpcap to capture traffic on loopback interface
3. Makes HTTP requests with known content
4. Stops capture and saves to `sample.pcapng`

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

The included Python scripts generate predictable HTTP traffic:

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
# Makes HTTP GET requests to /hello and /json
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
Install Wireshark which includes dumpcap:
```bash
# macOS
brew install wireshark

# Ubuntu/Debian
sudo apt-get install wireshark

# The dumpcap binary will be in your PATH
```

### Permission denied
dumpcap may need special permissions:
```bash
# macOS: Allow in System Preferences -> Security & Privacy
# Linux: Add user to wireshark group or use sudo
sudo usermod -aG wireshark $USER
```

### No packets captured
- Make sure you're capturing on the correct interface (lo0 for loopback)
- Check the filter syntax with dumpcap -d
- Verify traffic is actually being generated (use netstat or lsof)
