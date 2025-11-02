#!/bin/bash
# Script to capture test HTTP traffic using dumpcap

set -e

HTTP_PORT=8899
UDP_PORT=8898
OUTPUT_FILE_PCAPNG="${1:-sample.pcapng}"
OUTPUT_FILE_PCAP="${OUTPUT_FILE_PCAPNG%.pcapng}.pcap"
PACKET_COUNT=50

echo "=== Capturing Test HTTP + UDP Traffic ==="
echo "Output files:"
echo "  - $OUTPUT_FILE_PCAPNG (PCAPNG format)"
echo "  - $OUTPUT_FILE_PCAP (PCAP format)"
echo "HTTP Port: $HTTP_PORT"
echo "UDP Port: $UDP_PORT"
echo ""

# Check if dumpcap is available
if ! command -v dumpcap &> /dev/null; then
    echo "Error: dumpcap not found in PATH"
    echo "Install Wireshark or add dumpcap to your PATH"
    exit 1
fi

# Check if port is already in use
if lsof -Pi :$HTTP_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "Error: HTTP port $HTTP_PORT is already in use"
    exit 1
fi

if lsof -Pi :$UDP_PORT -t >/dev/null 2>&1; then
    echo "Error: UDP port $UDP_PORT is already in use"
    exit 1
fi

# Start HTTP server in background
echo "Starting HTTP server on port $HTTP_PORT..."
python3 http_server.py $HTTP_PORT &
SERVER_PID=$!

echo "Starting UDP server on port $UDP_PORT..."
python3 udp_server.py $UDP_PORT &
UDP_SERVER_PID=$!

# Give servers time to start
sleep 1

# Check if servers started successfully
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Error: Failed to start HTTP server"
    kill $UDP_SERVER_PID 2>/dev/null || true
    exit 1
fi

if ! kill -0 $UDP_SERVER_PID 2>/dev/null; then
    echo "Error: Failed to start UDP server"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

echo "Server started (PID: $SERVER_PID)"
echo "UDP server started (PID: $UDP_SERVER_PID)"

# Start packet capture in background (PCAPNG format - default)
CAPTURE_FILTER="(tcp port $HTTP_PORT) or (udp port $UDP_PORT)"

echo "Starting PCAPNG packet capture..."
dumpcap -i lo0 -f "$CAPTURE_FILTER" -w "$OUTPUT_FILE_PCAPNG" -q &
DUMPCAP_PCAPNG_PID=$!

# Start packet capture in background (PCAP format - legacy)
echo "Starting PCAP packet capture..."
dumpcap -i lo0 -f "$CAPTURE_FILTER" -w "$OUTPUT_FILE_PCAP" -q -P &
DUMPCAP_PCAP_PID=$!

# Give dumpcap time to start
sleep 1

# Check if both captures started successfully
if ! kill -0 $DUMPCAP_PCAPNG_PID 2>/dev/null; then
    echo "Error: Failed to start PCAPNG dumpcap"
    kill $DUMPCAP_PCAP_PID 2>/dev/null
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

if ! kill -0 $DUMPCAP_PCAP_PID 2>/dev/null; then
    echo "Error: Failed to start PCAP dumpcap"
    kill $DUMPCAP_PCAPNG_PID 2>/dev/null
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

echo "Captures started (PIDs: PCAPNG=$DUMPCAP_PCAPNG_PID, PCAP=$DUMPCAP_PCAP_PID)"

# Make HTTP requests
echo ""
echo "Generating traffic..."
python3 http_client.py $HTTP_PORT 5

python3 udp_client.py $UDP_PORT 5

# Give time for packets to be written
sleep 1

# Stop captures
echo ""
echo "Stopping captures..."
kill -INT $DUMPCAP_PCAPNG_PID 2>/dev/null || true
kill -INT $DUMPCAP_PCAP_PID 2>/dev/null || true
wait $DUMPCAP_PCAPNG_PID 2>/dev/null || true
wait $DUMPCAP_PCAP_PID 2>/dev/null || true

# Stop server
echo "Stopping servers..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
kill $UDP_SERVER_PID 2>/dev/null || true
wait $UDP_SERVER_PID 2>/dev/null || true

echo ""
echo "=== Capture Complete ==="

# Show capture info if capinfos is available
if command -v capinfos &> /dev/null; then
    echo ""
    echo "=== PCAPNG File Info ==="
    capinfos "$OUTPUT_FILE_PCAPNG" | grep -E "(File name|File size|Number of packets|Capture duration|Data byte rate)"
    echo ""
    echo "=== PCAP File Info ==="
    capinfos "$OUTPUT_FILE_PCAP" | grep -E "(File name|File size|Number of packets|Capture duration|Data byte rate)"
else
    # Show basic file info
    echo ""
    ls -lh "$OUTPUT_FILE_PCAPNG" "$OUTPUT_FILE_PCAP"
fi

echo ""
echo "Test captures saved:"
echo "  - $OUTPUT_FILE_PCAPNG (PCAPNG format)"
echo "  - $OUTPUT_FILE_PCAP (PCAP format)"
echo "You can view with: tshark -r $OUTPUT_FILE_PCAPNG"
echo "                   tshark -r $OUTPUT_FILE_PCAP"
