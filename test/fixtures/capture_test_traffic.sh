#!/bin/bash
# Script to capture test HTTP traffic using dumpcap

set -e

PORT=8899
OUTPUT_FILE_PCAPNG="${1:-sample.pcapng}"
OUTPUT_FILE_PCAP="${OUTPUT_FILE_PCAPNG%.pcapng}.pcap"
PACKET_COUNT=50

echo "=== Capturing Test HTTP Traffic ==="
echo "Output files:"
echo "  - $OUTPUT_FILE_PCAPNG (PCAPNG format)"
echo "  - $OUTPUT_FILE_PCAP (PCAP format)"
echo "Port: $PORT"
echo ""

# Check if dumpcap is available
if ! command -v dumpcap &> /dev/null; then
    echo "Error: dumpcap not found in PATH"
    echo "Install Wireshark or add dumpcap to your PATH"
    exit 1
fi

# Check if port is already in use
if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "Error: Port $PORT is already in use"
    exit 1
fi

# Start HTTP server in background
echo "Starting HTTP server on port $PORT..."
python3 http_server.py $PORT &
SERVER_PID=$!

# Give server time to start
sleep 1

# Check if server started successfully
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Error: Failed to start HTTP server"
    exit 1
fi

echo "Server started (PID: $SERVER_PID)"

# Start packet capture in background (PCAPNG format - default)
echo "Starting PCAPNG packet capture..."
dumpcap -i lo0 -f "tcp port $PORT" -w "$OUTPUT_FILE_PCAPNG" -q &
DUMPCAP_PCAPNG_PID=$!

# Start packet capture in background (PCAP format - legacy)
echo "Starting PCAP packet capture..."
dumpcap -i lo0 -f "tcp port $PORT" -w "$OUTPUT_FILE_PCAP" -q -P &
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
python3 http_client.py $PORT 5

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
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

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
