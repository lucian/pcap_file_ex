#!/usr/bin/env python3
"""Simple UDP client for generating custom telemetry traffic."""

import socket
import sys
import json
import time
import random

HOST = "127.0.0.1"
PORT = 8898


def send_messages(host=HOST, port=PORT, count=5):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        for i in range(count):
            message = {
                "sensor": f"sensor-{i+1}",
                "value": round(random.uniform(20.0, 30.0), 2),
                "seq": i + 1,
            }
            payload = json.dumps(message).encode("utf-8")
            sock.sendto(payload, (host, port))
            try:
                response, _ = sock.recvfrom(4096)
                print(f"UDP response: {response.decode('utf-8')}")
            except socket.timeout:
                print("UDP response timeout")
            time.sleep(0.05)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    send_messages(port=port, count=count)
