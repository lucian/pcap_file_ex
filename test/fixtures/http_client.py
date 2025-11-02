#!/usr/bin/env python3
"""Simple HTTP client for generating test traffic."""

import http.client
import sys
import time

PORT = 8899


def make_requests(host="127.0.0.1", port=PORT, count=5):
    """Make a series of HTTP requests."""
    print(f"Making {count} requests to {host}:{port}")

    for i in range(count):
        try:
            # Request 1: GET /hello
            conn = http.client.HTTPConnection(host, port, timeout=2)
            conn.request("GET", "/hello")
            response = conn.getresponse()
            data = response.read()
            print(f"  [{i+1}] GET /hello -> {response.status} ({len(data)} bytes)")
            conn.close()

            time.sleep(0.1)

            # Request 2: GET /json
            conn = http.client.HTTPConnection(host, port, timeout=2)
            conn.request("GET", "/json")
            response = conn.getresponse()
            data = response.read()
            print(f"  [{i+1}] GET /json -> {response.status} ({len(data)} bytes)")
            conn.close()

            time.sleep(0.1)

        except Exception as e:
            print(f"  [{i+1}] Error: {e}")

    print("Done!")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    make_requests(port=port, count=count)
