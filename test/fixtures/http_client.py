#!/usr/bin/env python3
"""HTTP client helper for generating mixed GET/POST traffic."""

import argparse
import http.client
import os
import sys
import time

PORT = 8899


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Generate HTTP GET/POST traffic.")
    parser.add_argument("port", type=int, nargs="?", default=PORT, help="Server port.")
    parser.add_argument(
        "count",
        type=int,
        nargs="?",
        default=5,
        help="Number of request cycles to execute.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP server host.")
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=512,
        help="Payload size for POST /submit requests.",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.05,
        help="Sleep interval between requests within a cycle (seconds).",
    )
    return parser.parse_args(argv)


def make_requests(host="127.0.0.1", port=PORT, count=5, payload_bytes=512, sleep=0.05):
    """Make a series of GET/POST requests with configurable payloads."""
    print(
        f"Making {count} request cycles to {host}:{port} "
        f"(POST payload: {payload_bytes} bytes)"
    )

    payload = os.urandom(payload_bytes)

    for i in range(count):
        try:
            with http.client.HTTPConnection(host, port, timeout=2) as conn:
                conn.request("GET", "/hello")
                response = conn.getresponse()
                data = response.read()
                print(
                    f"  [{i + 1}] GET /hello -> {response.status} "
                    f"({len(data)} bytes)"
                )

            time.sleep(sleep)

            with http.client.HTTPConnection(host, port, timeout=2) as conn:
                conn.request("GET", "/json")
                response = conn.getresponse()
                data = response.read()
                print(
                    f"  [{i + 1}] GET /json -> {response.status} "
                    f"({len(data)} bytes)"
                )

            time.sleep(sleep)

            with http.client.HTTPConnection(host, port, timeout=2) as conn:
                conn.request(
                    "POST",
                    "/submit",
                    body=payload,
                    headers={"Content-Type": "application/octet-stream"},
                )
                response = conn.getresponse()
                data = response.read()
                print(
                    f"  [{i + 1}] POST /submit -> {response.status} "
                    f"({len(data)} bytes)"
                )

        except Exception as exc:  # noqa: BLE001 - surface failures for debugging
            print(f"  [{i + 1}] Error: {exc}")

        time.sleep(sleep)

    print("Done!")


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    make_requests(
        host=args.host,
        port=args.port,
        count=args.count,
        payload_bytes=args.payload_bytes,
        sleep=args.sleep,
    )
