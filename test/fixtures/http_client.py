#!/usr/bin/env python3
"""HTTP client helper for generating mixed GET/POST traffic."""

import argparse
import json
import os
import socket
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


def build_request(method, path, host, port, body, extra_headers=None):
    extra_headers = extra_headers or {}
    headers = {
        "Host": f"{host}:{port}",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }

    if body:
        headers["Content-Length"] = str(len(body))
        headers.setdefault("Content-Type", "application/octet-stream")

    headers.update({k: v for k, v in extra_headers.items() if v is not None})

    request_headers = "\r\n".join([f"{key}: {value}" for key, value in headers.items()])
    request_line = f"{method} {path} HTTP/1.1"
    return (f"{request_line}\r\n{request_headers}\r\n\r\n").encode("ascii") + body


def send_request(host, port, method, path, body, extra_headers=None):
    payload = build_request(method, path, host, port, body, extra_headers)
    with socket.create_connection((host, port), timeout=2) as sock:
        sock.sendall(payload)
        response = sock.recv(4096)
    return response


def make_requests(host="127.0.0.1", port=PORT, count=5, payload_bytes=512, sleep=0.05):
    """Make a series of GET/POST requests with configurable payloads."""
    # Generate various payload types for testing auto-decoding
    json_payload = json.dumps({
        "user": "alice",
        "action": "login",
        "timestamp": int(time.time()),
        "items": [1, 2, 3, 4, 5],
        "metadata": {"source": "test", "version": "1.0"}
    }).encode('utf-8')

    form_payload = "username=bob&password=secret123&remember=true&action=submit".encode('utf-8')

    text_payload = "Hello, World! This is a plain text message for testing.".encode('utf-8')

    # For binary payload, still use random but smaller
    binary_payload = os.urandom(min(256, payload_bytes))

    print(
        f"Making {count} request cycles to {host}:{port} "
        f"(JSON: {len(json_payload)}B, Form: {len(form_payload)}B, Text: {len(text_payload)}B, Binary: {len(binary_payload)}B)"
    )

    for i in range(count):
        try:
            # Request 1: POST JSON data
            response = send_request(
                host,
                port,
                "POST",
                "/api/login",
                json_payload,
                extra_headers={"Content-Type": "application/json"},
            )
            print(
                f"  [{i + 1}] POST /api/login (JSON) -> {response.split(b'\\r\\n', 1)[0].decode()} "
                f"({len(response)} bytes)"
            )

            time.sleep(sleep)

            # Request 2: POST form data
            response = send_request(
                host,
                port,
                "POST",
                "/login",
                form_payload,
                extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            print(
                f"  [{i + 1}] POST /login (Form) -> {response.split(b'\\r\\n', 1)[0].decode()} "
                f"({len(response)} bytes)"
            )

            time.sleep(sleep)

            # Request 3: GET with text response expected
            response = send_request(
                host,
                port,
                "GET",
                "/hello",
                b"",
                extra_headers={},
            )
            print(
                f"  [{i + 1}] GET /hello -> {response.split(b'\\r\\n', 1)[0].decode()} "
                f"({len(response)} bytes)"
            )

            time.sleep(sleep)

            # Request 4: POST binary data (for testing fallback)
            response = send_request(
                host,
                port,
                "POST",
                "/submit",
                binary_payload,
                extra_headers={"Content-Type": "application/octet-stream"},
            )
            print(
                f"  [{i + 1}] POST /submit (Binary) -> {response.split(b'\\r\\n', 1)[0].decode()} "
                f"({len(response)} bytes)"
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
