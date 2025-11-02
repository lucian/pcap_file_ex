#!/usr/bin/env python3
"""Simple UDP server implementing a custom telemetry protocol."""

import socket
import sys
import json
import time

HOST = "127.0.0.1"
PORT = 8898
BUFFER_SIZE = 4096


def parse_message(data):
    try:
        message = json.loads(data.decode("utf-8"))
        if not isinstance(message, dict):
            raise ValueError("message not object")
        return message
    except Exception:
        return None


def build_response(message):
    return json.dumps(
        {
            "ack": message.get("sensor", "unknown"),
            "received": message.get("value"),
            "ts": time.time(),
            "status": "ok",
        }
    ).encode("utf-8")


def run_server(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        print(f"UDP server listening on {host}:{port}")

        while True:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            message = parse_message(data)
            if message is None:
                continue
            response = build_response(message)
            sock.sendto(response, addr)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    run_server(port=port)
