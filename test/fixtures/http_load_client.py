#!/usr/bin/env python3
"""Concurrent HTTP load generator for test captures."""

import argparse
import os
import socket
import threading
import time
from collections import Counter


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate sustained HTTP GET/POST traffic."
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP server host.")
    parser.add_argument("--port", type=int, default=8899, help="HTTP server port.")
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="How long to run the load generator (seconds).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of parallel worker threads.",
    )
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=1024,
        help="Binary payload size for POST /submit requests.",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.01,
        help="Sleep interval between request cycles (seconds).",
    )
    return parser.parse_args()


def build_request(method, path, host, port, body, headers=None):
    headers = headers or {}

    merged = {
        "Host": f"{host}:{port}",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }

    if body:
        merged["Content-Length"] = str(len(body))
        merged.setdefault("Content-Type", "application/octet-stream")

    merged.update(headers)

    header_blob = "\r\n".join(f"{k}: {v}" for k, v in merged.items())
    request_line = f"{method} {path} HTTP/1.1"
    return (f"{request_line}\r\n{header_blob}\r\n\r\n").encode("ascii") + body


def make_request(host, port, method, path, body=None, headers=None):
    payload = build_request(method, path, host, port, body or b"", headers)
    try:
        with socket.create_connection((host, port), timeout=2) as sock:
            sock.sendall(payload)
            response = sock.recv(2048)
            if not response:
                return None
            status_line = response.split(b"\r\n", 1)[0].decode(errors="ignore")
            parts = status_line.split(" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
            return None
    except Exception:
        return None


def worker(stop_event, host, port, get_payload, post_payload, sleep_interval, counter):
    while not stop_event.is_set():
        if (
            make_request(
                host,
                port,
                "GET",
                "/hello",
                body=get_payload,
                headers={"Content-Type": "application/octet-stream"},
            )
            == 200
        ):
            counter["GET /hello"] += 1

        time.sleep(sleep_interval)

        if (
            make_request(
                host,
                port,
                "GET",
                "/json",
                body=get_payload,
                headers={"Content-Type": "application/octet-stream"},
            )
            == 200
        ):
            counter["GET /json"] += 1

        time.sleep(sleep_interval)

        status = make_request(
            host,
            port,
            "POST",
            "/submit",
            body=post_payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        if status == 201:
            counter["POST /submit"] += 1

        time.sleep(sleep_interval)


def main():
    args = parse_args()
    post_payload = os.urandom(args.payload_bytes)
    get_payload = post_payload[: max(1, args.payload_bytes // 2)]

    stop_event = threading.Event()
    counters = [Counter() for _ in range(args.workers)]
    threads = []

    for i in range(args.workers):
        thread = threading.Thread(
            target=worker,
            args=(
                stop_event,
                args.host,
                args.port,
                get_payload,
                post_payload,
                args.sleep,
                counters[i],
            ),
            name=f"http-worker-{i}",
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    print(
        f"HTTP load generator running for {args.duration}s on "
        f"{args.host}:{args.port} with {args.workers} workers "
        f"(GET payload: {len(get_payload)} bytes, POST payload: {len(post_payload)} bytes)"
    )

    try:
        time.sleep(args.duration)
    finally:
        stop_event.set()
        for thread in threads:
            thread.join()

    totals = Counter()
    for counter in counters:
        totals.update(counter)

    print("HTTP load summary:")
    for name, count in sorted(totals.items()):
        print(f"  {name}: {count}")


if __name__ == "__main__":
    main()
