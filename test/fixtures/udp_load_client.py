#!/usr/bin/env python3
"""UDP telemetry load generator for test captures."""

import argparse
import json
import os
import random
import socket
import time


def parse_args():
    parser = argparse.ArgumentParser(description="Generate sustained UDP telemetry.")
    parser.add_argument("--host", default="127.0.0.1", help="UDP server host.")
    parser.add_argument("--port", type=int, default=8898, help="UDP server port.")
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="How long to run the load generator (seconds).",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=200.0,
        help="Target datagrams per second.",
    )
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=256,
        help="Payload size for the JSON `data` field.",
    )
    return parser.parse_args()


def build_payload(seq, payload_bytes):
    reading = {
        "sensor": f"sensor-{seq % 128}",
        "value": round(random.uniform(10.0, 90.0), 3),
        "seq": seq,
        "data": os.urandom(payload_bytes).hex(),
    }
    return json.dumps(reading).encode("utf-8")


def main():
    args = parse_args()

    interval = 1.0 / args.rate if args.rate > 0 else 0.0
    end_time = time.perf_counter() + args.duration
    seq = 0
    sent = 0

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        while time.perf_counter() < end_time:
            seq += 1
            payload = build_payload(seq, args.payload_bytes)
            try:
                sock.sendto(payload, (args.host, args.port))
                sent += 1
            except BlockingIOError:
                # Drop packet if socket buffer is full; we only care about generating load.
                pass

            if interval > 0:
                sleep_until = time.perf_counter() + interval
                while True:
                    now = time.perf_counter()
                    if now >= sleep_until:
                        break
                    time.sleep(min(sleep_until - now, 0.001))

    print(
        f"UDP load summary: host={args.host} port={args.port} "
        f"duration={args.duration}s sent={sent}"
    )


if __name__ == "__main__":
    main()
