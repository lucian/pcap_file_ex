#!/usr/bin/env python3
"""
HTTP/2 cleartext (h2c) server for generating test traffic.

Requires: pip install h2

This server implements prior-knowledge h2c (no HTTP/1.1 Upgrade).
Clients must send the HTTP/2 connection preface directly.
"""

import socket
import sys
from collections import defaultdict

try:
    import h2.config
    import h2.connection
    import h2.events
except ImportError:
    print("Error: h2 library required. Install with: pip install h2", file=sys.stderr)
    sys.exit(1)

DEFAULT_PORT = 8097


class H2CServer:
    """Simple HTTP/2 cleartext server for testing."""

    def __init__(self, port=DEFAULT_PORT):
        self.port = port
        self.sock = None

    def start(self):
        """Start listening for connections."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen(5)
        print(f"H2C server listening on http://127.0.0.1:{self.port}")

        try:
            while True:
                client_sock, addr = self.sock.accept()
                print(f"Connection from {addr}")
                self.handle_connection(client_sock)
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            self.sock.close()

    def handle_connection(self, sock):
        """Handle a single HTTP/2 connection."""
        config = h2.config.H2Configuration(client_side=False)
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        # Track request data per stream
        request_headers = defaultdict(list)
        request_data = defaultdict(bytes)

        try:
            while True:
                data = sock.recv(65535)
                if not data:
                    break

                events = conn.receive_data(data)

                for event in events:
                    if isinstance(event, h2.events.RequestReceived):
                        request_headers[event.stream_id] = event.headers

                    elif isinstance(event, h2.events.DataReceived):
                        request_data[event.stream_id] += event.data
                        conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )

                    elif isinstance(event, h2.events.StreamEnded):
                        self.handle_request(
                            conn,
                            event.stream_id,
                            request_headers[event.stream_id],
                            request_data[event.stream_id],
                        )
                        # Clean up
                        del request_headers[event.stream_id]
                        if event.stream_id in request_data:
                            del request_data[event.stream_id]

                    elif isinstance(event, h2.events.ConnectionTerminated):
                        return

                data_to_send = conn.data_to_send()
                if data_to_send:
                    sock.sendall(data_to_send)

        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            sock.close()

    def handle_request(self, conn, stream_id, headers, body):
        """Handle a complete HTTP/2 request and send response."""
        # Extract method and path from pseudo-headers
        headers_dict = dict(headers)
        method = headers_dict.get(":method", "GET")
        path = headers_dict.get(":path", "/")

        print(f"  Stream {stream_id}: {method} {path} ({len(body)} bytes)")

        # Route to handlers
        if path == "/hello":
            self.send_hello(conn, stream_id, body)
        elif path == "/json":
            self.send_json(conn, stream_id, body)
        elif path == "/submit" and method == "POST":
            self.send_submit(conn, stream_id, body)
        elif path == "/echo" and method == "POST":
            self.send_echo(conn, stream_id, body)
        elif path == "/large":
            self.send_large(conn, stream_id)
        elif path == "/trailers":
            self.send_with_trailers(conn, stream_id, body)
        else:
            self.send_not_found(conn, stream_id)

    def send_hello(self, conn, stream_id, body):
        """Send simple text response."""
        response = b"Hello, HTTP/2 World!"
        if body:
            response += b"\nReceived %d bytes" % len(body)

        headers = [
            (":status", "200"),
            ("content-type", "text/plain"),
            ("content-length", str(len(response))),
        ]
        conn.send_headers(stream_id, headers)
        conn.send_data(stream_id, response, end_stream=True)

    def send_json(self, conn, stream_id, body):
        """Send JSON response."""
        response = b'{"message": "test", "protocol": "h2c", "status": "ok"'
        if body:
            response += b', "request_bytes": %d' % len(body)
        response += b"}"

        headers = [
            (":status", "200"),
            ("content-type", "application/json"),
            ("content-length", str(len(response))),
        ]
        conn.send_headers(stream_id, headers)
        conn.send_data(stream_id, response, end_stream=True)

    def send_submit(self, conn, stream_id, body):
        """Send accepted response for POST."""
        response = b'{"status": "accepted", "bytes": %d}' % len(body)

        headers = [
            (":status", "201"),
            ("content-type", "application/json"),
            ("content-length", str(len(response))),
        ]
        conn.send_headers(stream_id, headers)
        conn.send_data(stream_id, response, end_stream=True)

    def send_echo(self, conn, stream_id, body):
        """Echo back the request body."""
        headers = [
            (":status", "200"),
            ("content-type", "application/octet-stream"),
            ("content-length", str(len(body))),
        ]
        conn.send_headers(stream_id, headers)
        conn.send_data(stream_id, body, end_stream=True)

    def send_large(self, conn, stream_id):
        """Send a large response (for testing DATA frame splitting)."""
        # 64KB response - will be split across multiple DATA frames
        response = b"X" * 65536

        headers = [
            (":status", "200"),
            ("content-type", "application/octet-stream"),
            ("content-length", str(len(response))),
        ]
        conn.send_headers(stream_id, headers)

        # Send in chunks to generate multiple DATA frames
        chunk_size = 16384
        for i in range(0, len(response), chunk_size):
            chunk = response[i : i + chunk_size]
            end_stream = i + chunk_size >= len(response)
            conn.send_data(stream_id, chunk, end_stream=end_stream)

    def send_with_trailers(self, conn, stream_id, body):
        """Send response with trailing headers (for gRPC-style flows)."""
        response = b'{"data": "with trailers"}'

        # Initial headers (no END_STREAM)
        headers = [
            (":status", "200"),
            ("content-type", "application/json"),
        ]
        conn.send_headers(stream_id, headers)

        # Data (no END_STREAM)
        conn.send_data(stream_id, response, end_stream=False)

        # Trailing headers (with END_STREAM)
        trailers = [
            ("grpc-status", "0"),
            ("grpc-message", "OK"),
        ]
        conn.send_headers(stream_id, trailers, end_stream=True)

    def send_not_found(self, conn, stream_id):
        """Send 404 response."""
        response = b"Not Found"

        headers = [
            (":status", "404"),
            ("content-type", "text/plain"),
            ("content-length", str(len(response))),
        ]
        conn.send_headers(stream_id, headers)
        conn.send_data(stream_id, response, end_stream=True)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    server = H2CServer(port)
    server.start()


if __name__ == "__main__":
    main()
