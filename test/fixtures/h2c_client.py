#!/usr/bin/env python3
"""
HTTP/2 cleartext (h2c) client for generating test traffic.

Requires: pip install h2

This client uses prior-knowledge h2c (no HTTP/1.1 Upgrade).
Sends the HTTP/2 connection preface directly.
"""

import socket
import sys

try:
    import h2.config
    import h2.connection
    import h2.events
except ImportError:
    print("Error: h2 library required. Install with: pip install h2", file=sys.stderr)
    sys.exit(1)

DEFAULT_PORT = 8097
DEFAULT_REQUESTS = 5


class H2CClient:
    """Simple HTTP/2 cleartext client for testing."""

    def __init__(self, host="127.0.0.1", port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.sock = None
        self.conn = None

    def connect(self):
        """Establish HTTP/2 connection."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        config = h2.config.H2Configuration(client_side=True)
        self.conn = h2.connection.H2Connection(config=config)
        self.conn.initiate_connection()
        self.sock.sendall(self.conn.data_to_send())

        # Receive server's connection preface
        data = self.sock.recv(65535)
        self.conn.receive_data(data)
        self.sock.sendall(self.conn.data_to_send())

    def close(self):
        """Close the connection."""
        if self.sock:
            self.sock.close()
            self.sock = None

    def request(self, method, path, body=None, headers=None):
        """Send a request and return the response."""
        stream_id = self.conn.get_next_available_stream_id()

        # Build headers
        req_headers = [
            (":method", method),
            (":path", path),
            (":scheme", "http"),
            (":authority", f"{self.host}:{self.port}"),
        ]

        if headers:
            req_headers.extend(headers)

        if body:
            req_headers.append(("content-length", str(len(body))))

        # Send headers
        end_stream = body is None
        self.conn.send_headers(stream_id, req_headers, end_stream=end_stream)

        # Send body if present
        if body:
            self.conn.send_data(stream_id, body, end_stream=True)

        self.sock.sendall(self.conn.data_to_send())

        # Receive response
        response_headers = []
        response_data = b""
        response_trailers = []
        stream_ended = False

        while not stream_ended:
            data = self.sock.recv(65535)
            if not data:
                break

            events = self.conn.receive_data(data)

            for event in events:
                if isinstance(event, h2.events.ResponseReceived):
                    response_headers = event.headers

                elif isinstance(event, h2.events.DataReceived):
                    response_data += event.data
                    self.conn.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )

                elif isinstance(event, h2.events.TrailersReceived):
                    response_trailers = event.headers

                elif isinstance(event, h2.events.StreamEnded):
                    if event.stream_id == stream_id:
                        stream_ended = True

            self.sock.sendall(self.conn.data_to_send())

        return {
            "headers": dict(response_headers),
            "data": response_data,
            "trailers": dict(response_trailers) if response_trailers else None,
        }

    def get(self, path, headers=None):
        """Send GET request."""
        return self.request("GET", path, headers=headers)

    def post(self, path, body, headers=None):
        """Send POST request."""
        return self.request("POST", path, body=body, headers=headers)


def run_test_traffic(port, num_requests):
    """Generate test HTTP/2 traffic."""
    client = H2CClient(port=port)

    try:
        client.connect()
        print(f"Connected to H2C server on port {port}")

        for i in range(num_requests):
            print(f"\n--- Request set {i + 1}/{num_requests} ---")

            # GET /hello
            resp = client.get("/hello")
            print(f"GET /hello: {resp['headers'].get(':status')} - {resp['data'][:50]}")

            # GET /json
            resp = client.get("/json")
            print(f"GET /json: {resp['headers'].get(':status')} - {resp['data'][:50]}")

            # POST /submit with body
            body = f"test data {i}".encode()
            resp = client.post("/submit", body)
            print(f"POST /submit: {resp['headers'].get(':status')} - {resp['data'][:50]}")

            # POST /echo
            echo_body = b"echo this back please"
            resp = client.post("/echo", echo_body)
            print(f"POST /echo: {resp['headers'].get(':status')} - echoed {len(resp['data'])} bytes")

            # GET /large (large response)
            resp = client.get("/large")
            print(f"GET /large: {resp['headers'].get(':status')} - {len(resp['data'])} bytes")

            # GET /trailers (response with trailing headers)
            resp = client.get("/trailers")
            print(
                f"GET /trailers: {resp['headers'].get(':status')} - trailers: {resp['trailers']}"
            )

            # GET /notfound (404)
            resp = client.get("/notfound")
            print(f"GET /notfound: {resp['headers'].get(':status')}")

    except Exception as e:
        print(f"Error: {e}")
        raise
    finally:
        client.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    num_requests = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_REQUESTS

    run_test_traffic(port, num_requests)


if __name__ == "__main__":
    main()
