#!/usr/bin/env python3
"""Simple HTTP server for generating test traffic."""

import http.server
import socketserver
import sys
from threading import Thread
import time

PORT = 8899


class TestHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Handler that responds to specific test requests."""

    def do_GET(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""

        if self.path == "/hello":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            if body:
                self.send_header("X-Request-Body-Length", str(len(body)))
            self.end_headers()
            payload = b"Hello, World!"
            if body:
                payload += b"\nReceived %d bytes" % len(body)
            self.wfile.write(payload)
        elif self.path == "/json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if body:
                self.send_header("X-Request-Body-Length", str(len(body)))
            self.end_headers()
            response = b'{"message": "test", "status": "ok"'
            if body:
                response += b', "request_body_bytes": %d' % len(body)
            response += b"}"
            self.wfile.write(response)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""

        if self.path == "/submit":
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = b'{"status": "accepted", "bytes": %d}' % len(body)
            self.wfile.write(response)
        elif self.path == "/echo":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress log messages."""
        pass


def run_server(port=PORT):
    """Run the HTTP server."""
    with socketserver.TCPServer(("127.0.0.1", port), TestHTTPHandler) as httpd:
        print(f"Server running on http://127.0.0.1:{port}")
        httpd.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    run_server(port)
