from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


HOST = "127.0.0.1"
PORT = 8000
TRUSTED_ORIGIN = "https://trusted.example"


class WebHawkLabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "WebHawkLocalLab/1.0"
    sys_version = ""

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        origin = self.headers.get("Origin")

        headers = []
        body = f"WebHawk local lab response: {path}\n".encode("utf-8")

        if path == "/cors/wildcard":
            headers.append(("Access-Control-Allow-Origin", "*"))

        elif path == "/cors/credentials":
            headers.extend([
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            ])

        elif path == "/cors/null":
            headers.append(("Access-Control-Allow-Origin", "null"))

        elif path == "/cors/duplicate":
            headers.extend([
                ("Access-Control-Allow-Origin", "https://trusted.example"),
                ("Access-Control-Allow-Origin", "https://other.example"),
            ])

        elif path == "/cors/invalid":
            headers.append((
                "Access-Control-Allow-Origin",
                "https://trusted.example/path",
            ))

        elif path == "/cors/allowlist":
            if origin == TRUSTED_ORIGIN:
                headers.append(("Access-Control-Allow-Origin", origin))
                headers.append(("Vary", "Origin"))

        elif path == "/cookies/insecure":
            headers.append((
                "Set-Cookie",
                "sessionid=lab-only-value; Path=/",
            ))

        elif path == "/cookies/configured":
            headers.append((
                "Set-Cookie",
                "sessionid=lab-safe-value; Path=/; Secure; HttpOnly; SameSite=Lax",
            ))

        elif path == "/headers/missing":
            pass

        else:
            self.send_error(404, "Unknown WebHawk lab route")
            return

        self.send_response(200)

        for name, value in headers:
            self.send_header(name, value)

        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()

        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format_string, *args):
        print(f"[LAB] {self.client_address[0]} - {format_string % args}")


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), WebHawkLabHandler)
    server.daemon_threads = True

    print(f"WebHawk local lab listening on http://{HOST}:{PORT}")
    print("Bound to loopback only. Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping WebHawk local lab...")
    finally:
        server.server_close()
