"""OAuth 2.0 Device Authorization Grant (RFC 8628): a mock authorization server and a TV-style client that polls."""
import json, secrets, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse, request

INTERVAL = 1
DEVICES = {}  # device_code -> {"user_code", "approved", "last_poll", "expires"}


class AuthServer(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        form = parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        if self.path == "/device_authorization":
            dc, uc = secrets.token_urlsafe(24), secrets.token_hex(4).upper()
            DEVICES[dc] = {"user_code": uc, "approved": False, "last_poll": 0, "expires": time.time() + 30}
            return self.reply(200, {"device_code": dc, "user_code": uc, "expires_in": 30, "interval": INTERVAL,
                                    "verification_uri": "http://localhost/activate"})
        if self.path == "/token":
            d = DEVICES.get(form["device_code"][0])
            if not d or time.time() > d["expires"]:
                return self.reply(400, {"error": "expired_token"})
            too_fast = time.time() - d["last_poll"] < INTERVAL
            d["last_poll"] = time.time()
            if too_fast:
                return self.reply(400, {"error": "slow_down"})
            if not d["approved"]:
                return self.reply(400, {"error": "authorization_pending"})
            return self.reply(200, {"access_token": secrets.token_urlsafe(16), "token_type": "Bearer"})
        if self.path == "/activate":  # the user's second device: enter the code and approve
            for d in DEVICES.values():
                if d["user_code"] == form["user_code"][0]:
                    d["approved"] = True
                    return self.reply(200, {"status": "approved"})
            return self.reply(404, {"error": "unknown user_code"})


def post(base, path, **form):
    req = request.Request(base + path, data=parse.urlencode(form).encode())
    try:
        with request.urlopen(req) as r:
            return r.status, json.load(r)
    except request.HTTPError as e:
        return e.code, json.load(e)


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", 0), AuthServer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"

    _, grant = post(base, "/device_authorization", client_id="tv-app")
    print(f"On your phone open {grant['verification_uri']} and enter {grant['user_code']}")
    # the "phone" approves after ~2.5s; the device keeps polling meanwhile
    threading.Timer(2.5, post, (base, "/activate"), {"user_code": grant["user_code"]}).start()

    seen, interval = [], grant["interval"]
    while True:
        time.sleep(interval)
        code, body = post(base, "/token", grant_type="urn:ietf:params:oauth:grant-type:device_code",
                          device_code=grant["device_code"], client_id="tv-app")
        if code == 200:
            break
        seen.append(body["error"])
        if body["error"] == "slow_down":
            interval += 5
    assert "authorization_pending" in seen, seen
    assert body["token_type"] == "Bearer"
    print("polled:", ", ".join(seen), "-> got access token")
    code, early = post(base, "/token", grant_type="x", device_code=grant["device_code"])
    assert code == 200 or early["error"] == "slow_down"  # polling faster than `interval` is punished
    print("OK")
    srv.shutdown()
