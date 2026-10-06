"""Minimal SCIM 2.0 /Users service (RFC 7644) plus an IdP-style client that provisions and deprovisions a user."""
import json, threading, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import request, parse

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
TOKEN = "lab-bearer-token"  # demo value, not a credential
USERS = {}


class Scim(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/scim+json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")

    def authed(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.reply(401, {"detail": "unauthorized"})
            return False
        return True

    def do_POST(self):
        if not self.authed():
            return
        u = self.body()
        if any(x["userName"] == u["userName"] for x in USERS.values()):
            return self.reply(409, {"scimType": "uniqueness", "detail": "userName taken"})
        u.update(id=str(uuid.uuid4()), schemas=[USER_SCHEMA], active=u.get("active", True))
        USERS[u["id"]] = u
        self.reply(201, u)

    def do_GET(self):
        if not self.authed():
            return
        url = parse.urlparse(self.path)
        parts = url.path.strip("/").split("/")
        if len(parts) == 4:
            u = USERS.get(parts[-1])
            return self.reply(200, u) if u else self.reply(404, {"detail": "not found"})
        found = list(USERS.values())
        flt = parse.parse_qs(url.query).get("filter")
        if flt:  # supports only: userName eq "x"
            want = flt[0].split('"')[1]
            found = [u for u in found if u["userName"] == want]
        self.reply(200, {"schemas": [LIST_SCHEMA], "totalResults": len(found), "Resources": found})

    def do_PATCH(self):
        if not self.authed():
            return
        u = USERS.get(self.path.strip("/").split("/")[-1])
        if not u:
            return self.reply(404, {"detail": "not found"})
        for op in self.body()["Operations"]:  # supports: replace <attr>
            if op["op"].lower() == "replace":
                u[op["path"]] = op["value"]
        self.reply(200, u)

    def do_DELETE(self):
        if not self.authed():
            return
        USERS.pop(self.path.strip("/").split("/")[-1], None)
        self.reply(204)


def call(base, method, path, body=None, token=TOKEN):
    req = request.Request(base + path, method=method, data=json.dumps(body).encode() if body else None,
                          headers={"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"})
    try:
        with request.urlopen(req) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except request.HTTPError as e:
        return e.code, None


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", 0), Scim)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}/scim/v2"

    code, u = call(base, "POST", "/Users", {"schemas": [USER_SCHEMA], "userName": "ada@orders.test"})
    assert code == 201, code
    print("provisioned", u["userName"], u["id"])
    assert call(base, "POST", "/Users", {"userName": "ada@orders.test"})[0] == 409
    _, found = call(base, "GET", "/Users?" + parse.urlencode({"filter": 'userName eq "ada@orders.test"'}))
    assert found["totalResults"] == 1
    _, patched = call(base, "PATCH", f"/Users/{u['id']}",
                      {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "active", "value": False}]})
    assert patched["active"] is False
    print("deactivated (leaver flow)")
    assert call(base, "GET", "/Users", token="wrong")[0] == 401
    assert call(base, "DELETE", f"/Users/{u['id']}")[0] == 204
    assert call(base, "GET", f"/Users/{u['id']}")[0] == 404
    print("OK")
    srv.shutdown()
