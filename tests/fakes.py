"""Fake ACME server and fake Cloudflare DNS API for offline tests.

The fake ACME server verifies JWS signatures, checks that the DNS-01 TXT
record published through the fake Cloudflare API has the right value, and
signs the CSR with a local CA.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import itertools
import json
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import josepy as jose
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .helpers import CA


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class _Server(ThreadingHTTPServer):
    daemon_threads = True


class _Base:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        handler = self._handler_class()
        self.httpd = _Server(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _handler_class(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep test output quiet
                pass

            def _body(self) -> bytes:
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n) if n else b""

            def do_GET(self):
                outer.handle(self, "GET", b"")

            def do_HEAD(self):
                outer.handle(self, "HEAD", b"")

            def do_POST(self):
                outer.handle(self, "POST", self._body())

            def do_DELETE(self):
                outer.handle(self, "DELETE", self._body())

        return Handler

    @staticmethod
    def send(h, status, body=None, headers=None, content_type="application/json"):
        data = b""
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h.send_response(status)
        for k, v in (headers or {}).items():
            h.send_header(k, v)
        h.send_header("Content-Type", content_type)
        h.send_header("Content-Length", str(len(data)))
        h.end_headers()
        if h.command != "HEAD":
            h.wfile.write(data)


class FakeCloudflare(_Base):
    def __init__(self, token: str = "cf-test-token", zone_id: str = "zone123") -> None:
        self.token = token
        self.zone_id = zone_id
        self.records: dict[str, dict] = {}
        self.created: list[dict] = []
        self.deleted: list[str] = []
        self.fail_delete = False
        self.create_delay = 0.0  # seconds before a create answers (after the record exists)
        self.delete_delay = 0.0  # seconds before a delete takes effect and answers
        self.list_calls = 0
        super().__init__()

    def add_record(self, name: str, content: str, comment: str, age_seconds: float = 0.0) -> str:
        """Put a TXT record straight into the zone (as if created earlier)."""
        created = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=age_seconds)
        rid = secrets.token_hex(8)
        with self.lock:
            self.records[rid] = {"type": "TXT", "name": name, "content": content, "comment": comment,
                                 "created_on": created.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
        return rid

    @property
    def api(self) -> str:
        return self.base + "/client/v4"

    def txt_values(self, name: str) -> list[str]:
        with self.lock:
            return [r["content"] for r in self.records.values() if r["name"] == name]

    def handle(self, h, method, body):
        if h.headers.get("Authorization") != f"Bearer {self.token}":
            return self.send(h, 403, {"success": False, "errors": [{"code": 10000, "message": "auth"}]})
        prefix = f"/client/v4/zones/{self.zone_id}/dns_records"
        path, _, query = h.path.partition("?")
        if method == "GET" and path == prefix:
            q = dict(urllib.parse.parse_qsl(query))
            self.list_calls += 1
            with self.lock:
                rows = [dict(r, id=rid) for rid, r in self.records.items()
                        if r["type"] == q.get("type", r["type"]) and r["name"] == q.get("name", r["name"])]
            per_page = int(q.get("per_page", "100"))
            page = int(q.get("page", "1"))
            total_pages = max(1, -(-len(rows) // per_page))
            chunk = rows[(page - 1) * per_page: page * per_page]
            # Cloudflare returns TXT content in quotes.
            chunk = [dict(r, content='"' + r["content"] + '"') for r in chunk]
            return self.send(h, 200, {"success": True, "result": chunk,
                                      "result_info": {"page": page, "per_page": per_page,
                                                      "total_pages": total_pages}})
        if method == "POST" and path == prefix:
            rec = json.loads(body)
            assert rec["type"] == "TXT"
            rid = secrets.token_hex(8)
            rec["created_on"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            with self.lock:
                self.records[rid] = rec
                self.created.append(dict(rec, id=rid))
            if self.create_delay:
                time.sleep(self.create_delay)
            return self.send(h, 200, {"success": True, "result": {"id": rid}})
        if method == "DELETE" and h.path.startswith(prefix + "/"):
            rid = h.path[len(prefix) + 1:]
            if self.delete_delay:
                time.sleep(self.delete_delay)
            if self.fail_delete:
                return self.send(h, 500, {"success": False, "errors": [{"code": 1}]})
            with self.lock:
                if rid not in self.records:
                    return self.send(h, 404, {"success": False, "errors": [{"code": 81044}]})
                del self.records[rid]
                self.deleted.append(rid)
            return self.send(h, 200, {"success": True, "result": {"id": rid}})
        return self.send(h, 404, {"success": False, "errors": [{"code": 7003}]})


class FakeACME(_Base):
    def __init__(self, dns: FakeCloudflare) -> None:
        self.dns = dns
        self.ca = CA()
        self.ids = itertools.count(1)
        self.nonces: set[str] = set()
        self.accounts: dict[str, jose.JWK] = {}  # url -> key
        self.orders: dict[str, dict] = {}
        self.authzs: dict[str, dict] = {}
        self.challs: dict[str, dict] = {}
        self.certs: dict[str, str] = {}
        self.rate_limited = False
        self.fail_validation = False
        self.chall_delay = 0.0  # seconds before a challenge answer is processed
        self.new_account_calls = 0
        self.seen_payloads: list[bytes] = []
        super().__init__()

    def directory(self):
        b = self.base
        return {"newNonce": b + "/new-nonce", "newAccount": b + "/new-account", "newOrder": b + "/new-order",
                "revokeCert": b + "/revoke", "keyChange": b + "/key-change",
                "meta": {"termsOfService": b + "/tos"}}

    def nonce(self) -> str:
        n = b64(secrets.token_bytes(16))
        with self.lock:
            self.nonces.add(n)
        return n

    def problem(self, h, status, typ, detail=""):
        return self.send(h, status, {"type": "urn:ietf:params:acme:error:" + typ, "detail": detail},
                         {"Replay-Nonce": self.nonce()}, "application/problem+json")

    def handle(self, h, method, body):
        path = h.path
        if path == "/directory":
            return self.send(h, 200, self.directory())
        if path == "/new-nonce":
            return self.send(h, 200 if method == "HEAD" else 204, None, {"Replay-Nonce": self.nonce(),
                                                                       "Cache-Control": "no-store"})
        if method != "POST":
            return self.send(h, 405, {})
        jws = json.loads(body)
        protected = json.loads(unb64(jws["protected"]))
        with self.lock:
            if protected.get("nonce") not in self.nonces:
                return self.problem(h, 400, "badNonce")
            self.nonces.discard(protected["nonce"])
        if protected.get("url") != self.base + path:
            return self.problem(h, 400, "unauthorized", "url mismatch")
        if "jwk" in protected:
            key = jose.JWK.from_json(protected["jwk"])
            account_url = None
        else:
            account_url = protected.get("kid")
            key = self.accounts.get(account_url)
            if key is None:
                return self.problem(h, 400, "accountDoesNotExist")
        parsed = jose.JWS.json_loads(body)
        if not parsed.verify(key):
            return self.problem(h, 400, "malformed", "bad signature")
        payload = unb64(jws["payload"]) if jws["payload"] else b""
        self.seen_payloads.append(payload)
        obj = json.loads(payload) if payload else None
        return self.route(h, path, key, account_url, obj)

    def route(self, h, path, key, account_url, obj):
        n = {"Replay-Nonce": self.nonce()}
        if path == "/new-account":
            self.new_account_calls += 1
            thumb = b64(key.thumbprint())
            url = f"{self.base}/acct/{thumb[:16]}"
            existed = url in self.accounts
            self.accounts[url] = key
            return self.send(h, 200 if existed else 201, {"status": "valid", "contact": obj.get("contact", [])},
                             dict(n, Location=url))
        if account_url is None:
            return self.problem(h, 400, "malformed", "kid required")
        if path == "/new-order":
            if self.rate_limited:
                return self.problem(h, 429, "rateLimited", "too many certificates")
            oid = str(next(self.ids))
            authz_urls = []
            for ident in obj["identifiers"]:
                aid = str(next(self.ids))
                cid = str(next(self.ids))
                token = b64(secrets.token_bytes(32))
                self.challs[cid] = {"type": "dns-01", "url": f"{self.base}/chall/{cid}", "token": token,
                                    "status": "pending", "_authz": aid, "_key": key}
                self.authzs[aid] = {"identifier": ident, "status": "pending", "_challs": [cid], "_order": oid}
                authz_urls.append(f"{self.base}/authz/{aid}")
            self.orders[oid] = {"status": "pending", "identifiers": obj["identifiers"],
                                "authorizations": authz_urls, "finalize": f"{self.base}/finalize/{oid}"}
            return self.send(h, 201, self._order(oid), dict(n, Location=f"{self.base}/order/{oid}"))
        kind, _, ident = path.strip("/").partition("/")
        if kind == "authz":
            return self.send(h, 200, self._authz(ident), n)
        if kind == "chall":
            if self.chall_delay:
                time.sleep(self.chall_delay)
            ch = self.challs[ident]
            authz = self.authzs[ch["_authz"]]
            name = "_acme-challenge." + authz["identifier"]["value"]
            key_auth = ch["token"] + "." + b64(ch["_key"].thumbprint())
            expected = b64(hashlib.sha256(key_auth.encode()).digest())
            if not self.fail_validation and expected in self.dns.txt_values(name):
                ch["status"] = "valid"
                authz["status"] = "valid"
            else:
                ch["status"] = "invalid"
                ch["error"] = {"type": "urn:ietf:params:acme:error:unauthorized", "detail": "no TXT"}
                authz["status"] = "invalid"
            order = self.orders[authz["_order"]]
            states = {self.authzs[u.rsplit("/", 1)[1]]["status"] for u in order["authorizations"]}
            if states == {"valid"}:
                order["status"] = "ready"
            elif "invalid" in states:
                order["status"] = "invalid"
            up = {"Link": f'<{self.base}/authz/{ch["_authz"]}>;rel="up"'}
            return self.send(h, 200, self._chall(ident), dict(n, **up))
        if kind == "finalize":
            order = self.orders[ident]
            if order["status"] != "ready":
                return self.problem(h, 403, "orderNotReady")
            csr = x509.load_der_x509_csr(unb64(obj["csr"]))
            cert = self.ca.sign_csr(csr)
            self.certs[ident] = (cert.public_bytes(serialization.Encoding.PEM) + self.ca.pem).decode()
            order["status"] = "valid"
            order["certificate"] = f"{self.base}/cert/{ident}"
            return self.send(h, 200, self._order(ident), n)
        if kind == "order":
            return self.send(h, 200, self._order(ident), n)
        if kind == "cert":
            return self.send(h, 200, self.certs[ident].encode(), n, "application/pem-certificate-chain")
        return self.problem(h, 404, "malformed", "unknown")

    def _order(self, oid):
        return {k: v for k, v in self.orders[oid].items() if not k.startswith("_")}

    def _chall(self, cid):
        return {k: v for k, v in self.challs[cid].items() if not k.startswith("_")}

    def _authz(self, aid):
        a = self.authzs[aid]
        out = {k: v for k, v in a.items() if not k.startswith("_")}
        out["challenges"] = [self._chall(c) for c in a["_challs"]]
        return out
