# akdbx relay: design and protocol (v1)

The akdbx relay lets a person open their akdbx broker's private pages (unlock,
password and card saves, pairing) from any device on the internet, without an
open port, a router change or a VPN. The relay forwards **encrypted** TLS
connections. It never holds a broker's private key, so it cannot read the
master password or any other value that passes through it.

The relay is optional. akdbx also works with no proxy (local only), with a
private proxy such as Tailscale Serve (recommended first, most secure), or with
another public tunnel. Proxies that decrypt HTTPS are strongly discouraged.

## Names and addresses

- Relay domain: `akdbx.link`.
- Each broker gets one random name: `<id>.akdbx.link`, where `<id>` is 12
  characters from `[a-z2-7]` (base32, no user choice, so nobody can register a
  look-alike name such as `paypal`). The relay refuses reserved labels
  (`www`, `api`, `relay`, `mail`, and any label shorter than 12 characters).
- Public origin of a broker: `https://<id>.akdbx.link:8443`.
  Port 8443, because port 443 on the relay host serves other sites through
  Cloudflare's proxy, which decrypts traffic. The relay must not be behind that
  proxy.
- Control API: `https://relay.akdbx.link:8443/api/v1/...` (the control host
  name is configurable). It is served on the same public port: the relay
  reads the SNI name, and for the control host name it terminates TLS
  itself, with its own certificate and key. It carries no master password:
  only registration, certificate requests (CSRs, never private keys), bearer
  secrets, and the encrypted tunnel streams (WebSocket frames of TLS
  ciphertext).
- The apex `https://akdbx.link/` is only a static landing page (through
  Cloudflare's proxy). No API route is reachable there.

DNS (Cloudflare zone `akdbx.link`):

| Name | Type | Proxy | Value |
| --- | --- | --- | --- |
| `akdbx.link` | A | proxied | relay host IPv4 (landing page only) |
| `*.akdbx.link` | A / AAAA | **DNS only** | relay host IPv4 / IPv6 (broker names and `relay.akdbx.link`) |
| `_acme-challenge.<id>.akdbx.link`, `_acme-challenge.relay.akdbx.link` | TXT | DNS only | created and removed by the relay during issuance |

## Trust model: no third party in the control path

Every connection to the relay, for brokers and for phones, goes straight to
the relay host on port 8443 through DNS-only names. No proxy, CDN or tunnel
decrypts any of it:

- **Broker pages** (`<id>.akdbx.link`): TLS ends in the broker. The relay
  sees only the SNI name and ciphertext.
- **Control API** (`relay.akdbx.link`): TLS ends in the relay process, with
  a key that only the relay holds (mode 0600 in its state directory). Bearer
  secrets, which authorize certificate requests and the control channel,
  therefore reach nobody but the relay. Earlier drafts served the control API
  through Cloudflare's TLS-terminating proxy; that let Cloudflare see every
  secret, and it is no longer supported.
- **Client addresses** for rate limits are the TCP peer addresses of these
  direct connections. The relay trusts no forwarded-address header
  (`CF-Connecting-IP`, `X-Forwarded-For` and similar are ignored).
- The relay's plain-HTTP port, if enabled, listens on a loopback address and
  answers only `GET /api/v1/health`.

The remaining trust point is the DNS zone, as the README describes: whoever
controls `akdbx.link` can obtain certificates for its names, which
Certificate Transparency logs make visible.

## Data path

```
phone browser --TLS(SNI=<id>.akdbx.link)--> relay :8443 (reads SNI only, no decryption)
   relay --"open stream S" over the broker's control WebSocket--> broker
   broker --new WebSocket wss://relay.akdbx.link:8443/api/v1/stream/S--> relay
   relay splices: phone TCP bytes <-> WebSocket binary frames
   broker splices: WebSocket binary frames <-> 127.0.0.1:<local-port> (the broker's own HTTPS page)
TLS terminates only in the broker, with the broker's own key.
```

## Protocol

All JSON bodies are UTF-8. All control endpoints are HTTPS at the control
base URL `https://relay.akdbx.link:8443`, terminated by the relay itself.
Brokers verify the relay's certificate as usual (a publicly trusted
certificate for the control host name) and send `Host: relay.akdbx.link:8443`.

Every error response has a JSON body `{"error": "<code>", "message": "..."}`.
When waiting can help (`429` and `503`), the body also has `"retry_after":
<integer seconds>` and the response has the same value in a `Retry-After`
header. Clients must accept unknown JSON fields.

### Health: `GET /api/v1/health`

Response 200: `{"status": "ok", "protocol": 1, "version": "<relay version>",
"registrations": "open" | "paused"}`. No authentication. Also served on the
relay host's loopback plain-HTTP port (default `127.0.0.1:8771`) for local
monitoring; that port has no other route.

### Register: `POST /api/v1/register`

Request: `{"protocol": 1, "client": "akdbx/<version>"}`. `client` is optional
(at most 64 printable characters).

Response 201: `{"protocol": 1, "name": "<id>.akdbx.link", "broker_id": "<id>",
"secret": "<43-char base64url>", "public_port": 8443}`.

- `secret` is a bearer credential. The relay stores only its SHA-256.
- Errors: 429 `rate_limited` (per source IP, the TCP peer address, default
  5 registrations per day; IPv6 addresses count per /64); 503 `registrations_paused` (certificate
  budget used up, see below); 400 `unsupported_protocol`; 400 `bad_request`.

### Certificate: `POST /api/v1/certificate`

Header `Authorization: Bearer <secret>`. Body: `{"csr": "<PEM CSR>"}`.

- The CSR must contain exactly one DNS name, equal to the broker's assigned
  name, and no other names or IP addresses. Key type: ECDSA P-256 or RSA 2048+.
- The relay runs ACME (Let's Encrypt production; staging in tests) with the
  DNS-01 challenge through the Cloudflare API, then removes the TXT record.
- **Deadline:** the relay answers within the certificate deadline (default
  90 s, `AKDBX_RELAY_CERTIFICATE_DEADLINE`). The deadline starts when the
  request arrives and covers both the wait for a free issuance slot and the
  ACME order. A request that cannot start its order in time gets
  `503 issuance_paused`; an order that does not finish in time gets
  `502 acme_failed`. Brokers should wait at least the deadline plus 10 s
  before they give up (the reference client waits 120 s).
- Response 200: `{"certificate": "<PEM chain, leaf first>", "not_after": "<RFC3339>"}`.
- A broker renews when less than one third of the lifetime remains. It may
  reuse or rotate its key.
- `not_after` is UTC in the form `YYYY-MM-DDTHH:MM:SSZ`.
- Errors: 401 `unauthorized`; 400 `bad_csr`; 429 `rate_limited` (more than
  5 certificates for this broker in 7 days, or a request for this broker is
  still running); 503 `issuance_paused` (relay budget or the certificate
  authority's rate limit reached, issuance not configured, or the relay is
  too busy to start the order within the deadline); 502 `acme_failed` (the
  order failed or passed the deadline). Failed orders do not count against
  any limit.
- The CSR subject may be empty or hold only a common name equal to the
  broker's name. Allowed extensions: subjectAltName, keyUsage,
  extendedKeyUsage, basicConstraints (not a CA).

### Control channel: `GET /api/v1/connect` (WebSocket)

Header `Authorization: Bearer <secret>`. One live control connection per
broker; a new one replaces the old one.

Relay to broker text frames: `{"type": "open", "stream": "<32-hex id>"}` and
`{"type": "ping"}`. Broker to relay: `{"type": "pong"}`. The relay sends a ping
every 30 s and closes a control connection that does not answer in 60 s. The
broker reconnects with backoff (1 s doubling to 60 s, with jitter).

- The broker may also send `{"type": "ping"}`; the relay answers
  `{"type": "pong"}`. Both sides ignore unknown message types.
- Messages are at most 4 KiB. Binary frames on the control channel are a
  protocol error.
- Close codes from the relay: 4000 (replaced by a newer control connection),
  4001 (no pong in time), 1003 (binary frame), 1007 (invalid JSON),
  1001 (relay shutting down).
- Errors before the upgrade: 401 `unauthorized`; 400 `websocket_required`.

### Stream: `GET /api/v1/stream/<stream>` (WebSocket)

Header `Authorization: Bearer <secret>`. The stream id must have been announced
to this broker in the last 10 s and is single-use. After the upgrade, binary
frames carry raw bytes in both directions. Either side closes to end the
stream. Text frames on a stream are a protocol error.

- The first binary frame from the relay is the buffered ClientHello, byte for
  byte.
- Binary messages are at most 256 KiB (a TLS record is at most about 16 KiB).
  A message may have at most 256 fragments; more, or more bytes than the
  limit, close the stream with 1009.
- The relay also sends WebSocket ping frames every 30 s when a stream is
  idle, so that NATs and firewalls keep it open; standard WebSocket clients
  answer them automatically. Any received frame counts as an answer. A
  stream with no frames and no pong for 60 s is closed with 1011.
- Errors before the upgrade: 401 `unauthorized`; 404 `unknown_stream`
  (unknown, expired, already used, or announced to another broker);
  400 `websocket_required`.
- Close codes from the relay: 1000 (the phone closed, or the stream was idle),
  1003 (text frame), 1009 (message too big or too many fragments),
  1011 (the phone connection was already gone, or keepalive timeout).
- The relay closes a stream whose broker sends no bytes within 10 s
  (`AKDBX_RELAY_STREAM_FIRST_BYTE_TIMEOUT`; the broker's first bytes are its
  TLS ServerHello), and any stream idle for 5 minutes.
- Every relay close completes within 5 s; after that the relay drops the
  TCP connection.

### Public listener (:8443, raw TCP)

1. Read the TLS ClientHello (at most 16 KiB in at most 8 TLS records, at
   most 5 s) without consuming it, and parse the SNI host name.
2. SNI equal to the control host name: terminate TLS in the relay with its
   own certificate and serve the control API on that connection.
3. Otherwise look up the broker. Unknown name, no live control connection,
   or no SNI: close the connection (no TLS alert is possible, because the
   relay has no certificate for that name).
4. Send `open` on the control channel and wait for the stream WebSocket,
   both within 10 s; replay the buffered ClientHello bytes, then splice.

Limits (defaults, configurable). "Per source IP" means per IPv4 address or
per IPv6 /64, by TCP peer address; it counts all connections to port 8443
from that address, including a broker's own control and stream connections:

- 10 new connections per second per source IP (burst 20);
- 1024 connections still sending their ClientHello, at most 8 per source IP;
- 64 concurrent streams per broker, 2048 in total, at most 16 per source IP
  (phone side, held for the connection's life);
- 4096 concurrent control-API connections, at most 96 per source IP;
- 10 s for the broker's first bytes, then 5 minutes idle;
- bytes are not inspected or stored.

Rate-limit tables hold at most 100,000 addresses each. When a table is full,
the relay drops entries that no longer limit anything, then the least
recently used entry, so new addresses are never all refused.

## Certificate budget and the Public Suffix List

Let's Encrypt allows about 50 new certificates per registered domain each
week; renewals of the same name are exempt. The relay counts new
(first-time) certificates in a rolling 7-day window. When the count reaches a
configured budget (default 40), it answers new registrations with
`503 registrations_paused` and a `retry_after` time. Existing brokers keep
renewing.

- A registration that has no certificate yet holds one budget slot for 24
  hours, so a burst of registrations cannot overshoot the weekly limit.
- A separate hard limit (default 48) stops first-time issuance with
  `503 issuance_paused`. Renewals (a broker that already has a certificate)
  are limited only by the per-broker cap. Plan: request a higher limit with Let's Encrypt's rate-limit form,
and submit `akdbx.link` to the Public Suffix List (private section) for
per-user site isolation once the relay serves enough users. The PSL does not
accept entries whose only purpose is a rate limit.

## Broker side (akdbx)

- `akdbx relay enable [--relay https://relay.akdbx.link:8443]`: register, create an
  ECDSA P-256 key and CSR, get the certificate, and write a private relay
  directory (key, certificate chain, `relay.json` with name, port, secret,
  relay URL). Prints the broker's public origin and the `serve` settings. It
  never prints the secret.
- `akdbx relay status`, `akdbx relay disable` (stop using it; keep or delete
  files on request).
- `akdbx serve --relay` (or the saved setting): uses origin
  `https://<id>.akdbx.link:8443`, the relay certificate and key for the
  loopback HTTPS page, a free `--local-port`, and starts the relay client:
  control WebSocket, stream WebSockets spliced to `127.0.0.1:<local-port>`,
  certificate renewal, and hot reload of the TLS context.
- The broker keeps every existing check (token, Host/Origin, 3-attempt link
  block). It trusts no header from the relay.
- Certificate transparency check (warning only): the broker may look for
  certificates for its name that it did not request, and report them in
  `status`.

## Relay host

- Runs on the existing VPS as an unprivileged system user with its own
  systemd unit. Public listener `0.0.0.0:8443` and `[::]:8443`, which serves
  both the broker pages (pass-through) and the control API (relay TLS).
  Optional health port on `127.0.0.1:8771` (plain HTTP, health only). Caddy
  serves only the static landing page at `akdbx.link`.
- The firewall opens 8443/tcp to everyone. Ports 80/443 stay Cloudflare-only.
- Secrets: Cloudflare API token limited to DNS edit on the `akdbx.link` zone
  (in a 0600 environment file); the ACME account key and the relay's control
  TLS key (0600 PEM files in the relay's 0700 state directory). None is in
  Git.
- The relay obtains the certificate for `relay.akdbx.link` itself, through
  the same ACME DNS-01 code, and renews it when a third of its lifetime is
  left. An operator may supply a certificate and key instead
  (`AKDBX_RELAY_CONTROL_CERT_FILE`, `AKDBX_RELAY_CONTROL_KEY_FILE`); the relay
  reloads them when they change (checked hourly).
- State: SQLite (brokers, secret hashes, issued-certificate log, and cleanup
  markers for ACME TXT records). Before the relay creates a TXT record it
  stores a marker; at start-up it removes every marked record and every
  relay-owned `_acme-challenge` record (tagged with the comment
  `akdbx-relay ACME challenge`) older than twice the certificate deadline.
  Run one relay per DNS zone.
