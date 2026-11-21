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
- Control API: `https://akdbx.link/api/v1/...`. This goes through Cloudflare
  (proxied) to the relay's local control port. It carries no master password:
  only registration, certificate requests (CSRs, never private keys) and the
  encrypted tunnel streams (WebSocket frames of TLS ciphertext).

DNS (Cloudflare zone `akdbx.link`):

| Name | Type | Proxy | Value |
| --- | --- | --- | --- |
| `akdbx.link` | A | proxied | relay host IPv4 |
| `*.akdbx.link` | A / AAAA | **DNS only** | relay host IPv4 / IPv6 |
| `_acme-challenge.<id>.akdbx.link` | TXT | DNS only | created and removed by the relay during issuance |

## Data path

```
phone browser --TLS(SNI=<id>.akdbx.link)--> relay :8443 (reads SNI only, no decryption)
   relay --"open stream S" over the broker's control WebSocket--> broker
   broker --new WebSocket wss://akdbx.link/api/v1/stream/S--> relay
   relay splices: phone TCP bytes <-> WebSocket binary frames
   broker splices: WebSocket binary frames <-> 127.0.0.1:<local-port> (the broker's own HTTPS page)
TLS terminates only in the broker, with the broker's own key.
```

## Protocol

All JSON bodies are UTF-8. All control endpoints are HTTPS through Cloudflare.

### Register: `POST /api/v1/register`

Request: `{"protocol": 1, "client": "akdbx/<version>"}`.

Response 201: `{"protocol": 1, "name": "<id>.akdbx.link", "broker_id": "<id>",
"secret": "<43-char base64url>", "public_port": 8443}`.

- `secret` is a bearer credential. The relay stores only its SHA-256.
- Errors (JSON `{"error": "<code>", "message": "..."}`): 429
  `rate_limited` (per source IP, for example 5 registrations per day);
  503 `registrations_paused` (certificate budget used up, see below);
  400 `unsupported_protocol`.

### Certificate: `POST /api/v1/certificate`

Header `Authorization: Bearer <secret>`. Body: `{"csr": "<PEM CSR>"}`.

- The CSR must contain exactly one DNS name, equal to the broker's assigned
  name, and no other names or IP addresses. Key type: ECDSA P-256 or RSA 2048+.
- The relay runs ACME (Let's Encrypt production; staging in tests) with the
  DNS-01 challenge through the Cloudflare API, then removes the TXT record.
- Response 200: `{"certificate": "<PEM chain, leaf first>", "not_after": "<RFC3339>"}`.
- A broker renews when less than one third of the lifetime remains. It may
  reuse or rotate its key.
- Errors: 401 `unauthorized`; 400 `bad_csr`; 503 `issuance_paused`;
  502 `acme_failed`.

### Control channel: `GET /api/v1/connect` (WebSocket)

Header `Authorization: Bearer <secret>`. One live control connection per
broker; a new one replaces the old one.

Relay to broker text frames: `{"type": "open", "stream": "<32-hex id>"}` and
`{"type": "ping"}`. Broker to relay: `{"type": "pong"}`. The relay sends a ping
every 30 s and closes a control connection that does not answer in 60 s. The
broker reconnects with backoff (1 s doubling to 60 s, with jitter).

### Stream: `GET /api/v1/stream/<stream>` (WebSocket)

Header `Authorization: Bearer <secret>`. The stream id must have been announced
to this broker in the last 10 s and is single-use. After the upgrade, binary
frames carry raw bytes in both directions. Either side closes to end the
stream. Text frames on a stream are a protocol error.

### Public listener (:8443, raw TCP)

1. Read the TLS ClientHello (at most 16 KiB, at most 5 s) without consuming
   it, and parse the SNI host name.
2. Look up the broker. Unknown name, no live control connection, or no SNI:
   close the connection (no TLS alert is possible, because the relay has no
   certificate for that name).
3. Send `open` on the control channel, wait at most 10 s for the stream
   WebSocket, replay the buffered ClientHello bytes, then splice.

Limits (defaults, configurable): 64 concurrent streams per broker, 2048 in
total; 10 new connections per second per source IP; idle stream timeout
5 minutes; bytes are not inspected or stored.

## Certificate budget and the Public Suffix List

Let's Encrypt allows about 50 new certificates per registered domain each
week; renewals of the same name are exempt. The relay counts new
(first-time) certificates in a rolling 7-day window. When the count reaches a
configured budget (default 40), it answers new registrations with
`503 registrations_paused` and a `retry_after` time. Existing brokers keep
renewing. Plan: request a higher limit with Let's Encrypt's rate-limit form,
and submit `akdbx.link` to the Public Suffix List (private section) for
per-user site isolation once the relay serves enough users. The PSL does not
accept entries whose only purpose is a rate limit.

## Broker side (akdbx)

- `akdbx relay enable [--relay https://akdbx.link]`: register, create an
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
  systemd unit. Public listener `0.0.0.0:8443` and `[::]:8443`; control API on
  `127.0.0.1:<port>` behind Caddy (`akdbx.link` site, proxied by Cloudflare).
- The firewall opens 8443/tcp to everyone. Ports 80/443 stay Cloudflare-only.
- Secrets: Cloudflare API token limited to DNS edit on the `akdbx.link` zone,
  ACME account key. Both in a 0600 environment file, never in Git.
- State: SQLite (brokers, secret hashes, issued-certificate log).
