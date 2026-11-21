# akdbx-relay

The akdbx relay lets you open your [akdbx](https://github.com/7bgsbm749g-boop/akdbx)
broker's private pages (vault unlock, password and card saves, extension
pairing) from any device, without an open port, a router change or a VPN.

The relay only forwards **encrypted** TLS connections. Each broker holds its
own certificate key; the relay never has it, so the relay cannot read the
master password or any other value that passes through it.

The relay is optional. In order of security, akdbx supports:

1. **Local only:** the page opens only on the broker's own computer.
2. **A private proxy**, such as Tailscale Serve: only your own devices can
   reach the page. This is the most secure way to unlock from another device,
   and the recommended one.
3. **The akdbx relay** (this project), or another public tunnel that does not
   decrypt traffic: any device on the internet can reach the page, and the
   secret link plus akdbx's three-attempt link block protect it.
4. **A public proxy that decrypts HTTPS** (for example Cloudflare Tunnel):
   strongly discouraged, because the proxy operator can read your master
   password.

The design and wire protocol are in [docs/PROTOCOL.md](docs/PROTOCOL.md).
Deployment notes are in [deploy/DEPLOY.md](deploy/DEPLOY.md).

## How it works

```
phone --TLS (SNI = <id>.akdbx.link)--> relay :8443 --WebSocket--> broker --> 127.0.0.1 HTTPS page
```

1. A broker registers (`POST https://relay.akdbx.link:8443/api/v1/register`)
   and gets a random name `<id>.akdbx.link` and a bearer secret. The control
   API shares port 8443: the relay terminates TLS for `relay.akdbx.link`
   itself, with its own certificate, and passes every other name through.
2. The broker makes its own key and sends only a CSR. The relay gets a Let's
   Encrypt certificate for that one name with the DNS-01 challenge, through
   the Cloudflare API, and returns the certificate chain.
3. The broker keeps a control WebSocket open to the relay.
4. A phone connects to `https://<id>.akdbx.link:8443`. The relay reads the
   server name from the TLS ClientHello (plain text) without terminating TLS,
   asks the broker for a stream, and splices the raw bytes both ways. TLS
   ends in the broker, with the broker's key.

## Security model

- **The relay cannot decrypt.** It never has a broker's private key. It sees
  the server name, connection times and sizes, and TLS ciphertext.
- **No third party in the control path.** Brokers reach the control API at
  `https://relay.akdbx.link:8443`, a DNS-only name. TLS ends in the relay,
  with a key that only the relay holds, so no proxy or CDN sees the bearer
  secrets that authorize certificate requests and the control channel.
  Caddy and Cloudflare serve only the static landing page at `akdbx.link`.
- **The trust point is DNS.** The relay operator controls the `akdbx.link`
  zone, so a dishonest or compromised relay could get a second certificate
  for a broker's name and intercept connections. Every publicly trusted
  certificate appears in Certificate Transparency logs, so this cannot stay
  hidden: a broker can check the logs for certificates it did not request
  (the akdbx broker can report them in `akdbx relay status`). Use a private proxy (option
  2 above) if this trust point is not acceptable.
- **Names cannot be chosen.** Names are 12 random characters from
  `[a-z2-7]`, so nobody can register a look-alike such as `paypal.akdbx.link`.
  Short and reserved labels (`www`, `api`, `relay`, `mail`) are refused.
- **A broker can get certificates only for its own name.** The CSR must hold
  exactly one DNS name, equal to the broker's name, no IP addresses, and an
  ECDSA P-256 or RSA 2048+ key.
- **Secrets are stored only as SHA-256 hashes.** The secret is returned once,
  at registration.
- **The broker still checks everything.** akdbx trusts no header from the
  relay and keeps its token, Host/Origin checks and three-attempt link block.
- **Nothing sensitive is kept.** The relay does not log or store relayed
  bytes, secrets, CSRs or client IP addresses. Client IPs (the TCP peer
  addresses; no forwarded-address header is trusted) exist only in memory,
  for rate limits. The SQLite state holds broker ids, secret hashes, the
  times of issued certificates, and cleanup markers for ACME TXT records.
- **Limits:** per-IP connection rate on :8443, per-IP open handshakes,
  streams and control connections, per-IP registrations per day, per-broker
  and global stream caps, ClientHello size, record-count and time limits,
  WebSocket message and fragment limits, a short wait for a broker's first
  bytes and an idle timeout, one deadline per certificate request, a weekly
  certificate budget, and a per-broker weekly certificate cap.

## Configuration

The relay reads `AKDBX_RELAY_*` environment variables, usually from
`/etc/akdbx-relay/relay.env` (mode 0600, see
[deploy/relay.env.example](deploy/relay.env.example)). `akdbx-relay
--env-file FILE` reads a file directly; variables already set in the
environment take precedence. Never commit a filled-in file.

| Variable | Default | Meaning |
| --- | --- | --- |
| `AKDBX_RELAY_CLOUDFLARE_API_TOKEN` | (none) | Cloudflare token with DNS edit on the relay zone only. Without it, certificate requests get `503 issuance_paused`. |
| `AKDBX_RELAY_CLOUDFLARE_ZONE_ID` | (none) | Id of the relay zone. |
| `AKDBX_RELAY_CLOUDFLARE_API` | `https://api.cloudflare.com/client/v4` | Cloudflare API base URL (tests use a fake). |
| `AKDBX_RELAY_ACME_DIRECTORY` | `production` | `production` (Let's Encrypt), `staging` (Let's Encrypt staging), or any ACME directory URL. |
| `AKDBX_RELAY_ACME_ACCOUNT_KEY_FILE` | `/var/lib/akdbx-relay/acme-account.pem` | ACME account key (RSA). Created with mode 0600 if missing. |
| `AKDBX_RELAY_ACME_EMAIL` | (none) | Optional ACME account contact. |
| `AKDBX_RELAY_ACME_CA_BUNDLE` | (none) | CA bundle for an ACME test server with a private CA. |
| `AKDBX_RELAY_ACME_TIMEOUT` | `60` | Seconds to wait for validation and finalization (also limited by the certificate deadline). |
| `AKDBX_RELAY_DNS_PROPAGATION_SECONDS` | `10` | Wait after creating the TXT record, before answering the challenge. |
| `AKDBX_RELAY_CERTIFICATE_DEADLINE` | `90` | Seconds for a whole certificate request: queue wait plus ACME order. Brokers should wait longer than this. |
| `AKDBX_RELAY_DOMAIN` | `akdbx.link` | Relay domain. Broker names are `<id>.<domain>`. |
| `AKDBX_RELAY_PUBLIC_HOSTS` | `0.0.0.0,::` | Comma-separated addresses for the public listener. |
| `AKDBX_RELAY_PUBLIC_PORT` | `8443` | Public listener port. |
| `AKDBX_RELAY_ADVERTISED_PORT` | public port | `public_port` returned at registration. |
| `AKDBX_RELAY_CONTROL_HOSTNAME` | `relay.<domain>` | SNI name for which the relay terminates TLS and serves the control API on the public port. Must be DNS only. |
| `AKDBX_RELAY_CONTROL_CERT_FILE` | (none) | Operator-supplied certificate chain for the control host name. Without it, the relay gets and renews its own certificate through ACME and keeps `control-chain.pem` and `control-key.pem` (0600) next to the state file. |
| `AKDBX_RELAY_CONTROL_KEY_FILE` | (none) | Private key for `AKDBX_RELAY_CONTROL_CERT_FILE` (set both or neither). |
| `AKDBX_RELAY_HEALTH_HOST` | `127.0.0.1` | Loopback address of the plain-HTTP health port (`GET /api/v1/health` only). Empty disables it. |
| `AKDBX_RELAY_HEALTH_PORT` | `8771` | Health port. |
| `AKDBX_RELAY_STATE_PATH` | `/var/lib/akdbx-relay/relay.sqlite3` | SQLite state file. Its directory is the state directory. |
| `AKDBX_RELAY_CERT_BUDGET` | `40` | First-time certificates per rolling 7 days (plus registrations from the last 24 h that have no certificate yet) at which new registrations pause. |
| `AKDBX_RELAY_CERT_HARD_LIMIT` | `48` | First-time certificates per rolling 7 days at which first-time issuance pauses. Renewals are not limited by it. |
| `AKDBX_RELAY_CERTS_PER_BROKER_WEEK` | `5` | Certificates per broker per rolling 7 days. |
| `AKDBX_RELAY_MAX_CONCURRENT_ISSUANCE` | `2` | ACME orders in progress at once. |
| `AKDBX_RELAY_REGISTRATIONS_PER_IP_DAY` | `5` | Registrations per client IP (IPv6: per /64) per 24 h. |
| `AKDBX_RELAY_MAX_STREAMS_PER_BROKER` | `64` | Concurrent streams per broker. |
| `AKDBX_RELAY_MAX_STREAMS_TOTAL` | `2048` | Concurrent streams in total. |
| `AKDBX_RELAY_MAX_PENDING_HANDSHAKES` | `1024` | Public connections still sending their ClientHello. |
| `AKDBX_RELAY_MAX_HANDSHAKES_PER_IP` | `8` | Of those, per IP (IPv6: per /64). |
| `AKDBX_RELAY_MAX_STREAMS_PER_IP` | `16` | Concurrent phone-side streams per IP, held for the connection's life. |
| `AKDBX_RELAY_MAX_CONTROL_CONNECTIONS` | `4096` | Concurrent control API connections (control channels and stream WebSockets). |
| `AKDBX_RELAY_MAX_CONTROL_CONNECTIONS_PER_IP` | `96` | Of those, per IP. |
| `AKDBX_RELAY_CONN_RATE_PER_IP` | `10` | New connections to broker names on the public port (phones and browsers) per second per IP (IPv6: per /64). |
| `AKDBX_RELAY_CONN_BURST_PER_IP` | `20` | Burst allowance for the connection rate. |
| `AKDBX_RELAY_CONTROL_CONN_RATE_PER_IP` | `20` | New connections to the control host name (brokers' control and stream connections) per second per IP, in a separate bucket. |
| `AKDBX_RELAY_CONTROL_CONN_BURST_PER_IP` | `96` | Burst allowance for the control connection rate. Keep it above `AKDBX_RELAY_MAX_STREAMS_PER_BROKER`, so a broker can open all its streams at once. |
| `AKDBX_RELAY_CLIENT_HELLO_TIMEOUT` | `5` | Seconds to receive the ClientHello. |
| `AKDBX_RELAY_CLIENT_HELLO_MAX_BYTES` | `16384` | Largest ClientHello buffered. |
| `AKDBX_RELAY_STREAM_OPEN_TIMEOUT` | `10` | Seconds to announce a stream on the control channel and for the broker to open it. |
| `AKDBX_RELAY_STREAM_FIRST_BYTE_TIMEOUT` | `10` | Seconds for the broker's first bytes on a new stream. |
| `AKDBX_RELAY_STREAM_IDLE_TIMEOUT` | `300` | Seconds without data before a stream closes. |
| `AKDBX_RELAY_CONTROL_PING_INTERVAL` | `30` | Seconds between control `ping` messages. |
| `AKDBX_RELAY_CONTROL_PONG_TIMEOUT` | `60` | Seconds without `pong` before the control channel closes. |
| `AKDBX_RELAY_WS_PING_INTERVAL` | `30` | Seconds between WebSocket ping frames on idle streams (keeps NATs from closing them). |
| `AKDBX_RELAY_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. |

## Running locally

Python 3.11 or newer. Use a virtual environment outside the checkout:

```sh
python3 -m venv ~/.venvs/akdbx-relay
~/.venvs/akdbx-relay/bin/pip install -e '.[test]'
~/.venvs/akdbx-relay/bin/pytest
```

A local relay without certificate issuance, with a self-signed control
certificate:

```sh
mkdir -p /tmp/relay && cd /tmp/relay
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
  -subj /CN=relay.akdbx.link -addext subjectAltName=DNS:relay.akdbx.link \
  -keyout control-key.pem -out control-chain.pem
AKDBX_RELAY_STATE_PATH=/tmp/relay/relay.sqlite3 AKDBX_RELAY_PUBLIC_HOSTS=127.0.0.1 \
  AKDBX_RELAY_CONTROL_CERT_FILE=/tmp/relay/control-chain.pem \
  AKDBX_RELAY_CONTROL_KEY_FILE=/tmp/relay/control-key.pem \
  ~/.venvs/akdbx-relay/bin/akdbx-relay
curl -s http://127.0.0.1:8771/api/v1/health
curl -s --cacert /tmp/relay/control-chain.pem \
  --resolve relay.akdbx.link:8443:127.0.0.1 https://relay.akdbx.link:8443/api/v1/health
```

The tests run without network access: a fake ACME server and a fake
Cloudflare API stand in for Let's Encrypt and Cloudflare, and
`akdbx_relay/testclient.py` is a small reference broker client that
registers, keeps the control WebSocket open and splices streams to a local
TLS server. The tests reach the control API over TLS on the public port with
SNI `relay.akdbx.link`, using a test CA.
