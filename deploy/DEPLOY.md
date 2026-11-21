# Deploying the akdbx relay

This is the plan for one Linux host with systemd, Caddy and a Cloudflare zone
for `akdbx.link`. Nothing in this repository changes a live host by itself.

The relay serves everything secret-bearing on its own port 8443: broker
pages (passed through, TLS ends in the broker) and the control API at
`https://relay.akdbx.link:8443` (TLS ends in the relay). Caddy and Cloudflare
serve only the static landing page at `https://akdbx.link/`. No bearer
secret passes through Cloudflare or Caddy.

## 1. Cloudflare

1. DNS records in the `akdbx.link` zone:

   | Name | Type | Proxy | Value |
   | --- | --- | --- | --- |
   | `akdbx.link` | A (and AAAA if the host has IPv6) | proxied | host address (landing page only) |
   | `*.akdbx.link` | A (and AAAA) | **DNS only** | host address |

   The wildcard must stay DNS only. It covers the broker names and the
   control host name `relay.akdbx.link`. If Cloudflare proxied it,
   Cloudflare would terminate TLS for those names: it could read broker pages
   and every broker's bearer secret, and the relay's design would fail. Do
   not add a separate proxied record for `relay.akdbx.link`.
2. API token: My Profile > API Tokens > Create Token > "Edit zone DNS"
   template, with Zone Resources limited to `akdbx.link`. The relay needs
   only DNS edit on this one zone. It uses the token for DNS-01 TXT records
   for broker certificates and for its own `relay.akdbx.link` certificate.
3. Copy the zone id from the zone's overview page.

## 2. Firewall

Open `8443/tcp` to everyone (IPv4 and IPv6). Leave ports 80/443 as they are
(Cloudflare only). The relay trusts no forwarded-address header; its rate
limits use the TCP peer address of the direct connection to 8443. The
health port (`127.0.0.1:8771`) is loopback only; do not expose or proxy it.

## 3. Install

From a checkout of this repository on the host:

```sh
sudo deploy/setup.sh
sudoedit /etc/akdbx-relay/relay.env    # token, zone id; keep ACME_DIRECTORY=staging first
sudo deploy/setup.sh --start
curl -s http://127.0.0.1:8771/api/v1/health
```

`setup.sh` creates the `akdbx-relay` system user, a virtual environment in
`/opt/akdbx-relay/venv`, `/etc/akdbx-relay/relay.env` (0600, root, only if it
does not exist), the landing page in `/var/www/akdbx.link`, and the systemd
unit. It stops if `relay.env` still has a setting that this version refuses
(`AKDBX_RELAY_CONTROL_HOST`, `AKDBX_RELAY_CONTROL_PORT`,
`AKDBX_RELAY_TRUSTED_PROXY_IPS`).

The relay creates its files in `/var/lib/akdbx-relay` (0700) at first use:
the SQLite state, the ACME account key `acme-account.pem`, and its control
TLS key and certificate `control-key.pem` and `control-chain.pem` (all
0600). At start it orders the `relay.akdbx.link` certificate if it has none,
and it renews it when a third of the lifetime is left; until the first
certificate is installed, connections to the control host name are closed
(`journalctl -u akdbx-relay` shows progress). To use a certificate from
elsewhere instead, set `AKDBX_RELAY_CONTROL_CERT_FILE` and
`AKDBX_RELAY_CONTROL_KEY_FILE`; the relay reloads them when they change.

Check, from any computer:

```sh
curl -s https://relay.akdbx.link:8443/api/v1/health
```

With the staging directory the certificate is from the untrusted staging CA:
add `-k` for this check only.

## 4. Caddy (landing page only)

1. Back up the Caddyfile.
2. Append `deploy/Caddyfile.akdbx-relay` and set its `bind` line like the
   other site blocks on the host. If an earlier version of this block is
   there (with `handle /api/*` and `reverse_proxy 127.0.0.1:8771`), replace
   it: the API must not be reachable through Caddy.
3. `sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile`,
   then `sudo systemctl reload caddy`.
4. If Caddy needs a first certificate for `akdbx.link` while the record is
   proxied and 80/443 are Cloudflare only, follow the host's normal procedure
   for a new site (for example, DNS only until Caddy has the certificate).

Check: `https://akdbx.link/` shows the landing page, and
`https://akdbx.link/api/v1/health` returns 404.

## 5. Smoke test (staging certificates)

On any computer. Staging certificates come from Let's Encrypt's untrusted
staging CA, so give the test client the staging root certificates (see
Let's Encrypt's "Staging Environment" page) in one PEM file:

```sh
python -m akdbx_relay.testclient --relay https://relay.akdbx.link:8443 \
  --ca-file ./staging-roots.pem --state ./relay-test.json demo
```

It registers, gets a certificate, and prints `https://<id>.akdbx.link:8443/`.
With staging, browsers warn about the untrusted staging CA; `curl -k` shows
the page. When it works, set `AKDBX_RELAY_ACME_DIRECTORY=production`, delete
`/var/lib/akdbx-relay/control-chain.pem` (so the relay orders a production
control certificate), restart (`sudo systemctl restart akdbx-relay`), and
test again with a new state file. Each first-time certificate counts against
the weekly budget.

## Operations

- Logs: `journalctl -u akdbx-relay`. They contain no client IPs, secrets,
  CSRs or relayed bytes.
- Update: `git pull` in the checkout, then `sudo deploy/setup.sh --start`.
- Backup: the database runs in WAL mode, so copying `relay.sqlite3` while
  the relay runs can miss committed records (they may still be in
  `relay.sqlite3-wal`). Use SQLite's online backup instead:

  ```sh
  sudo -u akdbx-relay sqlite3 /var/lib/akdbx-relay/relay.sqlite3 \
    ".backup '/var/lib/akdbx-relay/backup.sqlite3'"
  ```

  (without the `sqlite3` tool: `sudo -u akdbx-relay python3 -c "import
  sqlite3; sqlite3.connect('/var/lib/akdbx-relay/relay.sqlite3').backup(sqlite3.connect('/var/lib/akdbx-relay/backup.sqlite3'))"`;
  or stop the service, copy `relay.sqlite3` together with any `-wal` and
  `-shm` files, and start it again). Back up, with the same care as the
  token, these 0600 files from `/var/lib/akdbx-relay`: the database backup
  (broker list, secret hashes, certificate log), `acme-account.pem` (the
  ACME account key), and `control-key.pem` with `control-chain.pem` (the
  relay's own control TLS key and certificate). Without the database, every
  broker must register again. Without the control key, the relay orders a
  new control certificate at start, which counts once against the weekly
  certificate budget.
- Certificate requests normally take 15 to 40 seconds
  (`AKDBX_RELAY_DNS_PROPAGATION_SECONDS` plus ACME validation). The relay
  answers each one within `AKDBX_RELAY_CERTIFICATE_DEADLINE` (default 90 s),
  which covers the wait for a free issuance slot and the ACME order; keep
  `AKDBX_RELAY_ACME_TIMEOUT` below it.
- Let's Encrypt limits: about 50 new certificates per registered domain each
  week. The relay pauses new registrations at `AKDBX_RELAY_CERT_BUDGET`
  (default 40). Renewals continue. To grow, request a higher limit with
  Let's Encrypt's rate-limit form and consider the Public Suffix List entry
  described in [PROTOCOL.md](../docs/PROTOCOL.md).
- Run one relay per DNS zone: at start the relay removes relay-owned
  `_acme-challenge` TXT records that are older than twice the certificate
  deadline.
