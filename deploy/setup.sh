#!/usr/bin/env bash
# Install or update the akdbx relay on a systemd host. Safe to run again.
#
#   sudo deploy/setup.sh            install or update; do not start
#   sudo deploy/setup.sh --start    also enable and (re)start the service
#
# It does not change Caddy, DNS or the firewall. See deploy/DEPLOY.md.
# The control API is served by the relay itself on port 8443 for
# relay.akdbx.link (DNS only); Caddy serves only the landing page.
set -euo pipefail

START=0
for arg in "$@"; do
	case "$arg" in
	--start) START=1 ;;
	-h | --help)
		sed -n '2,8p' "$0"
		exit 0
		;;
	*)
		echo "unknown argument: $arg" >&2
		exit 2
		;;
	esac
done

if [[ $(id -u) -ne 0 ]]; then
	echo "run as root (sudo)" >&2
	exit 1
fi

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PREFIX=/opt/akdbx-relay
ETC=/etc/akdbx-relay
WWW=/var/www/akdbx.link
UNIT=/etc/systemd/system/akdbx-relay.service
PYTHON=${PYTHON:-python3}

"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || {
	echo "Python 3.11 or newer is required" >&2
	exit 1
}

# 1. Service account (no login shell, no home files).
if ! id akdbx-relay >/dev/null 2>&1; then
	useradd --system --user-group --home-dir /var/lib/akdbx-relay --no-create-home \
		--shell /usr/sbin/nologin akdbx-relay
	echo "created system user akdbx-relay"
fi

# 2. Program in its own virtual environment, owned by root.
install -d -m 0755 "$PREFIX"
if [[ ! -x $PREFIX/venv/bin/python ]]; then
	"$PYTHON" -m venv "$PREFIX/venv"
fi
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet --upgrade "$SRC"
echo "installed $("$PREFIX/venv/bin/akdbx-relay" --version)"

# 3. Settings: create from the example once; never overwrite.
install -d -m 0700 -o root -g root "$ETC"
if [[ ! -e $ETC/relay.env ]]; then
	install -m 0600 -o root -g root "$SRC/deploy/relay.env.example" "$ETC/relay.env"
	echo "created $ETC/relay.env: set the Cloudflare token and zone id"
else
	chmod 0600 "$ETC/relay.env"
	chown root:root "$ETC/relay.env"
fi
# Settings from drafts that served the API behind Caddy and Cloudflare. The
# relay refuses them; say what to do instead of failing later.
for old in AKDBX_RELAY_CONTROL_HOST AKDBX_RELAY_CONTROL_PORT AKDBX_RELAY_TRUSTED_PROXY_IPS; do
	if grep -qE "^[[:space:]]*${old}=" "$ETC/relay.env"; then
		echo "$ETC/relay.env sets $old, which this version no longer supports." >&2
		echo "Remove it (see deploy/relay.env.example: AKDBX_RELAY_HEALTH_HOST/PORT, CONTROL_HOSTNAME)." >&2
		exit 1
	fi
done

# 4. State directory (systemd also creates it through StateDirectory=). It
#    holds the SQLite state, the ACME account key and the relay's own control
#    TLS key and certificate, all 0600.
install -d -m 0700 -o akdbx-relay -g akdbx-relay /var/lib/akdbx-relay

# 5. Landing page for Caddy (the only thing Caddy serves for akdbx.link).
install -d -m 0755 "$WWW"
install -m 0644 "$SRC/deploy/www/index.html" "$WWW/index.html"

# 6. systemd unit.
if ! cmp -s "$SRC/deploy/akdbx-relay.service" "$UNIT"; then
	install -m 0644 "$SRC/deploy/akdbx-relay.service" "$UNIT"
	systemctl daemon-reload
	echo "installed $UNIT"
fi

"$PREFIX/venv/bin/akdbx-relay" --env-file "$ETC/relay.env" --check-config

if [[ $START -eq 1 ]]; then
	systemctl enable akdbx-relay.service
	systemctl restart akdbx-relay.service
	systemctl --no-pager --lines=5 status akdbx-relay.service || true
else
	echo "not started; run with --start, or: systemctl enable --now akdbx-relay"
fi
