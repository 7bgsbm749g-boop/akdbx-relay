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
Status: under construction.
