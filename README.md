> **v0.2.0 — feature:** Full QUIC & HTTP/3 (UDP 443) routing support via TPROXY (`:14400`),
> QUIC Initial header decryption & SNI classification (v1 & v2, RFC 9001/9369), flow table with
> 5-tuple and CID tracking, and length-prefixed datagram relay over the mTLS yamux tunnel with
> fail-open fallback (Jalur A) so mobile apps never freeze.
>
> **v0.1.5 — bugfix:** (1) `internal/nftsetup` omitted `udp dport 53 redirect` from the `output`
> chain. Only incoming TUN traffic (`prerouting`) needs UDP 53 redirection; local processes
> (dnf, curl, system services) generate UDP 53 queries which failed reverse-NAT or were broken
> on host. (2) `cmd/rdns-client` now automatically executes `nftsetup.Unapply` immediately upon
> receiving a shutdown signal (and in `defer`), ensuring nftables redirect tables are cleanly removed
> when the service stops instead of stranding host DNS with dead listeners.
>
> **v0.1.4 — logging:** `internal/dnsintercept` added explicit debug logging for
> upstream DNS write failures, read timeouts, and client response errors.
>
> **v0.1.3 — bugfix:** `internal/markdial` set `SO_MARK` on sockets *after* `DialContext`
> returned, meaning the initial TCP SYN packet had mark 0 and was caught by the
> client's own nftables redirect on reconnect (causing an infinite dial loop to localhost
> and `connect: cannot assign requested address`). Fixed by setting `SO_MARK` before
> `connect()` via `net.Dialer.Control`. Also added exit node endpoints to excluded IPs
> in nftables rules as defense-in-depth.
>
> **v0.1.2 — bugfix:** `internal/nftsetup` generated `type filter` chains for
> `output` and `prerouting`, which caused `Error: Could not process rule: Operation not supported`
> because `redirect` is a NAT operation and `prerouting` hook is not supported on
> `type filter` in netfilter. Updated `output` and `prerouting` chains to `type nat`
> with priority `-100` (`dstnat`).
>
> **v0.1.1 — bugfix:** `internal/nftsetup` generated `sk mark <mark> accept`,
> which is not valid nftables syntax (`sk` is not a keyword; the correct
> expression is `socket mark <mark> accept`, matching nftables' `socket`
> expression for the originating socket's `SO_MARK`). This caused
> `rdns-client` to fail applying its nftables redirects with
> `syntax error, unexpected mark` on any modern `nft` (tested against
> nftables v1.1.5). Fixed in `internal/nftsetup/nftsetup.go`; the generator
> tests in `internal/nftsetup/nftsetup_test.go` were updated to match.

# rdns — Domain-Based Split DNS & Traffic Router

`rdns` gives a VPN **domain-based split routing**: only domains you list are
resolved *and* egressed through a chosen country's node; every other domain
goes straight out from the node the client is actually on. It works at the
network layer (transparent intercept), so it applies to **all** your existing
VPN protocols (SSH-WS, VLESS/VMESS/Trojan via Xray, OpenVPN) with **zero
changes on the end-user device**.

This solves the classic geoblock problem: a client connected to a Singapore
node can't reach services geo-blocked to Malaysia, because neither its DNS
resolution nor its egress IP is Malaysian. `rdns` routes just those domains
through a Malaysian exit node — both the DNS answer and the traffic.

See `rdns-prd.md` for the full product requirements and design rationale.

> **Setting up for the first time?**
> - **[Panduan Cepat Setup Otomatis (Server & Client)](#quick-start-setup-otomatis-server--client)** (Direkomendasikan)
> - **[PANDUAN-CERTIFICATE.md](PANDUAN-CERTIFICATE.md)**: Panduan sertifikat mTLS praktis untuk pemula.
> - **[SETUP.md](SETUP.md)**: Panduan arsitektur manual lengkap langkah-demi-langkah.
> - **[ROADMAP.md](ROADMAP.md)**: Desain arsitektur Residential & Mobile SIM Egress (STB Armbian & Android Phone).

---

## Quick Start (Setup Otomatis Server & Client)

### 1. Setup Server / Exit Node (VPS Malaysia / Indonesia)
Di VPS Exit Node (tujuan egress), jalankan installer otomatis:
```bash
# Clone atau salin repository rdns, lalu jalankan:
bash install-server.sh
```

*(Atau jalankan dengan parameter satu baris, sangat cocok untuk **NatVPS** dengan port custom):*
```bash
bash install-server.sh --ip 103.150.120.10 --tunnel-port 24443 --dns-port 10053 --profile my
```

Skrip ini akan secara otomatis:
1. Memasang binary `rdns-server` dan `rdns-certs` ke `/usr/local/bin/`.
2. Men-generate Root CA dan sertifikat Server mTLS ECDSA.
3. Mengonfigurasi `/etc/rdns/server.yaml`.
4. Mengaktifkan daemon service (mendukung systemd di Ubuntu/Debian/Rocky/CentOS dan OpenRC di Alpine Linux).
5. **Mencetak Token Pairing `rdns://...`** di terminal.

> **Tips:** Untuk membuat token pairing tambahan di kemudian hari:
> ```bash
> rdns-server-cli mint <nama_profil> [masa_aktif_hari]
> ```

---

### 2. Setup Client / Decision Node (VPS Autoscript Singapore)
Di VPS Singapore (tempat user VPN terhubung):

#### Cara A: Lewat Menu TUI Autoscript (Paling Mudah)
1. Buka menu autoscript: `menu`
2. Pilih Menu **SmartDNS / RDNS**.
3. Pilih **`[1] Pair Exit Node Baru`** ➔ Paste token `rdns://...` dari Server tadi.
4. Pilih **`[4] Pasang Kategori Preset Rules`** ➔ Pilih **`[2] Malaysia Region`** (untuk seluruh domain `.my`) dan **`[1] Streaming & OTT Populer`**.

#### Cara B: Lewat 1-Baris Perintah CLI
```bash
# 1. Pairing token
rdns-manager pair "rdns://eyJ2ZXJzaW9uIjogMSwgInByb2ZpbGVfbmFtZSI..."

# 2. Pasang preset yang diinginkan
rdns-manager load-preset my malaysia
rdns-manager load-preset my streaming
```

#### Cara C: Uji Status Domain
```bash
rdns-manager test-domain shopee.com.my
rdns-manager test-domain netflix.com
```

---

### 3. Hemat Bandwidth Maksimal (`cdn_direct: true`)
Pada konfigurasi default `/etc/rdns/client.yaml`, opsi `cdn_direct: true` aktif secara otomatis:
- **Jalur Auth & Geo-Unblock:** DNS query dan metadata handshake TLS/QUIC (`netflix.com`, `hotstar.com`, `astro.com.my`, `sooka.my`, dsb.) dialirkan lewat tunnel mTLS ke Exit Node sehingga terdeteksi berada di Malaysia.
- **Jalur Video Stream Berat:** Chunk video streaming berukuran besar (`nflxvideo.net`, `aiv-cdn.net`, `googlevideo.com`, `hotstar-cdn.net`, `byteoversea.com`, dsb.) dialirkan secara **direct** ke CDN edge terdekat, menghemat bandwidth exit node hingga **>99%**.

---

---

## Table of contents

- [How it works](#how-it-works)
- [Roles](#roles)
- [Security model](#security-model-two-layers)
- [Fail-closed](#fail-closed)
- [Build](#build)
- [Setup (full walkthrough)](#setup-full-walkthrough)
  - [Prerequisites](#prerequisites)
  - [What goes where](#what-goes-where)
  - [Step 0 — Mint the internal PKI (offline)](#step-0--mint-the-internal-pki-once-offline)
  - [Step 1 — Exit node (rdns-server, Alpine)](#step-1--exit-node-rdns-server-alpine)
  - [Step 2 — Decision node (rdns-client, Rocky + autoscript)](#step-2--decision-node-rdns-client-rocky-with-autoscript)
  - [Step 3 — End-to-end verification](#step-3--end-to-end-verification)
- [Debugging (--debug simple / full)](#debugging---debug-simple--full)
- [Troubleshooting](#troubleshooting)
- [Configuration reference](#configuration-reference)
- [Project layout](#project-layout)
- [Limitations](#notes--known-limitations-v01-v03)

## How it works

```
Client VPN (SSH-WS / VLESS / OpenVPN)
        │
        ▼
┌──────────────────────────────────┐
│  VPS SG/ID — rdns-client         │  (decision node, Rocky Linux)
│  nftables redirects & TPROXY:    │
│    OUTPUT + PREROUTING:          │
│      udp/53        → local :5353 │
│      tcp/443,80    → local :14300│
│      udp/443 (QUIC)→ local :14400│  (TPROXY)
│    INPUT: accept only redirected │
│      (conntrack/meta mark) pkts  │
│  1) DNS interceptor: QNAME → rule │
│  2) SNI/HTTP interceptor (TCP):  │
│     SNI / Host → rule            │
│  3) QUIC interceptor (UDP):      │
│     Initial decrypt / SNI → rule │
│  Match?                          │
│    no  → resolve/dial locally    │
│          (Jalur A: pass-through) │
│    yes → over the mTLS+yamux     │
│          tunnel to that profile  │
│          (Jalur B: framed relay) │
└───────────────┬──────────────────┘
                │  tcp/443 (mTLS, yamux, persistent — TCP stream + UDP datagrams)
                │  udp/53  (forwarded DNS, IP-ACL)
                ▼
┌──────────────────────────────────┐
│  VPS MY — rdns-server            │  (exit node, Alpine)
│  ONLY 3 public ports:            │
│    udp/53  ACL DNS answer svc    │
│    tcp/443 mTLS yamux tunnel     │
│    tcp/80  ACME HTTP-01 only     │
│  resolve via local MY resolver,  │
│  relay with egress from MY IP    │
└──────────────────────────────────┘
```

> **Why OUTPUT *and* PREROUTING** (an extension beyond the PRD draft, which
> said PREROUTING only): on a VPN node the end-user traffic is re-originated
> by local processes — dropbear/ssh-ws and xray *dial out* on behalf of
> SSH-WS/VLESS/Trojan clients (→ `OUTPUT`), while OpenVPN traffic arrives
> from the TUN interface (→ `PREROUTING`). Both chains carry the same
> redirects. Each redirect stamps a conntrack mark, and an `INPUT` chain
> (priority -150, before firewalld's filter chain) accepts exactly those
> marks — this is what lets the redirected packets reach the local
> interceptors on an autoscript box, where firewalld runs a strict
> allowlist that does **not** include the interceptor ports (5353/14300)
> and must not. See `internal/nftsetup` for the full rationale.

**Key principle:** `rdns-server` never knows what a domain rule is. It does
two generic jobs — answer DNS, relay traffic — for anyone who passes ACL +
mTLS. All the domain-matching "brains" live in `rdns-client`.

## Roles

| Binary | Runs on | Job |
|--------|---------|-----|
| `rdns-client` | decision VPS (Rocky, co-located with autoscript) | intercept, match rules, decide tunnel-vs-direct, keep mTLS+yamux sessions |
| `rdns-server` | exit VPS (Alpine) | ACL-gated DNS answer + mTLS yamux relay with local egress |
| `rdns-certs` | anywhere (offline) | mint the internal CA, per-node client certs, exit server cert |

## Security model (two layers)

- **tcp/443 (relay) — mTLS.** Every `rdns-client` holds a client cert signed
  by an internal CA (one-time, per node). The server only accepts valid
  client certs (`RequireAndVerifyClientCert`) and enforces a revocation list
  (by cert SPKI digest) at the application layer after the handshake.
- **udp/53 (DNS forward) — IP ACL + rate limit.** UDP has no handshake, so it
  is spoofable (the classic DNS-amplification vector). Mitigated by an
  allowlist of decision-node IPs **plus** a per-IP token-bucket rate limit,
  enforced in the app and mirrored in nftables. Non-whitelisted/rate-limited
  queries are dropped and counted (the §15 "reject count" metric).
- **tcp/80 — minimal.** Serves only `/.well-known/acme-challenge/*`; every
  other path is 404. No relay logic at all.

The exit node's public surface is exactly three ports.

## Fail-closed

If a matched domain's profile tunnel is down, that traffic is **dropped, not
leaked** to the origin node — so a dead exit can't silently send a "must go
through MY" domain out from SG. Unmatched traffic is unaffected (it never
depends on a tunnel).

## Build

Requires Go 1.25+. Both binaries are `CGO_ENABLED=0` static — the same build
runs on Alpine (musl) and Rocky (glibc).

```bash
make build       # → dist/rdns-{client,server,certs}-linux-amd64
make test        # go vet + go test ./...
```

Cross-build (what CI does) for a specific target:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 CC=musl-gcc \
  go build -trimpath -ldflags "-s -w -X main.version=v0.1.0" \
  -o rdns-server ./cmd/rdns-server          # Alpine target
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -X main.version=v0.1.0" \
  -o rdns-client ./cmd/rdns-client          # Rocky target
```

## Docker

A single multi-stage image ships all three binaries; compose services pick
which to run. The runtime layer is Alpine (needs `nft` on the client side and
CA roots for Let's Encrypt on the server side).

```bash
make docker         # build rdns:local for the current arch
make docker-multi   # buildx multi-arch (amd64 + arm64)
make smoke          # local end-to-end test (exit + client + assertions)
```

**Production** (client and server on different VPSes) uses
[`docker-compose.yml`](docker-compose.yml) with profiles:

```bash
# exit node:
docker compose --profile server up -d --build
# decision node:
docker compose --profile client up -d --build
# one-shot PKI helper (writes ./pki):
docker compose run --rm certs ca -name rdns-ca -out /pki
```

Configs live in [`etc/`](etc/) (mounted read-only); PKI in `./pki` (gitignored).
Both services run `network_mode: host` — required because nftables is
host-kernel state (client) and the udp/53 ACL needs the real source IP
(server). See the compose file header for the full rationale, and
[SETUP.md](SETUP.md) for the non-Docker path.

**Local test** (one machine, no VPS):
[`docker-compose.test.yml`](docker-compose.test.yml) mints a throwaway PKI,
starts an exit + client on a bridge network, and runs a smoke test that
verifies DNS-split and tunnel-relay end to end (`make smoke`).

---

## Setup (full walkthrough)

> For the detailed, copy-pasteable version — including **Cloudflare
> pointing** (why the record must be *DNS-only*), **what happens after
> pointing**, real example values, and **dynamic / residential IP** handling —
> see **[SETUP.md](SETUP.md)**. The section below is the condensed overview.

This is the complete, ordered procedure. Do the steps in sequence — the PKI
(Step 0) must exist before either node can start, and the **exit node (Step
1) must be running before the decision node (Step 2)** can connect to it.

### Prerequisites

| You need | Why |
|----------|-----|
| **2+ VPSes** | one decision node per origin country (e.g. SG), one exit node per target country (e.g. MY). A single box can be both, but keep roles separate for clean egress. |
| **Root on every VPS** | `rdns-client` needs `CAP_NET_ADMIN` (nftables) + `SO_MARK`; `rdns-server` binds udp/53 + tcp/443/80. |
| **A domain you control** | for the exit node's Let's Encrypt cert (e.g. `exit-my.example.com` → A record to the MY VPS IP). Optional if you use a static cert. |
| **autoscript already installed** on the decision node | `rdns-client` is designed to coexist with it (see [Step 2](#step-2--decision-node-rdns-client-rocky-with-autoscript)). |
| **Go 1.25+** on your build machine | to compile the three binaries (or download prebuilt from CI). |

> **This PC is dev-only.** Build the Linux binaries here, then **copy the
> changed files to each VPS by hand** (the workflow you already use). Nothing
> here assumes this machine is a deploy target.

### What goes where

```
OFFLINE machine (your laptop / build box)
   └─ rdns-certs  →  ca.crt, ca.key, node-sg.{crt,key}, exit-my.{crt,key}

DECISION node  (Rocky, has autoscript)          EXIT node  (Alpine, clean)
   rdns-client  ←── ca.crt, node-sg.{crt,key}      rdns-server ←── ca.crt, exit-my.{crt,key}
   client.yaml, rules.json                          server.yaml
   (applies its own nftables)                       (open udp/53, tcp/443, tcp/80)
        │                                                  ▲
        └────────────── mTLS tunnel (tcp/443) ─────────────┘
        └────────────── DNS forward (udp/53)  ─────────────┘
```

### Step 0 — Mint the internal PKI (once, offline)

Run `rdns-certs` on a machine that is **not** a VPS (your laptop). Keep
`ca.key` secret and off the servers — it only signs new certs.

```bash
# 1. The internal CA (one per deployment).
./rdns-certs ca -name "rdns-ca" -out ./pki
#   → ./pki/ca.crt  ./pki/ca.key

# 2. One client cert per DECISION node (name it after the node).
./rdns-certs client -ca ./pki/ca.crt -cakey ./pki/ca.key \
  -name node-sg -out ./pki/certs
./rdns-certs client -ca ./pki/ca.crt -cakey ./pki/ca.key \
  -name node-id -out ./pki/certs        # repeat per node

# 3. One server cert per EXIT node. Use BOTH -dns (the hostname) and -ip
#    (the VPS public IP) so the client can verify it by either.
./rdns-certs server -ca ./pki/ca.crt -cakey ./pki/ca.key \
  -name exit-my -dns exit-my.example.com -ip 203.0.113.20 -out ./pki/certs
```

Files produced (all `0600`):

```
pki/
  ca.crt  ca.key
  certs/
    node-sg.crt  node-sg.key
    node-id.crt  node-id.key
    exit-my.crt  exit-my.key
```

**Distribute:**
- `ca.crt` → **every** node (both roles verify against it).
- `node-<name>.{crt,key}` → that decision node.
- `exit-<name>.{crt,key}` → that exit node.
- `ca.key` → **nowhere** (stays offline).

### Step 1 — Exit node (`rdns-server`, Alpine)

The exit node is a clean box (no autoscript). It opens exactly three public
ports.

**1a. Install the binary + config.**

```bash
# On the Alpine VPS, as root:
mkdir -p /etc/rdns/certs /var/lib/rdns /var/log
install -m 0755 rdns-server /usr/local/bin/rdns-server
# copy from the offline PKI:
cp ca.crt            /etc/rdns/ca.crt
cp exit-my.crt       /etc/rdns/certs/exit-my.crt
cp exit-my.key       /etc/rdns/certs/exit-my.key
# copy the example config and edit it:
cp examples/server/server.example.yaml /etc/rdns/server.yaml
```

**1b. Edit `/etc/rdns/server.yaml`.** The two things you **must** set:

```yaml
listen:
  dns:    "0.0.0.0:53"
  tunnel: "0.0.0.0:443"
  acme:   "0.0.0.0:80"

tls:
  # Pick ONE:
  domain: exit-my.example.com        # Let's Encrypt (needs DNS A record → this VPS)
  # cert_file: /etc/rdns/certs/exit-my.crt   # …or the static cert from Step 0
  # key_file:  /etc/rdns/certs/exit-my.key
  client_cas: /etc/rdns/ca.crt       # REQUIRED — the internal CA that signs node certs

acl:
  allowed:                           # the decision nodes' PUBLIC IPs (udp/53 gate)
    - 203.0.113.10                   #   ← SG node
    - 198.51.100.20                  #   ← ID node
  rate_per_sec: 50
  burst: 100

dns:
  upstreams: [system]                # answer using the box's local (MY) resolver
```

> **`tls.domain` vs static cert:** with `domain`, `rdns-server` gets a real
> Let's Encrypt cert via HTTP-01 on port 80 (auto-renewed, cached in
> `/var/lib/rdns/acme`) — the box then looks like an ordinary HTTPS server.
> With `cert_file`/`key_file`, it uses the internal-CA cert from Step 0
> (no public DNS needed, but the 443 cert is not CA-signed). Both still
> require a valid **client** cert (mTLS) to relay.

**1c. Open the three ports (Alpine firewall).** The exit node is clean, so
you open them yourself. With `nft` (Alpine's default):

```bash
rc-service nftables status >/dev/null 2>&1 || rc-update add nftables
cat >/etc/nftables.d/rdns.nft <<'EOF'
table inet rdns_in {
  chain input {
    type filter hook input priority 0; policy accept;
    udp dport 53  accept
    tcp dport { 443, 80 } accept
    ct state established,related accept
    iif lo accept
  }
}
EOF
# include it from /etc/nftables.conf, then:
rc-service nftables restart
```

(If the box has no firewall, skip this — but then the udp/53 ACL is your only
gate, so keep `acl.allowed` tight.)

**1d. Install + start the service.**

```bash
cp deploy/rdns-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now rdns-server
journalctl -u rdns-server -n 20      # expect: "rdns-server ready"
```

**1e. Confirm only 3 ports are open** (from another machine):

```bash
nmap -sT -p 53,80,443,22,8080 <exit-ip>   # 53/udp, 80, 443 open; everything else closed
```

### Step 2 — Decision node (`rdns-client`, Rocky + autoscript)

This box already runs autoscript. `rdns-client` is designed to coexist: it
uses its **own** nftables table (`rdns`), never touches firewalld, and
excludes the node's own IP + loopback so autoscript's VPN endpoints keep
working.

**2a. Install the binary + config + certs.**

```bash
# On the Rocky VPS (with autoscript), as root:
mkdir -p /etc/rdns/certs /var/log
install -m 0755 rdns-client /usr/local/bin/rdns-client
cp ca.crt        /etc/rdns/ca.crt
cp node-sg.crt   /etc/rdns/certs/node-sg.crt
cp node-sg.key   /etc/rdns/certs/node-sg.key
cp examples/client/client.example.yaml /etc/rdns/client.yaml
cp examples/client/rules.example.json  /etc/rdns/rules.json
```

**2b. Edit `/etc/rdns/client.yaml`.** The things you **must** set:

```yaml
listen:
  dns: "0.0.0.0:5353"
  sni: "0.0.0.0:14300"

rules: /etc/rdns/rules.json

tls:
  ca_file:   /etc/rdns/ca.crt
  cert_file: /etc/rdns/certs/node-sg.crt
  key_file:  /etc/rdns/certs/node-sg.key

profiles:
  - name: my
    server:      exit-my.example.com:443   # the exit node's tunnel endpoint
    server_name: exit-my.example.com       # must match the exit cert's name
    dns:         exit-my.example.com:53    # the exit node's udp/53

dns:
  default_upstream: "8.8.8.8:53"           # resolver for UNMATCHED domains.
                                           # autoscript sets /etc/resolv.conf to
                                           # 8.8.8.8/1.1.1.1, so match that.
                                           # (empty = auto-detect from resolv.conf)

# The node's OWN public IP(s). Traffic to these is NOT redirected, so
# autoscript's endpoints (VLESS/Trojan on 443, SSH 22/109/3303, OpenVPN 1194)
# are never hijacked. THIS IS THE MOST IMPORTANT FIELD — get it wrong and you
# break your own VPN.
local_ips:
  - 203.0.113.10                           # ← this VPS's public IP

tunnel_mark: 219750615                     # 0xd1920d7; must equal the nftables mark
```

**2c. Edit `/etc/rdns/rules.json`** — the domains to route per profile:

```json
{
  "my": ["maybank2u.com.my", "astro.com.my", "iflix.com"],
  "id": ["bri.co.id", "vidio.com"]
}
```

Matching is **suffix-based**: `bri.co.id` also matches `mobile.bri.co.id`.
Longest-suffix wins, so a specific rule overrides a broader one.

**2d. Install + start the service.**

```bash
cp deploy/rdns-client.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now rdns-client
journalctl -u rdns-client -n 20
```

Expected startup log (JSON, one line each):
```
"msg":"rdns-client starting"
"msg":"rules loaded"        "profiles":["id","my"] "domains":5
"msg":"tunnel manager started" "profiles":2
"msg":"nftables redirects applied" "dns":"0.0.0.0:5353" "sni":"0.0.0.0:14300" "mark":"0xd1920d7"
"msg":"dns interceptor listening"
"msg":"sni interceptor listening"
```

**2e. Reload rules without restart** (edit `rules.json`, then):

```bash
systemctl reload rdns-client        # sends SIGHUP; a bad file keeps old rules
```

### Step 3 — End-to-end verification

From a **client device** connected to the decision node's VPN (SG):

```bash
# 1. A LISTED domain → resolves via MY + egresses from MY IP.
dig +short bri.co.id                 # MY/CDN view
curl -s https://api.ipify.org        # (through bri.co.id's own page) → MY IP

# 2. An UNLISTED domain → unchanged, still SG.
curl -s https://www.cloudflare.com/cdn-cgi/trace | grep ip   # SG IP

# 3. Fail-closed check: stop the exit node, then hit a listed domain.
#    It should FAIL (dropped), NOT silently leak to SG.
```

On the **exit node**, watch the reject counters (should be 0 from your nodes):
```bash
journalctl -u rdns-server -f | grep '"msg":"stats"'
#   dns_drop_acl / dns_drop_rate  → 0 from whitelisted nodes; non-zero only from scanners
```

---

## Debugging: `--debug simple` / `--debug full`

Both binaries take `--debug` for live testing. It overrides the config's
`logging.level`.

```bash
rdns-client --debug simple     # app-level: one line per connection
rdns-client --debug full       # + wire-level: every stream, packet, byte count
rdns-server --debug full       # same on the exit node
```

| Mode | Shows | Use when |
|------|-------|----------|
| *(none)* | Info/Warn/Error only | normal operation |
| `simple` | + **Debug**: tunnel connect/close, rule reload, and the **decision** for each connection (`sni: tunnel` vs `sni: direct`, `dns: forward` vs `dns: local`) | "is it routing correctly?" |
| `full` | + **Trace**: yamux stream open/close, per-relay byte counts, every DNS packet (incl. drops), SNI/Host parse steps | "why does THIS connection misroute?" |

The distinction is real: `simple` emits one line per connection; `full` adds
the wire-level detail underneath. Example (`--debug simple`, a matched domain):

```json
{"level":"DEBUG","msg":"sni: tunnel","host":"bri.co.id","profile":"id","port":443}
{"level":"DEBUG","msg":"dns: forward","qname":"bri.co.id","profile":"id","to":"exit-id.example.com:53"}
```

The same connection under `--debug full` additionally shows:

```json
{"level":"DEBUG-8","msg":"sni: classified","host":"bri.co.id","head_bytes":1509,"peer":"10.9.0.2:52113"}
{"level":"DEBUG-8","msg":"tunnel: stream opened","dest":"bri.co.id:443"}
{"level":"DEBUG-8","msg":"dns: query","qname":"bri.co.id","bytes":27,"from":"10.9.0.2:40012","matched":true}
{"level":"DEBUG-8","msg":"sni: relay done","host":"bri.co.id","to_target":4096,"to_client":18234}
```

To debug a systemd-run instance, temporarily add `--debug full` to the unit's
`ExecStart` (or run the binary by hand in a shell):

```bash
rdns-client -config /etc/rdns/client.yaml --debug full
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Listed domain still resolves to origin country | `rules.json` not matching, or DNS not intercepted | `--debug simple`; check for a `dns: forward` line. If you see `dns: local`, the QNAME isn't matching the rule (typo / wrong suffix). |
| Listed domain fails entirely (connection dropped) | **fail-closed** — the profile's tunnel is down | Check `tunnelmgr: connected` in the log; verify the exit node is up and the client cert is valid. This is correct behavior (no leak), not a bug. |
| autoscript's own VPN stops working after starting rdns-client | `local_ips` missing/wrong → the node's own 443 got redirected | Set `local_ips` to the VPS's real public IP. Restart `rdns-client`. |
| `nftables redirects applied` never appears / apply fails | not root / no `CAP_NET_ADMIN` | Run as root, or grant the cap. Check `journalctl -u rdns-client`. |
| Exit node answers DNS but relay fails | client cert not signed by the exit's `client_cas`, or revoked | Re-mint the client cert (Step 0); confirm `ca.crt` matches on both sides; check the exit log for `peer cert REVOKED`. |
| `dns_drop_acl` climbing | a source IP isn't in `acl.allowed` | Add the decision node's public IP to `acl.allowed` and restart `rdns-server`. |
| High latency on unmatched domains | intercept overhead | Should be <5ms (PRD §15). If higher, check `--debug full` relay byte counts for stalls; ensure the direct dial isn't resolving via a slow upstream. |
| QUIC/HTTP3 sites not routed | Domain not matched or ECH active | QUIC (UDP 443) is intercepted via TPROXY (`:14400`). If domain is matched, it tunnels via mTLS yamux datagram relay. If unmatched or unclassified (e.g. ECH), it falls back to Jalur A (pass-through) so apps never hang. Check `--debug simple` for `quic:` log lines. |

## Configuration reference

Full annotated examples, split by side (each with its own README):

- decision node → [`examples/client/`](examples/client/README.md):
  `client.example.yaml` + `rules.example.json` (simple quick-test domains:
  ipinfo, speedtest, netflix, …)
- exit node → [`examples/server/`](examples/server/README.md):
  `server.example.yaml`

### `rdns-client` flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-config` | `/etc/rdns/client.yaml` | config path |
| `-nft` | `true` | apply nftables redirects on start (needs root) |
| `-no-nft` | `false` | skip nftables (dev; interceptors only see locally-redirected traffic) |
| `-debug` | *(off)* | `simple` (app-level) or `full` (wire-level traces) |
| `-version` | — | print version and exit |

### `rdns-server` flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-config` | `/etc/rdns/server.yaml` | config path |
| `-debug` | *(off)* | `simple` or `full` |
| `-version` | — | print version and exit |

### `rdns-certs` subcommands

| Command | Key flags |
|---------|-----------|
| `ca` | `-name`, `-out`, `-ttl` |
| `client` | `-ca`, `-cakey`, `-name`, `-out`, `-ttl` |
| `server` | `-ca`, `-cakey`, `-name`, `-out`, `-dns`, `-ip`, `-ttl` |

Domain rules are `{"<profile>": ["<domain>", ...]}`, **suffix-based** — a rule
for `bri.co.id` matches `mobile.bri.co.id`. Longest-suffix wins.

## Project layout

```
cmd/rdns-client/     decision-node main
cmd/rdns-server/     exit-node main
tools/rdns-certs/    PKI minting CLI
internal/
  config/            YAML config load + validation (client & server)
  rules/             domain→profile rule engine (suffix match, atomic reload)
  tunnel/            mTLS+yamux protocol: dest header, session, TCP & UDP relay
  tunnelmgr/         one session/profile, auto-reconnect, fail-closed
  snix/              SNI (ClientHello) + Host extraction from raw bytes
  dnsx/              QNAME extraction from raw DNS
  quicx/             QUIC Initial decrypt (v1/v2) & TLS 1.3 ClientHello SNI
  sniintercept/      tcp/443,80 interceptor (decision node)
  dnsintercept/      udp/53 interceptor (decision node)
  quicintercept/     udp/443 TPROXY interceptor + flow table (decision node)
  dnsanswer/         ACL-gated DNS answer service (exit node)
  acl/               source-IP allowlist + per-IP token-bucket rate limit
  acme/              Let's Encrypt (HTTP-01) wiring + challenge-only handler
  certstore/         CA, client certs, server cert, revocation
  markdial/          SO_MARK dialer (excludes rdns's own egress from tproxy)
  nftsetup/          nftables redirect generation + apply
  logging/           slog JSON setup + --debug simple/full modes
deploy/              systemd units
etc/                 Docker runtime configs (server.yaml, client.yaml, test/)
docker/              smoke-test scripts for docker-compose.test.yml
Dockerfile           multi-stage static build (all 3 binaries)
docker-compose.yml   production (profiles: server / client / certs)
docker-compose.test.yml  local end-to-end smoke test
examples/
  client/            client.example.yaml + rules.example.json + README
  server/            server.example.yaml + README
  examples_test.go   validates the examples against the real loaders
SETUP.md             full walkthrough: Cloudflare → server → client
```

## Notes & known limitations

- **QUIC/HTTP3 (UDP 443)** is fully supported via TPROXY interception (`:14400`), Initial packet decryption (v1 & v2), and length-prefixed datagram streaming over the mTLS yamux tunnel. Unmatched/unclassified flows use Jalur A pass-through (fail-open) so apps never hang.
- **TLS ECH** (Encrypted Client Hello) hides the SNI → such connections fall back to "no match → direct" (Jalur A pass-through, no crash or freeze, just not bypassed).
- **Single exit node per profile** in v1. Multi-exit-node failover is v1.1.
- **UDP/53 spoofing** is mitigated but not eliminated (inherent to UDP); the ACL + rate limit are the control, not a guarantee. This is a deliberate, documented trade-off, not an oversight.

## License

See `rdns-prd.md` (owner: risqinf). Build & contribute per the Makefile.
