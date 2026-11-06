# Panduan Deploy rdns

Dokumen ini berisi: **[A] fungsi tiap binary**, **[B] manifest file** (apa
di-copy ke mana), **[C] uji cepat 10 menit tanpa Cloudflare**, **[D] setup
produksi dengan Cloudflare + Let's Encrypt**, **[E] IP dinamis/residential**,
**[F] debug & troubleshooting**.

---

## A. Fungsi tiap binary

| Binary | Dijalankan di | Fungsi | Butuh config? |
|--------|--------------|--------|---------------|
| **`rdns-client`** | VPS **decision node** (Rocky, tempat autoscript + user VPN masuk) | Intercept DNS (udp/53) & HTTPS/HTTP (tcp/443,80) milik user, cocokkan ke `rules.json`. Domain cocok → dilewatkan tunnel mTLS ke exit node. Domain tidak cocok → keluar langsung dari VPS ini. Juga memasang rule nftables-nya sendiri saat start. | `client.yaml` + `rules.json` + 3 file cert |
| **`rdns-server`** | VPS **exit node** (Alpine, negara tujuan — mis. MY) | Melayani 3 port publik: `udp/53` jawab DNS pakai resolver lokal (di-ACL), `tcp/443` terima tunnel mTLS lalu relay + egress pakai IP VPS ini, `tcp/80` khusus ACME. Tidak tahu apa-apa soal domain rules. | `server.yaml` + 2–3 file cert |
| **`rdns-certs`** | **PC Anda** (offline, tidak pernah di server) | Alat pembuat sertifikat: CA internal, cert tiap decision node, cert tiap exit node. Sekali jalan, hasilnya berupa file yang di-copy ke server. | tidak ada |

**Cara kerja satu kalimat:** user → VPN masuk ke decision node → `rdns-client`
cek domain-nya ada di rules? → kalau ya, traffic & DNS-nya dikirim lewat
tunnel ke `rdns-server` di negara tujuan → keluar dari IP negara itu.

---

## B. Manifest file — apa di-copy ke mana

### B.1. Dari hasil build (`dist/`)

| File | Ukuran | Ke mana |
|------|--------|---------|
| `rdns-client-linux-amd64` | ~6.9 MB | **decision node** → `/usr/local/bin/rdns-client` |
| `rdns-server-linux-amd64` | ~9.0 MB | **exit node** → `/usr/local/bin/rdns-server` |
| `rdns-certs-windows-amd64.exe` | ~3.7 MB | **tetap di PC** (untuk mint cert) |
| `rdns-certs-linux-amd64` | ~3.7 MB | cadangan; kalau mau mint langsung di VPS Linux |
| `SHA256SUMS` | — | untuk cek integritas setelah copy |

> VPS ARM? pakai varian `-linux-arm64`. Cek: `uname -m` → `x86_64` = amd64,
> `aarch64` = arm64.

### B.2. Hasil mint cert (`pki/`) — **INI YANG PALING SERING TERLEWAT**

Setelah §C.1 dijalankan di PC, folder `pki/` berisi:

```
pki/
├── ca.crt          ← copy ke KEDUA server (decision + exit)
├── ca.key          ← JANGAN PERNAH di-copy ke server. Tetap di PC.
└── certs/
    ├── node-sg.crt ← copy ke decision node SG
    ├── node-sg.key ← copy ke decision node SG
    ├── exit-my.crt ← copy ke exit node MY
    └── exit-my.key ← copy ke exit node MY
```

**Tabel lengkap penempatan file cert:**

| File | Decision node (SG) | Exit node (MY) | Catatan |
|------|--------------------|----------------|---------|
| `ca.crt` | ✅ `/etc/rdns/ca.crt` | ✅ `/etc/rdns/ca.crt` | **wajib di kedua sisi**, harus file yang sama |
| `ca.key` | ❌ | ❌ | rahasia, hanya di PC |
| `node-sg.crt` | ✅ `/etc/rdns/certs/node-sg.crt` | ❌ | identitas client |
| `node-sg.key` | ✅ `/etc/rdns/certs/node-sg.key` | ❌ | **chmod 600** |
| `exit-my.crt` | ❌ | ✅ `/etc/rdns/certs/exit-my.crt` | identitas exit (static mode) |
| `exit-my.key` | ❌ | ✅ `/etc/rdns/certs/exit-my.key` | **chmod 600** |

### B.3. File config

| File sumber | Ke mana | Path di server |
|-------------|---------|----------------|
| `etc/client.yaml` (atau `examples/client/client.example.yaml`) | decision node | `/etc/rdns/client.yaml` |
| `examples/client/rules.example.json` | decision node | `/etc/rdns/rules.json` |
| `etc/server.yaml` (atau `examples/server/server.example.yaml`) | exit node | `/etc/rdns/server.yaml` |

### B.4. Unit systemd (opsional, kalau tidak pakai Docker)

| File | Ke mana | Path |
|------|---------|------|
| `deploy/rdns-client.service` | decision node | `/etc/systemd/system/` |
| `deploy/rdns-server.service` | exit node | `/etc/systemd/system/` |

---

## C. UJI CEPAT — 10 menit, TANPA Cloudflare / domain

> 💡 **PANDUAN KHUSUS PEMULA:**  
> Jika Anda merasa pembuatan sertifikat atau konfigurasi ini terlalu rumit, silakan buka panduan super lengkap dan ramah pemula di:  
> 📖 **[PANDUAN-CERTIFICATE.md](PANDUAN-CERTIFICATE.md)** (disertai analogi mudah & instruksi step-by-step).

Mode ini memakai **static cert** (mTLS internal). Tidak butuh domain, tidak butuh Let's Encrypt, dan tidak butuh membuka port 80 di internet.

### Contoh IP Nyata yang Digunakan:
Di bawah ini kita gunakan contoh IP nyata agar mudah dipahami:
- **Server DNS / Exit Node (Malaysia):** `103.150.120.10`
- **Client DNS / Decision Node (Singapore):** `103.150.120.20`
*(Saat praktik, ganti kedua IP ini dengan IP VPS asli Anda).*

---

### C.1. Sertifikat SSL/TLS (Pilih Salah Satu)

#### Pilihan 1: Pakai yang Sudah Jadi (Paling Cepat)
Sertifikat sudah dibuatkan dan siap pakai di folder **`examples\pki\`**:
- `examples\pki\ca.crt` $\rightarrow$ Kirim ke **KEDUA server**
- `examples\pki\exit-node\exit-my.{crt,key}` $\rightarrow$ Kirim ke **Server DNS (103.150.120.10)**
- `examples\pki\decision-node\node-sg.{crt,key}` $\rightarrow$ Kirim ke **Client DNS (103.150.120.20)**
- `examples\pki\ca.key` $\rightarrow$ **TETAP DI PC/LAPTOP** (kunci rahasia induk)

#### Pilihan 2: Buat Sendiri dari Nol di Laptop (Hanya 3 Perintah)
Buka PowerShell di laptop Anda:
```powershell
mkdir certs-saya; cd certs-saya

# 1. Buat Induk Sertifikat (CA)
..\dist\rdns-certs-windows-amd64.exe ca -name rdns-ca -out .

# 2. Buat Sertifikat Server DNS Malaysia (Ganti 103.150.120.10 dgn IP Server Anda)
..\dist\rdns-certs-windows-amd64.exe server -ca ca.crt -cakey ca.key -name exit-my -dns exit-my -ip 103.150.120.10 -out .

# 3. Buat Sertifikat Client DNS Singapore
..\dist\rdns-certs-windows-amd64.exe client -ca ca.crt -cakey ca.key -name node-sg -out .
```

---

### C.2. Upload ke Server DNS / Exit Node (Malaysia: 103.150.120.10)

Dari PowerShell di laptop Anda (root project `rdns`):

```powershell
$SERVER_DNS = "103.150.120.10"

# 1. Upload binary
scp .\dist\rdns-server-linux-amd64 root@${SERVER_DNS}:/usr/local/bin/rdns-server

# 2. Buat folder dan upload sertifikat
ssh root@${SERVER_DNS} "mkdir -p /etc/rdns/certs"
scp .\examples\pki\ca.crt                  root@${SERVER_DNS}:/etc/rdns/ca.crt
scp .\examples\pki\exit-node\exit-my.crt   root@${SERVER_DNS}:/etc/rdns/certs/exit-my.crt
scp .\examples\pki\exit-node\exit-my.key   root@${SERVER_DNS}:/etc/rdns/certs/exit-my.key

# 3. Upload file konfigurasi
scp .\etc\server.yaml root@${SERVER_DNS}:/etc/rdns/server.yaml
```

---

### C.3. Konfigurasi Server DNS (103.150.120.10)

SSH ke server DNS:

```bash
ssh root@103.150.120.10

chmod 755 /usr/local/bin/rdns-server
chmod 600 /etc/rdns/certs/exit-my.key
mkdir -p /var/lib/rdns /var/log

# Buka firewall untuk 2 port ini:
iptables -I INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
```

Edit `/etc/rdns/server.yaml` (`nano /etc/rdns/server.yaml`):

```yaml
listen:
  dns:    "0.0.0.0:53"
  tunnel: "0.0.0.0:443"

tls:
  cert_file:  /etc/rdns/certs/exit-my.crt
  key_file:   /etc/rdns/certs/exit-my.key
  client_cas: /etc/rdns/ca.crt

acl:
  allowed:
    # ⚠️ Masukkan IP VPS Client VPN (Singapore) Anda di sini!
    - 103.150.120.20
  rate_per_sec: 50
  burst: 100

dns:
  upstreams: [system]
  timeout: 3s

logging:
  level: debug
  file: ""
```

Jalankan server DNS:

```bash
/usr/local/bin/rdns-server -config /etc/rdns/server.yaml --debug simple
```

Yang harus muncul (tanda berhasil):
```text
"msg":"rdns-server starting"
"msg":"ACL ready" "allowed":1
"msg":"cert material loaded" "revoked":0
"msg":"tunnel listener" "addr":"0.0.0.0:443" "cert":"static-cert"
"msg":"dns answer service" "addr":"0.0.0.0:53" "upstreams":["system"]
"msg":"rdns-server ready" "public_ports":["udp/53","tcp/443"]
```
*(Biarkan terminal ini tetap terbuka)*.

---

### C.4. Upload + Konfigurasi Client DNS (Singapore: 103.150.120.20)

Dari PowerShell laptop Anda (buka tab/jendela PowerShell baru):

```powershell
$CLIENT_DNS = "103.150.120.20"

# 1. Upload binary
scp .\dist\rdns-client-linux-amd64 root@${CLIENT_DNS}:/usr/local/bin/rdns-client

# 2. Buat folder dan upload sertifikat
ssh root@${CLIENT_DNS} "mkdir -p /etc/rdns/certs"
scp .\examples\pki\ca.crt                      root@${CLIENT_DNS}:/etc/rdns/ca.crt
scp .\examples\pki\decision-node\node-sg.crt   root@${CLIENT_DNS}:/etc/rdns/certs/node-sg.crt
scp .\examples\pki\decision-node\node-sg.key   root@${CLIENT_DNS}:/etc/rdns/certs/node-sg.key

# 3. Upload konfigurasi dan rules
scp .\etc\client.yaml                          root@${CLIENT_DNS}:/etc/rdns/client.yaml
scp .\examples\client\rules.example.json       root@${CLIENT_DNS}:/etc/rdns/rules.json
```

SSH ke VPS Client (Singapore):

```bash
ssh root@103.150.120.20

chmod 755 /usr/local/bin/rdns-client
chmod 600 /etc/rdns/certs/node-sg.key
```

Edit `/etc/rdns/client.yaml` (`nano /etc/rdns/client.yaml`):

```yaml
rules: /etc/rdns/rules.json

listen:
  dns:  "127.0.0.1:5353"
  sni:  "127.0.0.1:14300"
  quic: "0.0.0.0:14400"

profiles:
  - name: my
    # ⚠️ Masukkan IP VPS Server DNS (Malaysia) Anda di sini!
    server:      103.150.120.10:443
    dns:         103.150.120.10:53
    # server_name harus 'exit-my' (nama di dalam sertifikat server)
    server_name: exit-my

tls:
  ca_file:   /etc/rdns/ca.crt
  cert_file: /etc/rdns/certs/node-sg.crt
  key_file:  /etc/rdns/certs/node-sg.key

# Masukkan IP VPS Client ini sendiri agar port VPN aslinya tidak bentrok
auto_local_ips: false
local_ips:
  - 103.150.120.20

dns:
  default_upstream: "8.8.8.8:53"
  timeout: 2s
```

`rules.json` sudah otomatis berisi domain populer untuk uji coba (`ipinfo.io`, `netflix.com`, `api.ipify.org`, dll).

---

### C.5. Jalankan Client DNS & Cek Koneksi

```bash
/usr/local/bin/rdns-client -config /etc/rdns/client.yaml --debug simple
```

Yang harus muncul:
```
"msg":"rules loaded" "profiles":["my"] "domains":12
"msg":"tunnel manager started" "profiles":1
"msg":"nftables redirects applied" "local_ips":[...] "auto":true
"msg":"tunnelmgr: connected" "profile":"my"     ← INI KUNCI: tunnel UP
"msg":"dns interceptor listening"
"msg":"sni interceptor listening"
"msg":"quic interceptor listening"
```

Kalau `tunnelmgr: connected` **tidak muncul**, lihat §F.

### C.6. Uji dari device user (PALING MUDAH)

Sambungkan HP/laptop ke VPN **decision node SG** seperti biasa, lalu di device:

```bash
curl -s ipinfo.io | grep -E '"(ip|country)"'
#   "country": "MY"   ← BERHASIL: keluar dari exit node MY
#   "country": "SG"   ← belum bekerja, lihat §F

curl -s https://www.google.com -o /dev/null -w '%{remote_ip}\n'
#   IP node SG  ← domain tidak terdaftar tetap direct (benar)
```

Ini menguji jalur sebenarnya: traffic user → nftables redirect → interceptor
→ tunnel → exit node.

### C.6b. Uji dari dalam decision node (opsional, tanpa device)

Karena `rdns-client` sudah memasang nftables, koneksi keluar dari box ini
juga ikut di-intercept. Jadi cukup:

```bash
# DNS split: tanya interceptor langsung (port 5353)
dig @127.0.0.1 -p 5353 ipinfo.io +short
#   terjawab = DNS lewat exit node ✅

# egress split: HTTPS biasa (nftables yang redirect ke interceptor)
curl -s https://ipinfo.io/json | grep country
#   "country":"MY" ✅   (cert divalidasi ke CA publik ipinfo, bukan ca.crt rdns —
#                        ca.crt hanya untuk hop tunnel client↔exit, bukan end-to-end)
```

> Jangan pakai `--cacert /etc/rdns/ca.crt` untuk curl ke situs publik:
> sertifikat CA internal rdns hanya mengamankan hop **tunnel** client↔exit.
> TLS end-to-end ke `ipinfo.io` tetap pakai CA publik normal.

### C.7. Pasang systemd (setelah uji cepat berhasil)

```powershell
scp .\deploy\rdns-server.service root@${EXIT}:/etc/systemd/system/
scp .\deploy\rdns-client.service root@${SG}:/etc/systemd/system/
```

```bash
# di masing-masing server:
systemctl daemon-reload
systemctl enable --now rdns-server     # exit node
systemctl enable --now rdns-client     # decision node
journalctl -u rdns-server -f           # pantau
```

---

## D. Setup produksi — Cloudflare + Let's Encrypt

Bedanya dengan §C hanya **cert exit node**: bukan static, tapi sertifikat
Let's Encrypt asli (exit node terlihat seperti HTTPS server biasa). Decision
node tidak berubah.

### D.1. Pointing di Cloudflare

DNS → Records → Add record:

| Field | Nilai | ⚠️ |
|-------|-------|-----|
| Type | `A` | |
| Name | `exit-my` | → `exit-my.example.com` |
| IPv4 address | `<EXIT_IP>` | IP exit node |
| **Proxy status** | **DNS only (awan ABU-ABU)** | **WAJIB** |
| TTL | Auto | |

**Kenapa tidak boleh awan oranye (Proxied):** Cloudflare mengakhiri TLS di
sisinya lalu membuat koneksi baru ke origin → sertifikat **client** mTLS
rdns tidak diteruskan → tunnel mati. Selain itu port 80 jadi di-belakangi
Cloudflare → challenge ACME gagal → cert tidak terbit.

Cek:
```bash
dig +short exit-my.example.com
#   harus = <EXIT_IP>. Kalau muncul 104.x / 172.67.x → masih proxied.
```

### D.2. Exit node — ganti ke mode LE

```bash
# di exit node, edit /etc/rdns/server.yaml:
```
```yaml
listen:
  dns:    "0.0.0.0:53"
  tunnel: "0.0.0.0:443"
  acme:   "0.0.0.0:80"        # ← tambah port 80

tls:
  domain: exit-my.example.com # ← ganti cert_file/key_file dengan ini
  client_cas: /etc/rdns/ca.crt
```

Buka port 80 juga:
```bash
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
```

Restart:
```bash
systemctl restart rdns-server
journalctl -u rdns-server -f | grep acme
```

Yang terjadi otomatis (fitur prefetch):
```
"msg":"acme (tcp/80) listening" "domain":"exit-my.example.com"
"msg":"acme: certificate issued" "domain":"exit-my.example.com"   ← selesai
```
Kalau pointing belum propagate, ia **retry tiap 30 detik** sampai berhasil —
tidak perlu restart.

### D.3. Decision node — pakai domain

```yaml
profiles:
  - name: my
    server:      exit-my.example.com:443
    server_name: exit-my.example.com    # ← sama dgn domain cert LE
    dns:         exit-my.example.com:53
```
```bash
systemctl restart rdns-client
```

### D.4. Verifikasi cert publik

```bash
echo | openssl s_client -connect exit-my.example.com:443 2>/dev/null \
  | openssl x509 -noout -issuer -subject
#   issuer : Let's Encrypt  (bukan "rdns-ca")
#   subject: CN = exit-my.example.com
```

---

## E. `local_ips` untuk IP dinamis / residential

**Jawaban: kosongkan `local_ips`, biarkan `auto_local_ips: true`** (default).

`rdns-client` mendeteksi alamat IP box-nya sendiri saat start dan **cek ulang
tiap 60 detik** (`local_ip_refresh`). IP berubah → rule nftables disusun
ulang otomatis, tanpa restart.

Kenapa benar untuk residential: traffic inbound yang sudah di-DNAT router
tiba di box dengan **daddr = IP lokal interface** (mis. `192.168.1.23`), bukan
IP publik. Auto-detect membaca IP interface — persis yang relevan, dan stabil
walau IP publik berubah.

```bash
# lihat hasil deteksi:
journalctl -u rdns-client | grep 'nftables redirects applied'
#   "local_ips":["192.168.1.23","172.17.0.1"] "auto":true
```

| Situasi | Konfigurasi |
|---------|-------------|
| Residential / IP berubah | `auto_local_ips: true`, `local_ips: []` |
| VPS IP statis, mau manual | `auto_local_ips: false`, `local_ips: [<SG_IP>]` |
| Auto-detect meleset satu IP | `auto_local_ips: true` + `local_ips: [<IP_TERSEBUT>]` (di-merge) |

---

## F. Debug & troubleshooting

### Flag debug

```bash
rdns-client --debug simple   # 1 baris per koneksi: tunnel/direct/fail-closed
rdns-client --debug full     # + stream yamux, byte count, tiap paket DNS
rdns-server --debug full     # sama di sisi exit node
```

### Log yang menentukan arah

| Baris log (client) | Arti |
|--------------------|------|
| `"msg":"sni: tunnel" "host":"ipinfo.io" "profile":"my"` | ✅ TCP lewat exit node |
| `"msg":"quic: tunnel" "host":"ipinfo.io" "profile":"my"` | ✅ QUIC/UDP lewat exit node |
| `"msg":"dns: forward" "qname":"ipinfo.io" "profile":"my"` | ✅ DNS lewat exit |
| `"msg":"sni: direct" "host":"google.com"` | ✅ TCP tidak terdaftar → langsung |
| `"msg":"quic: direct" "host":"google.com"` | ✅ QUIC tidak terdaftar / unclassified → langsung (Jalur A) |
| `"msg":"sni: tunnel unavailable; dropping (fail-closed)"` | ⚠️ tunnel exit mati — **by design**, tidak bocor |
| `"msg":"quic: tunnel unavailable; fallback direct"` | ⚠️ tunnel exit mati → fail-open Jalur A (tidak hanging) |
| `"msg":"tunnelmgr: dial failed"` | tidak bisa connect ke exit node |

### Masalah umum

| Gejala | Penyebab | Solusi |
|--------|----------|--------|
| `tunnelmgr: connected` tidak pernah muncul | exit node mati / port 443 tertutup / cert tidak cocok | `nc -zv <EXIT_IP> 443` dari decision node. Cek `server_name` = nama di cert. |
| `certificate is valid for ... not ...` | `server_name` ≠ SAN cert | Static: `server_name: exit-my` (sama dgn `-dns` saat mint). LE: pakai domain. |
| `bad certificate` / handshake gagal | `ca.crt` di kedua sisi beda | Copy ulang `ca.crt` yang sama ke kedua server. |
| DNS terjawab tapi egress masih SG | traffic tidak lewat interceptor | Cek nftables: `nft list table ip rdns`. Pastikan `local_ips` tidak ikut men-cover IP tujuan. |
| VPN autoscript jadi rusak | `local_ips` salah → endpoint 443 sendiri ikut di-redirect | Set `auto_local_ips: true`. Hentikan: `systemctl stop rdns-client`. |
| `dig @127.0.0.1 -p 5353` timeout | interceptor mati / ACL menolak | `--debug full`; cek `dns_drop_acl` di log exit node → tambahkan IP decision ke `acl.allowed`. |
| Netflix / Apps tetap keluar SG saat pakai HTTP/3 | Domain belum terdaftar di rules.json / ECH aktif | Pastikan domain QUIC/HTTP3 masuk di rules.json. QUIC kini di-intercept via UDP 443 TPROXY. Jika ECH aktif, otomatis fallback ke Jalur A (direct). |

### Reset total (kalau mau mulai dari awal)

```bash
# decision node:
systemctl stop rdns-client
nft delete table ip rdns ; nft delete table ip6 rdns   # hapus rule rdns
# exit node:
systemctl stop rdns-server
```
