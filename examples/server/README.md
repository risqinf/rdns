# examples/server — contoh config untuk exit node

File di folder ini untuk disalin ke VPS **exit node** (Alpine, box bersih):

| File | Tujuan di VPS |
|------|---------------|
| `server.example.yaml` | `/etc/rdns/server.yaml` |

## Langkah singkat

```bash
# di VPS exit node (Alpine), sebagai root:
mkdir -p /etc/rdns/certs /var/lib/rdns /var/log
install -m 0755 rdns-server /usr/local/bin/rdns-server
cp examples/server/server.example.yaml /etc/rdns/server.yaml
# lalu isi: tls.domain / tls.client_cas, acl.allowed (lihat komentar di file)
```

Exit node **bukan** open resolver publik dan **bukan** proxy publik — semua
fungsi-nya hanya melayani decision node yang lolos mTLS/ACL.

## fields yang WAJIB diubah di `server.example.yaml`

1. **`tls.domain`** — hostname milik Anda yang A record-nya menunjuk ke IP
   VPS ini (untuk Let's Encrypt di port 80/443). **Atau** pakai static cert
   (uncomment `cert_file`/`key_file`, hasil `rdns-certs server`).
2. **`tls.client_cas`** — `ca.crt` internal yang sama dengan di decision
   node. Tanpa ini tidak ada client yang bisa ter-verifikasi.
3. **`acl.allowed`** — IP publik semua decision node. Ini gerbang udp/53
   publik; IP di luar daftar di-drop dan dihitung di counter
   `dns_drop_acl`.

## Verifikasi cepat (tanpa decision node)

```bash
# 1. dari VPS exit itu sendiri (IP localhost masuk allowlist? tidak —
#    tambah 127.0.0.1 sementara kalau mau tes dari box-nya sendiri):
dig @127.0.0.1 ipinfo.io +time=3
#    harus dapat jawaban (bukti resolver lokal jalan)

# 2. pastikan hanya 3 port terbuka dari mesin lain:
nmap -sT -p 53,80,443,22,2222,8080 <exit-ip>
#    open: 53/udp, 80, 443   —   sisanya closed/filtered

# 3. jalur mTLS tanpa client resmi harus GAGAL (client cert wajib):
openssl s_client -connect <exit-ip>:443
#    → handshake error: "certificate required" / handshake failure.
#    Ini benar: tanpa client cert dari CA internal tidak ada yang bisa relay.

# 4. jalur non-ACME di port 80 harus 404:
curl -sI http://<exit-ip>/ | head -1
#    → HTTP/1.1 404 Not Found
```

## Memantau & debug

```bash
journalctl -u rdns-server -f
#   baris stats tiap 30 detik:
#   "dns_total":..., "dns_allowed":..., "dns_drop_acl":...,
#   "dns_drop_rate":..., "dns_fwd_fail":...
```

| Counter | Arti sehat |
|---------|-----------|
| `dns_allowed` | naik saat decision node meneruskan query domain matched |
| `dns_drop_acl` | 0 dari node Anda; naik = ada IP asing memindai / spoofing |
| `dns_drop_rate` | 0 saat normal; naik = ada node query melebihi `rate_per_sec` |
| `dns_fwd_fail` | 0; naik = resolver lokal (`upstreams`) bermasalah |

Debug manual (override level config):

```bash
rdns-server -config /etc/rdns/server.yaml --debug simple   # keputusan + session
rdns-server -config /etc/rdns/server.yaml --debug full     # + tiap stream, byte count
```

Log penting di exit node:
- `tunnel: session accepted "peer":"node-sg"` — decision node terhubung (CN
  dari client cert-nya)
- `tunnel: peer cert REVOKED; dropping` — cert node masuk daftar
  `revoked_certs`
- `tunnel: dial failed "dest":"ipinfo.io:443"` — egress ke tujuan gagal

## Menambah exit node negara baru

1. VPS baru (Alpine) → ulangi langkah di atas.
2. `rdns-certs server -ca ca.crt -cakey ca.key -name exit-id -dns exit-id.example.com -ip <IP>`.
3. di **setiap** decision node: tambah entry `profiles` (`id`) di
   `client.yaml`, tambah IP node decision ke `acl.allowed` exit baru, lalu
   `systemctl reload rdns-client`.
4. tambah key `id` di `rules.json` decision node +
   `systemctl reload rdns-client`.
