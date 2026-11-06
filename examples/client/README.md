# examples/client — contoh config untuk decision node

File di folder ini untuk disalin ke VPS **decision node** (Rocky, dengan
autoscript):

| File | Tujuan di VPS |
|------|---------------|
| `client.example.yaml` | `/etc/rdns/client.yaml` |
| `rules.example.json` | `/etc/rdns/rules.json` |

## Langkah singkat

```bash
# di VPS decision node, sebagai root:
mkdir -p /etc/rdns/certs
install -m 0755 rdns-client /usr/local/bin/rdns-client
cp examples/client/client.example.yaml /etc/rdns/client.yaml
cp examples/client/rules.example.json  /etc/rdns/rules.json
# lalu isi: tls.*, profiles.*, local_ips, acl (lihat komentar di file)
```

## fields yang WAJIB diubah di `client.example.yaml`

1. **`tls.*`** — path cert node Anda (hasil `rdns-certs client`).
2. **`profiles.*`** — satu entry per exit node: `server` (host:443),
   `server_name` (harus match nama cert exit), `dns` (host:53).
3. **`local_ips`** — IP publik VPS ini. **Paling kritis**: kalau kosong/salah,
   endpoint VPN autoscript di 443 ikut ter-redirect dan VPN Anda rusak.
4. **`dns.default_upstream`** — resolver untuk domain yang TIDAK ada di rules
   (kosong = auto-detect dari `/etc/resolv.conf`).

## rules.example.json — set sederhana untuk tes cepat

Rules yang disertakan sengaja memakai domain yang **hasil tesnya langsung
tampak** dari device client, supaya Anda bisa verifikasi tanpa perlu domain
berbayar:

| Domain | Tes apa | Cara cek dari device client |
|--------|---------|------------------------------|
| `ipinfo.io` | **DNS + egress** | `curl ipinfo.io` → field `country` harus **MY**, bukan SG/ID |
| `api.ipify.org` | **egress** | `curl api.ipify.org` → IP yang keluar harus IP exit node |
| `ip-api.com` | **egress** (alternatif) | `curl ip-api.com/json` → `"countryCode":"MY"` |
| `speed.cloudflare.com` | **egress + jalur CDN** | `curl speed.cloudflare.com/api/...` → colo terdekat = MY |
| `speedtest.net` / `fast.com` / `ooklaserver.com` | **speedtest** | server speedtest yang terpilih seharusnya berada di negara exit |
| `netflix.com` + `nflx*.net` | **streaming (geoblock)** | Netflix dari node SG biasanya tergeoblock; setelah di-list harus buka. Subdomain `nflxvideo/nflximg/nflxext/nflxso` penting — CDN-nya ada di domain terpisah, bukan `netflix.com` |

> Catatan: suffix match berlaku, jadi `ipinfo.io` otomatis mencakup
> `api.ipinfo.io`. Satu entry cukup.

### Verifikasi 30 detik

```bash
# di device client yang terhubung ke VPN (node SG):
curl -s ipinfo.io | grep -E 'ip|country'
#   ip      : <IP exit node MY>
#   country : MY          ← BUKAN SG

# domain yang TIDAK ada di rules harus tetap keluar dari node asal:
curl -s https://www.google.com -o /dev/null -w '%{remote_ip}\n'
#   → IP node SG (bukti domain lain tetap direct, tidak ikut MY)
```

Kalau `country` masih SG → cek log client dengan
`rdns-client --debug simple` dan pastikan ada baris
`"msg":"dns: forward" "qname":"ipinfo.io" "profile":"my"`.

### Menambah profil negara baru

1. tambah exit node di `examples/server/` (lihat README di sana) +
   `rdns-certs client/server` untuk node baru,
2. tambah entry `profiles` di `client.example.yaml`,
3. tambah key di `rules.example.json`, misal:
   ```json
   {
     "my": [ "ipinfo.io", "netflix.com" ],
     "id": [ "bri.co.id", "vidio.com" ]
   }
   ```
4. `systemctl reload rdns-client` (SIGHUP, tanpa restart).

## debugging

```bash
# jalankan manual dengan debug agar semua keputusan terlihat:
rdns-client -config /etc/rdns/client.yaml --debug simple
# perlu detail wire-level (stream open, byte count, tiap paket DNS):
rdns-client -config /etc/rdns/client.yaml --debug full
```

- `sni: tunnel`   → koneksi TCP domain matched → lewat exit node ✅
- `sni: direct`   → domain TCP tidak ada di rules → keluar langsung ✅
- `sni: tunnel unavailable; dropping (fail-closed)` → tunnel exit down →
  koneksi TCP di-drop (bukan bocor ke node asal)
- `quic: tunnel`  → flow QUIC/HTTP3 domain matched → lewat tunnel datagram exit node ✅
- `quic: direct`  → flow QUIC tidak ada di rules / unclassified (ECH) → keluar langsung (Jalur A) ✅
- `quic: tunnel unavailable; fallback direct` → tunnel exit down →
  fallback Jalur A agar aplikasi mobile tidak hanging (fail-open)

## check.sh — Script Testing Regional Unlock & Media Checker

Tersedia script `examples/check.sh` untuk mengecek status unlock regional media (Netflix, YouTube Premium, TikTok, ChatGPT, Claude, HotStar, Viu, Steam, Vidio, Bilibili, dll.):

```bash
chmod +x examples/check.sh
./examples/check.sh
```

