# PRD: rdns — Domain-Based Split DNS & Traffic Router

| | |
|---|---|
| **Status** | Draft v0.1 |
| **Owner** | risqinf |
| **Tech stack** | Go 1.25 (pinned), Alpine Linux (server), musl static binaries |
| **Related systems** | autoscript (account/tunnel management), websocket-proxy (SSH-WS relay) |

---

## 1. Background

VPN infrastruktur saat ini terdiri dari beberapa VPS per negara (contoh: SG dan ID sebagai node VPN yang menjalankan `autoscript`, MY sebagai node yang seharusnya jadi titik keluar untuk domain yang dibatasi region). Masalah: client MY yang terhubung ke node VPN di luar MY (misal SG) gagal mengakses layanan yang di-geoblock ke Malaysia, karena baik resolusi DNS maupun IP keluar (egress) bukan berasal dari Malaysia.

`rdns` menyelesaikan ini dengan **split routing berbasis domain**: hanya domain yang match daftar aturan yang dialihkan ke node negara tujuan (resolusi DNS *dan* traffic-nya); domain lain tetap keluar langsung dari node asal. Ini bekerja di level jaringan (transparent intercept), sehingga **berlaku untuk semua protokol VPN yang sudah ada** (SSH-WS, VLESS/VMESS/Trojan via Xray, OpenVPN) tanpa perlu instalasi apa pun di device end-user.

## 2. Goals

- G1 — Domain yang terdaftar di rule list diarahkan (DNS + traffic) ke node profil yang sesuai (mis. `my`, `id`), domain lain tetap direct.
- G2 — Berjalan transparan di level VPS, tidak butuh perubahan apa pun di aplikasi/device client.
- G3 — Permukaan port publik di server DNS/exit seminimal mungkin: **hanya UDP 53, TCP 443, TCP 80**.
- G4 — Binary statis (Go, `CGO_ENABLED=0`), deploy gampang ke Alpine (server) maupun Rocky Linux (client, co-located dengan autoscript).
- G5 — ACL/permission builtin: hanya node yang terdaftar yang boleh memakai resolver dan relay milik node lain.
- G6 — Mudah nambah profil negara baru tanpa ubah arsitektur inti.

## 3. Non-Goals

- Tidak menyediakan resolver DNS publik (bukan open resolver).
- QUIC/HTTP3 (UDP 443) kini didukung penuh via TPROXY + Initial decrypt & SNI routing + mTLS yamux datagram relay (RFC 9001/9000). Non-match/unclassified fail-open ke Jalur A (pass-through).
- Tidak menggantikan `autoscript`/`websocket-proxy` — `rdns` berjalan berdampingan, di layer jaringan yang berbeda.
- Tidak menyediakan UI manajemen di v1 — konfigurasi lewat file (YAML/JSON), CLI reload.

## 4. Terminologi

| Istilah | Arti |
|---|---|
| **rdns-client** | Binary yang jalan di VPS VPN (SG/ID). "Decision node" — intercept, cek rule, putuskan. |
| **rdns-server** | Binary yang jalan di VPS DNS/exit (MY, atau negara lain). "Exit node" — resolve DNS + egress traffic, tanpa tahu apa-apa soal domain rule. |
| **Profile** | Label negara tujuan (`my`, `id`, dst) yang dipetakan ke satu `rdns-server`. |
| **Domain rule** | Pasangan pattern domain → profile. |
| **Session tunnel** | Satu koneksi mTLS+yamux persisten per profile antara rdns-client dan rdns-server. |
| **Stream** | Satu logical connection relay di dalam session tunnel (1 stream = 1 koneksi TCP yang di-relay). |

## 5. Arsitektur Sistem

```
Client VPN (SSH-WS/VLESS/OpenVPN)
        │
        ▼
┌─────────────────────────────┐
│  VPS SG/ID — rdns-client     │
│  (Rocky Linux, co-located    │
│   dgn autoscript)             │
│                               │
│  nftables PREROUTING & OUTPUT │
│   udp/53     → :5353 (dns)    │
│   tcp/443,80 → :14300 (sni)   │
│   udp/443    → :14400 (TPROXY)│
│                               │
│  1) DNS interceptor:          │
│     parse QNAME → cek rule    │
│  2) SNI interceptor (TCP):    │
│     peek ClientHello/Host →   │
│     cek rule                  │
│  3) QUIC interceptor (UDP):   │
│     Initial decrypt / SNI →   │
│     cek rule                  │
│                               │
│  Match?                       │
│   tidak → resolve/dial lokal  │
│           (Jalur A: pass-thru)│
│   ya → kirim lewat session    │
│         tunnel (mTLS+yamux)   │
│         ke rdns-server profil │
│         (Jalur B: relay)      │
└───────────────┬───────────────┘
                │  TCP 443 (mTLS, persisten, multiplex TCP streams + UDP datagrams)
                │  UDP 53 (forwarded DNS query, IP-ACL)
                ▼
┌─────────────────────────────┐
│  VPS MY — rdns-server         │
│  (Alpine Linux, musl static)  │
│                                │
│  Port publik: udp/53, tcp/443,│
│               tcp/80 SAJA     │
│                                │
│  udp/53 → DNS answer service  │
│    (ACL by source IP + rate   │
│     limit, forward ke         │
│     resolver lokal MY)        │
│                                │
│  tcp/443 → mTLS listener      │
│    → verifikasi client cert   │
│    → yamux session            │
│    → per-stream: baca dest    │
│      header → dial tujuan     │
│      asli → relay + NAT       │
│      egress pakai IP publik   │
│      MY                       │
│                                │
│  tcp/80 → ACME HTTP-01 saja    │
│    (buat renew cert TLS 443,  │
│     sekaligus kamuflase        │
│     "server web biasa")        │
└───────────────────────────────┘
```

**Prinsip kunci**: `rdns-server` tidak pernah tahu apa itu domain rule. Dia cuma jalanin 2 fungsi generik (jawab DNS, relay+egress traffic) untuk siapa pun yang lolos ACL. Semua "kecerdasan" domain-matching ada di `rdns-client`.

## 6. Tech Stack

| Komponen | Pilihan | Alasan |
|---|---|---|
| Bahasa | Go **1.25** (pinned di `go.mod`, bukan versi terbaru) | Stabilitas — hindari breaking change/fitur baru yang belum matang di toolchain produksi kamu |
| Build | `CGO_ENABLED=0`, `-ldflags="-s -w"` | Binary statis, portable Rocky ⇄ Alpine tanpa dependency runtime |
| OS server (exit node) | Alpine Linux | Minim attack surface, image kecil, cocok untuk appliance dgn 3 port saja |
| OS client (decision node) | Rocky Linux 9/10 (co-located autoscript) — tapi binary-nya OS-agnostic | Static build jadi nggak peduli distro, bisa pindah kalau perlu |
| TLS/mTLS | stdlib `crypto/tls` | Nggak perlu dependency luar buat hal sekritis ini |
| Multiplexing | `github.com/hashicorp/yamux` | Matang, dipakai luas (Consul/Nomad), pure Go, ringan |
| Database rule/config | SQLite via `modernc.org/sqlite` (pure-Go, no cgo) | Biar `CGO_ENABLED=0` tetap kepakai; alternatif ringan: JSON file kalau skala rule kecil |
| Firewall/redirect | `nft` (shell-out via `os/exec`) | Konsisten dgn keputusan sebelumnya — nggak perlu binding netlink native |
| Logging | stdlib `log/slog` | Sudah cukup, terstruktur, no dependency |
| Sertifikat TLS | Let's Encrypt via `golang.org/x/crypto/acme/autocert` (memakai TCP 80 utk challenge) | Sertifikat asli → server 443 kelihatan seperti HTTPS server biasa |

## 7. Desain Port (constraint eksplisit)

Server (`rdns-server`, exit node) **hanya** boleh membuka:

| Port | Protokol | Fungsi |
|---|---|---|
| 53 | UDP | Forward DNS query dari rdns-client yang sudah lolos rule match, dijawab pakai resolver lokal |
| 443 | TCP | mTLS session tunnel (yamux) — semua traffic relay (baik asal domain itu HTTPS *maupun* HTTP biasa) lewat sini |
| 80 | TCP | **Hanya** ACME HTTP-01 challenge (renew cert). Tidak menerima relay apa pun. |

Client (`rdns-client`) tidak perlu port publik masuk sama sekali — semua koneksi keluar (outbound) ke `rdns-server`.

## 8. Security Model — 2 Lapis, Beda Karakter per Port

Karena WireGuard di-drop, **tidak ada lagi lapisan crypto-peer-auth otomatis di level kernel**. Ini trade-off nyata yang harus disadari:

### Lapis TCP 443 (relay) — kuat, mTLS
- Setiap `rdns-client` punya client certificate unik, ditandatangani oleh CA internal (dibuat sekali, per node).
- `rdns-server` cuma terima koneksi TLS dengan client cert valid (`tls.RequireAndVerifyClientCert`).
- Ini setara (bahkan lebih fleksibel dari sisi revocation — tinggal cabut dari CRL/daftar cert valid) dengan yang WireGuard tadinya kasih.

### Lapis UDP 53 (DNS forward) — lebih lemah, IP-based
- UDP tanpa handshake artinya **rawan IP spoofing** (klasik di dunia DNS — mirip vektor DNS amplification attack).
- Mitigasi:
  1. `nftables` ACL: hanya source IP node yang terdaftar (SG/ID) yang boleh kirim ke port 53.
  2. Rate limiting per-IP (`nft limit rate`) — cegah traffic besar meski dari IP yang "keliatan" whitelisted.
  3. **Rekomendasi v1.1**: query DNS juga bisa dilewatkan sebagai stream terpisah di dalam session tunnel mTLS yang sama (opsional, fallback ke UDP 53 langsung kalau tunnel lagi down) — beri opsi paling aman sambil tetap penuhi syarat "port 53 harus kebuka".
- Karena `rdns-server` bukan open resolver publik (nggak akan pernah dipromosikan/dipakai orang luar), risiko realistis relatif kecil, tapi tetap harus didokumentasikan sebagai keputusan sadar, bukan celah yang kelupaan.

### Lapis TCP 80 — minimal exposure
- Hanya melayani path ACME challenge (`/.well-known/acme-challenge/*`), request lain di-drop/404. Tidak ada relay logic sama sekali di port ini.

## 9. Domain Rule Engine

Format rule (JSON, contoh — bisa dipindah ke SQLite kalau daftarnya membesar):

```json
{
  "my": ["maybank2u.com.my", "astro.com.my", "iflix.com"],
  "id": ["bri.co.id", "vidio.com"]
}
```

Matching: suffix-based (pattern `bri.co.id` otomatis match `mobile.bri.co.id`). Load sekali saat start; **v1.1**: dukung reload tanpa restart (`SIGHUP` atau file-watch).

## 10. Protokol Tunnel (rdns-client ⇄ rdns-server)

1. Saat start, rdns-client buka **1 koneksi TCP 443 persisten** ke tiap profile server, mTLS handshake, lalu bungkus jadi **yamux session**.
2. Untuk tiap koneksi yang match rule (dari SNI/DNS/QUIC interceptor):
   - Buka **1 yamux stream baru** di session yang sesuai (bukan koneksi TCP baru — jadi nggak ada overhead TLS handshake berulang per request).
   - Kirim header di awal stream: `[1 byte proto: 0x01=TCP, 0x02=UDP][1 byte panjang host][host][2 byte port big-endian]` — beritahu server protokol dan tujuan aslinya.
   - Untuk TCP: relay byte stream dua arah sampai salah satu sisi close.
   - Untuk UDP (QUIC): relay datagram dengan length-prefixed framing `[2 byte length BE][datagram]` dua arah.
3. Kebijakan ketersediaan tunnel:
   - Untuk TCP: kalau session tunnel putus → fail-closed (koneksi di-drop, tidak bocor ke IP asal).
   - Untuk UDP/QUIC: kalau session tunnel putus → fail-open ke Jalur A (pass-through dial langsung dari VPS lokal) agar app Android/iOS tidak hanging atau gagal load.

## 11. Komponen rdns-client (Decision Node)

| Modul | Tugas |
|---|---|
| `dnsintercept` | Listen di port lokal hasil redirect nftables (udp/53→local), parse QNAME, cek rule, forward ke resolver lokal (default) atau ke `rdns-server` profil terkait (via UDP 53 langsung — subjek §8) |
| `sniintercept` | Listen di port lokal hasil redirect (tcp/443,80→local), ambil original destination (`SO_ORIGINAL_DST`), peek SNI (TLS ClientHello) atau `Host:` header (plain HTTP), cek rule, buka stream TCP ke session tunnel yang sesuai kalau match, atau dial langsung kalau tidak |
| `quicintercept` | Listen UDP 443 via TPROXY (`:14400`), kelola flow table 5-tuple & CID prefix, klasifikasi SNI via `quicx`, relay datagram via yamux (Jalur B) atau dial UDP langsung transparan (Jalur A) |
| `quicx` | HKDF initial secrets derivation (QUIC v1 `0x00000001` & v2 `0x6b3343cf`), header unprotection + AES-128-GCM decryption, CRYPTO frame reassembly, TLS 1.3 ClientHello SNI extractor |
| `tunnelmgr` | Kelola 1 session mTLS+yamux per profile, reconnect otomatis, health-check, buka stream TCP/UDP |
| `ruleloader` | Load & (nanti) reload domain rule |
| `nftsetup` | Helper shell-out ke `nft` buat pasang rule redirect & TPROXY (dijalankan sekali saat install, bukan tiap request) |

## 12. Komponen rdns-server (Exit Node)

| Modul | Tugas |
|---|---|
| `dnsanswer` | Listen udp/53 publik, ACL by source IP + rate limit, forward query ke resolver MY-lokal, balikin jawaban |
| `tunnellisten` | Listen tcp/443, terima mTLS handshake, verifikasi client cert, terima yamux session, accept stream, baca dest header, dial tujuan asli, relay (OS yang urus NAT/masquerade keluar) |
| `acmehandler` | Listen tcp/80, layani `/.well-known/acme-challenge/*` saja, integrasi `autocert` buat auto-renew sertifikat tcp/443 |
| `certstore` | Simpan daftar client cert/CA yang di-trust, dukung revocation list sederhana |

## 13. Risiko & Open Questions

| Risiko | Dampak | Catatan |
|---|---|---|
| **QUIC/HTTP3** (banyak app modern pakai UDP 443) | Mengatasi app Android/iOS yang memakai HTTP/3 tanpa fallback | **Resolved (QUIC RFC 9001)**: Di-intercept via TPROXY `:14400`, diekstrak SNI-nya dari QUIC Initial (RFC 9001/9000). Jika match, di-relay via mTLS yamux stream dengan datagram length framing (`0x02`). Jika tidak match atau unclassified (ECH / unknown QUIC version), pass-through transparan (Jalur A) tanpa drop/reject agar koneksi tidak macet. |
| **TLS ECH (Encrypted Client Hello)** makin banyak diadopsi (Cloudflare, sebagian browser) | SNI ter-enkripsi, `extract_sni` nggak akan nemu apa-apa | Domain kena ECH otomatis fallback ke "tidak match" (direct) — bukan crash, tapi berarti nggak ke-bypass. Worth dipantau tren adopsinya |
| **IP spoofing di UDP 53** | Potensi abuse/reflection kalau ACL nftables misconfigured | Lihat §8, mitigasi rate-limit + ACL wajib dari awal, bukan opsional |
| **Single exit node per profile** | MY jadi single point of failure kalau exit node down | Bisa jadi kerja v1.1: `rdns-client` dukung >1 exit node per profile dgn failover |
| **Sertifikat TLS publik di 443** | Domain di server cert (kalau pakai autocert real domain) jadi "identitas" yang bisa dicari orang lain | Pertimbangkan self-signed CA custom kalau nggak butuh kamuflase HTTPS publik beneran, atau domain generik yang nggak identifiable |

## 14. Rencana Rilis (Phased)

| Fase | Scope |
|---|---|
| **v0.1 (MVP)** | DNS split saja (udp/53 forward + ACL). Belum ada relay TCP. Cukup buat validasi domain yang cuma butuh geo-DNS/CDN trick. |
| **v0.2** | Tambah `sniintercept` + tunnel mTLS/yamux + relay TCP penuh. |
| **v0.3** | ACME autocert utk port 80/443, hardening rate-limit, systemd unit final. |
| **v1.0** | Domain rule reload tanpa restart, logging terstruktur, metrics dasar, serta dukungan QUIC/HTTP3 (UDP 443 TPROXY + Initial SNI decrypt + yamux datagram relay). |
| **v1.1+** | Multi-exit-node per profile, opsi tunneling DNS lewat mTLS (bukan UDP 53 mentah). |

## 15. Success Metrics

- Domain yang masuk rule list: **100% resolve + egress dari IP profil tujuan** (diverifikasi via checker otomatis, model `check_region` yang sudah dibahas sebelumnya).
- Domain di luar rule list: **latensi tambahan < 5ms** dibanding tanpa `rdns` (intercept overhead harus nggak berasa).
- Zero unauthorized access ke `dnsanswer`/`tunnellisten` dari IP di luar whitelist (dicek dari log/reject count).
- Server exit node: **hanya 3 port** yang pernah terlihat open di port scan eksternal.
