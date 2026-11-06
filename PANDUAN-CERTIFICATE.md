# Panduan Praktis Pembuatan Sertifikat (Certificate) untuk Pemula

Panduan ini dibuat khusus agar **mudah dimengerti oleh siapa saja**, tanpa perlu pusing dengan istilah teknis rumit (seperti mTLS, SAN, CA Signer, dsb).

---

## 1. Pahami Konsep Dasarnya (1 Menit Saja)

Dalam arsitektur `rdns`, kita menghubungkan **2 VPS**:
1. **Server DNS / Exit Node (Contoh IP: `103.150.120.10`)**  
   Ini VPS di negara tujuan (misalnya **Malaysia**). VPS ini bertugas meresolusi DNS dan menjadi pintu keluar (egress) traffic agar kita terdeteksi berada di Malaysia.
2. **Client DNS / Decision Node (Contoh IP: `103.150.120.20`)**  
   Ini VPS VPN utama Anda (misalnya **Singapore**, tempat autoscript/Xray/SSH-WS Anda berjalan). VPS ini yang menerima koneksi pengguna dan memutuskan apakah paket diteruskan ke Malaysia atau langsung keluar di Singapore.

### Mengapa butuh sertifikat (certificate)?
Ibarat jalan tol VIP rahasia antara Singapore $\leftrightarrow$ Malaysia:
- **CA (`ca.crt`)**: Kantor pusat yang menerbitkan kartu identitas.
- **Sertifikat Server (`exit-my.crt` & `.key`)**: KTP resmi milik Server DNS Malaysia.
- **Sertifikat Client (`node-sg.crt` & `.key`)**: Tiket masuk resmi milik Client VPN Singapore.

Kedua VPS saling mencocokkan sertifikat ini. **Jika bukan dari CA yang sama, koneksi langsung ditolak 100%.** Tidak ada orang luar atau hacker yang bisa menembus tunnel Anda.

---

## 2. Contoh Skenario IP yang Kita Gunakan

Agar tidak membingungkan dengan tanda kurung siku `<IP>`, di seluruh panduan ini kita pakai contoh nyata:
- **IP Server DNS (Exit Node Malaysia):** `103.150.120.10`
- **IP Client DNS (Decision Node Singapore):** `103.150.120.20`

*(Saat mempraktikkan, Anda tinggal mengganti kedua IP tersebut dengan IP VPS asli Anda).*

---

## 3. Langkah 1: Buat Sertifikat (Cukup Sekali di Laptop / PC)

Cara paling mudah dan aman adalah membuat sertifikat dari laptop/PC Windows Anda sendiri menggunakan file `rdns-certs-windows-amd64.exe` yang ada di folder `dist\`.

Buka **PowerShell** di folder proyek `rdns`, lalu jalankan perintah berikut:

```powershell
# 1. Buat folder baru untuk menampung sertifikat Anda
mkdir certs-saya
cd certs-saya

# 2. Buat Induk Sertifikat (CA)
..\dist\rdns-certs-windows-amd64.exe ca -name rdns-ca -out .

# 3. Buat Sertifikat untuk Server DNS / Exit Node (Malaysia)
# Ganti 103.150.120.10 dengan IP VPS Server DNS Anda!
..\dist\rdns-certs-windows-amd64.exe server -ca ca.crt -cakey ca.key -name exit-my -dns exit-my -ip 103.150.120.10 -out .

# 4. Buat Sertifikat untuk Client DNS / VPN Node (Singapore)
..\dist\rdns-certs-windows-amd64.exe client -ca ca.crt -cakey ca.key -name node-sg -out .
```

*(Catatan bagi pengguna Linux/Mac: Perintahnya sama persis, cukup ganti nama file binary dengan `./dist/rdns-certs-linux-amd64`)*.

---

## 4. Langkah 2: Cek File yang Dihasilkan

Setelah menjalankan 4 baris perintah di atas, di dalam folder `certs-saya` akan muncul **6 file**:

| Nama File | Untuk Siapa? | Keterangan |
|---|---|---|
| **`ca.crt`** | **KEDUA SERVER** | Sertifikat induk. Wajib dicopy ke Server DNS DAN Client DNS. |
| **`ca.key`** | **SIMPAN DI LAPTOP** | Kunci rahasia induk. **JANGAN PERNAH** di-upload ke server mana pun! |
| **`exit-my.crt`** | **Server DNS (103.150.120.10)** | Sertifikat Server DNS Malaysia. |
| **`exit-my.key`** | **Server DNS (103.150.120.10)** | Kunci privat Server DNS Malaysia. |
| **`node-sg.crt`** | **Client DNS (103.150.120.20)** | Sertifikat Client VPN Singapore. |
| **`node-sg.key`** | **Client DNS (103.150.120.20)** | Kunci privat Client VPN Singapore. |

---

## 5. Langkah 3: Upload File ke Masing-Masing VPS

### Pilihan A: Menggunakan Perintah PowerShell (Paling Cepat)

Dari PowerShell di laptop Anda (masih di dalam folder `certs-saya`):

```powershell
# ============================================================
# 1. UPLOAD KE SERVER DNS / EXIT NODE (103.150.120.10)
# ============================================================
# Buat folder penyimpanan di server:
ssh root@103.150.120.10 "mkdir -p /etc/rdns/certs"

# Upload binary, ca.crt, serta cert & key milik exit node:
scp ..\dist\rdns-server-linux-amd64 root@103.150.120.10:/usr/local/bin/rdns-server
scp ca.crt                          root@103.150.120.10:/etc/rdns/ca.crt
scp exit-my.crt                     root@103.150.120.10:/etc/rdns/certs/exit-my.crt
scp exit-my.key                     root@103.150.120.10:/etc/rdns/certs/exit-my.key
scp ..\etc\server.yaml              root@103.150.120.10:/etc/rdns/server.yaml


# ============================================================
# 2. UPLOAD KE CLIENT DNS / VPN NODE (103.150.120.20)
# ============================================================
# Buat folder penyimpanan di client:
ssh root@103.150.120.20 "mkdir -p /etc/rdns/certs"

# Upload binary, ca.crt, serta cert & key milik client node:
scp ..\dist\rdns-client-linux-amd64 root@103.150.120.20:/usr/local/bin/rdns-client
scp ca.crt                          root@103.150.120.20:/etc/rdns/ca.crt
scp node-sg.crt                     root@103.150.120.20:/etc/rdns/certs/node-sg.crt
scp node-sg.key                     root@103.150.120.20:/etc/rdns/certs/node-sg.key
scp ..\etc\client.yaml              root@103.150.120.20:/etc/rdns/client.yaml
scp ..\examples\client\rules.example.json root@103.150.120.20:/etc/rdns/rules.json
```

### Pilihan B: Menggunakan Aplikasi FileZilla / WinSCP (Visual)

Jika tidak terbiasa dengan baris perintah `scp`, buka FileZilla atau WinSCP:
1. Konek ke **Server DNS (`103.150.120.10`)**:
   - Taruh `ca.crt` di folder `/etc/rdns/ca.crt`
   - Taruh `exit-my.crt` dan `exit-my.key` di folder `/etc/rdns/certs/`
   - Taruh `rdns-server-linux-amd64` di `/usr/local/bin/rdns-server`
   - Taruh `server.yaml` di `/etc/rdns/server.yaml`
2. Konek ke **Client DNS (`103.150.120.20`)**:
   - Taruh `ca.crt` di folder `/etc/rdns/ca.crt`
   - Taruh `node-sg.crt` dan `node-sg.key` di folder `/etc/rdns/certs/`
   - Taruh `rdns-client-linux-amd64` di `/usr/local/bin/rdns-client`
   - Taruh `client.yaml` di `/etc/rdns/client.yaml`
   - Taruh `rules.example.json` di `/etc/rdns/rules.json`

---

## 6. Langkah 4: Sesuaikan Konfigurasi YAML di Server

### A. Di Server DNS (`103.150.120.10`)
Login SSH ke server DNS:
```bash
ssh root@103.150.120.10

# Berikan izin eksekusi dan keamanan kunci:
chmod +x /usr/local/bin/rdns-server
chmod 600 /etc/rdns/certs/exit-my.key
mkdir -p /var/lib/rdns /var/log

# Buka firewall untuk port 53 (UDP) dan port 443 (TCP):
iptables -I INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
```

Edit file `/etc/rdns/server.yaml` (misal dengan `nano /etc/rdns/server.yaml`).  
Pastikan isinya seperti ini:

```yaml
listen:
  dns: "0.0.0.0:53"
  tunnel: "0.0.0.0:443"

tls:
  cert_file: /etc/rdns/certs/exit-my.crt
  key_file: /etc/rdns/certs/exit-my.key
  client_cas: /etc/rdns/ca.crt

acl:
  allowed:
    # ⚠️ MASUKKAN IP CLIENT DNS / VPN NODE ANDA DI SINI!
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
> **Kunci Keamanan:** Baris `- 103.150.120.20` memastikan hanya VPS VPN Singapore Anda yang boleh meminta jawaban DNS ke VPS Malaysia ini.

---

### B. Di Client DNS / VPN Node (`103.150.120.20`)
Login SSH ke VPS VPN Singapore Anda:
```bash
ssh root@103.150.120.20

# Berikan izin eksekusi dan keamanan kunci:
chmod +x /usr/local/bin/rdns-client
chmod 600 /etc/rdns/certs/node-sg.key
```

Edit file `/etc/rdns/client.yaml` (`nano /etc/rdns/client.yaml`).  
Pastikan isinya seperti ini:

```yaml
rules: /etc/rdns/rules.json

listen:
  dns: "127.0.0.1:5353"
  sni: "127.0.0.1:14300"
  quic: "0.0.0.0:14400"

profiles:
  - name: my
    # ⚠️ MASUKKAN IP SERVER DNS / EXIT NODE MALAYSIA ANDA DI SINI!
    server: 103.150.120.10:443
    dns: 103.150.120.10:53
    # server_name harus tetap 'exit-my' sesuai nama sertifikat server
    server_name: exit-my

tls:
  ca_file: /etc/rdns/ca.crt
  cert_file: /etc/rdns/certs/node-sg.crt
  key_file: /etc/rdns/certs/node-sg.key

# Masukkan IP VPS Client ini sendiri agar port VPN aslinya tidak bentrok
auto_local_ips: false
local_ips:
  - 103.150.120.20

dns:
  default_upstream: "8.8.8.8:53"
  timeout: 2s

logging:
  level: debug
  file: ""
```

---

## 7. Langkah 5: Jalankan dan Buktikan Hasilnya!

### 1. Jalankan Server DNS (Malaysia)
Di terminal VPS `103.150.120.10`:
```bash
/usr/local/bin/rdns-server -config /etc/rdns/server.yaml --debug simple
```
Output yang menandakan **BERHASIL**:
```text
"msg":"rdns-server starting"
"msg":"ACL ready" "allowed":1
"msg":"tunnel listener" "addr":"0.0.0.0:443" "cert":"static-cert"
"msg":"dns answer service" "addr":"0.0.0.0:53"
"msg":"rdns-server ready"
```

### 2. Jalankan Client DNS (Singapore)
Buka terminal baru, login ke VPS `103.150.120.20`:
```bash
/usr/local/bin/rdns-client -config /etc/rdns/client.yaml --debug simple
```
Output yang menandakan **BERHASIL KONEK**:
```text
"msg":"rules loaded" "profiles":["my"] "domains":12
"msg":"tunnel manager started" "profiles":1
"msg":"nftables redirects applied"
"msg":"tunnelmgr: connected" "profile":"my"    <--- 🌟 INI TANDA SUKSES BESAR!
"msg":"dns interceptor listening"
"msg":"sni interceptor listening"
"msg":"quic interceptor listening"
```

Jika baris `"msg":"tunnelmgr: connected"` sudah muncul, selamat! Artinya:
- Sertifikat SSL/TLS valid 100%.
- Tunnel mTLS terenkripsi sudah aktif dan saling percaya.
- Port TCP dan UDP (QUIC/HTTP3) siap di-routing otomatis ke Malaysia.

---

## 8. Pertanyaan Umum Pemula (FAQ)

### Tanya: "Bagaimana kalau saya ingin menambah Server Exit Node baru (misalnya Indonesia)?"
**Jawab:**
Sangat mudah, jangan buat CA baru. Pakai CA yang sudah ada di folder `certs-saya`:
1. Buat sertifikat untuk exit node Indonesia (misal IP `103.150.120.30`):
   ```powershell
   ..\dist\rdns-certs-windows-amd64.exe server -ca ca.crt -cakey ca.key -name exit-id -dns exit-id -ip 103.150.120.30 -out .
   ```
2. Upload `ca.crt`, `exit-id.crt`, dan `exit-id.key` ke VPS Indonesia.
3. Di Client Singapore (`client.yaml`), tambahkan profil baru:
   ```yaml
   profiles:
     - name: my
       server: 103.150.120.10:443
       dns: 103.150.120.10:53
       server_name: exit-my
     - name: id
       server: 103.150.120.30:443
       dns: 103.150.120.30:53
       server_name: exit-id
   ```

### Tanya: "Kenapa muncul tulisan `bad certificate`?"
**Jawab:**
Artinya file `ca.crt` di Server DNS dan di Client DNS berbeda. Pastikan Anda menyalin file `ca.crt` yang sama persis dari folder `certs-saya` ke kedua server.

### Tanya: "Kenapa muncul tulisan `certificate is valid for exit-my not ...`?"
**Jawab:**
Periksa file `client.yaml` pada baris `server_name:`. Nilainya harus sama persis dengan nama saat membuat cert (yaitu `exit-my`). Jangan diisi alamat IP di baris `server_name` tersebut.
