
## Xray 基于 Nginx 的 VLESS + XTLS 一键安装脚本 <img src="https://raw.githubusercontent.com/wulabing/Xray_onekey/main/image/project_xray.jpg" alt="Project_Xray" width="122" height="30" align="bottom" />


> 感Terima kasih kepada JetBrains yang telah menyediakan lisensi pengembangan perangkat lunak sumber terbuka non-komersial!

> Thanks for non-commercial open source development authorization by JetBrains!

### Karena kemungkinan xtls diblokir, disarankan untuk menggunakan versi frontend Nginx

### Telegram 群组
* Telegram 交流群：https://t.me/wulabing_v2ray 
* Telegram 更新公告频道：https://t.me/wulabing_channel

### Persiapan
* Siapkan nama domain dan tambahkan record A ke dalamnya;
* Instal `wget`.

### Spesifikasi tautan impor
https://github.com/XTLS/Xray-core/issues/91

> Pada 2021-2-24, hanya V2RayN 4.12+ dan V2RayNG 1.5.8+ yang mendukung tautan dan impor kode QR, klien lain harap mengisi informasi konfigurasi secara manual.


### Metode pemasangan/pembaruan (frontend Nginx)

Metode konfigurasi yang didukung

- VLESS + TCP + TLS + Nginx + WebSocket

```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/wulabing/Xray_onekey/nginx_forward/install.sh" && chmod +x install.sh && bash install.sh
```

### Metode pemasangan/pembaruan (bagian depan Xray)

Metode Konfigurasi yang Didukung

- VLESS + TCP + XTLS / TLS  + Nginx

- VLESS + TCP + XTLS / TLS  + Nginx 及 VLESS + TCP + TLS + Nginx + WebSocket Pola kemunduran dan pola yang hidup berdampingan

```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/yudhapermana-yt/Xray_onekey-bahasa-indonesia/main/install.sh" && chmod +x install.sh && bash install.sh
```


### Catatan
* Jika Anda tidak memahami arti spesifik dari pengaturan dalam skrip, kecuali untuk nama domain, gunakan nilai default yang disediakan oleh skrip;
* Menggunakan skrip ini mengharuskan Anda untuk memiliki dasar Linux dan pengalaman dalam menggunakannya, untuk memahami sebagian pengetahuan tentang jaringan komputer, dan operasi dasar komputer;
* Saat ini mendukung Debian 9+ / Ubuntu 18.04+ / Centos7+ / Oracle Linux 7+;
* Pemilik grup hanya memberikan dukungan yang sangat terbatas, jika Anda memiliki pertanyaan, Anda dapat bertanya kepada anggota grup.

### Ucapan Terima Kasih

* Gambar proyek README Project_Xray dalam skrip ini disediakan oleh Blitzcrank Telegram:@Blitz_crank dengan ucapan terima kasih kepada Blitzcrank.
* MTProxyTLS dalam skrip ini didasarkan pada modifikasi sekunder dari https://github.com/sunpma/mtp. Terima kasih kepada sunpma;
* Skrip asli Riptide 4-in-1 dalam skrip ini mengacu pada https://www.94ish.me/1635.html. Terima kasih kepada https://www.94ish.me/1635.html;
* Proyek versi modifikasi dari skrip Riptide 4-in-1 dalam skrip ini merujuk pada https://github.com/ylx2016/Linux-NetSpeed. Terima kasih kepada ylx2016;
* File konfigurasi dan sebagian logika dalam skrip ini direferensikan di https://github.com/jiuqi9997/xray-yes Terima kasih kepada Nine7;
* API kode QR dalam skrip ini direferensikan di https://github.com/mack-a/v2ray-agent Terima kasih kepada mack-a.

### Metode startup

Memulai Xray: `systemctl start xray`

Menghentikan Xray: `systemctl stop xray`

Mulai Nginx: `systemctl start nginx`

Menghentikan Nginx: `systemctl stop nginx`

### Direktori terkait

Katalog Web: `/www/xray_web`

Konfigurasi sisi server Xray: `/usr/local/etc/xray/config.json`.

Katalog Nginx: `/etc/nginx`

File sertifikat: `/ssl/xray.key` (kunci privat) dan `/ssl/xray.crt` (kunci publik sertifikat)

### Donasi

Anda dapat membeli VPS dengan Movers AFF saya

https://bandwagonhost.com/aff.php?aff=63939

Anda dapat menggunakan JustMySocks AFF saya untuk membeli proxy dari Penggerak!

https://justmysocks.net/members/aff.php?aff=17621

Anda dapat membeli VPS dengan DMIT AFF saya

https://www.dmit.io/aff.php?aff=3957

Anda dapat menggunakan Vultr AFF saya untuk membuat akun Vultr baru dan menggunakan

https://www.vultr.com/?ref=6881279

Anda dapat mendukung saya melalui USDT, terima kasih atas dukungan Anda!
TRC20:TFannfnajNGYsMTuVDcXfZXXPbcaxAEffa


## Stargazers over time

[![Stargazers over time](https://starchart.cc/wulabing/Xray_onekey.svg)](https://starchart.cc/wulabing/Xray_onekey)

