# auth-log-analyzer

Linux `auth.log` dosyalarını analiz edip SSH saldırılarını, şüpheli `sudo` kullanımını ve hesap değişikliklerini raporlayan bir komut satırı aracı.
Bulguları **MITRE ATT&CK** tekniklerine eşler; aynı tespitleri bir SIEM'de çalıştırmak için **Sigma kuralları** içerir.

- Python 3.10+, yalnızca standart kütüphane (GeoIP isteğe bağlı)
- Çıktı: terminal, JSON ve HTML rapor, brute force yapan IP'ler için blocklist
- `.gz` arşivlerini ve birden fazla log dosyasını aynı anda okur

## Örnek çıktı

`samples/generated.log` üzerinde (kısaltılmış):

```text
== !! OLASI ELE GEÇİRME — başarısız denemelerden sonra başarılı giriş
  2026-10-14T03:21:12  ubuntu@203.0.113.45  (password), öncesinde 40 hata [BRUTE-FORCE IP]

== Brute-force tespitleri (1) ==================================
  203.0.113.45   toplam 40 | pencerede tepe 40 | 2026-10-14T03:10:00 → 2026-10-14T03:19:33
      denenen: admin, ftp, git, oracle, pi, postgres …

== Şüpheli / reddedilen sudo ===================================
  2026-10-14T03:23:40  ubuntu → root: /usr/bin/cat /etc/shadow

== Hesap değişiklikleri ========================================
  2026-10-14T03:24:02  user_add   backup2
  2026-10-14T03:24:05  group_add  backup2 → grup sudo

== MITRE ATT&CK (7 teknik) =====================================
  T1078.003  Valid Accounts: Local Accounts  [Initial Access] ×1
  T1098      Account Manipulation  [Persistence] ×1
  T1136.001  Create Account: Local Account  [Persistence] ×1
  T1548.003  Abuse Elevation Control Mechanism: Sudo and Sudo Caching  [Privilege Escalation] ×1
  T1003.008  OS Credential Dumping: /etc/passwd and /etc/shadow  [Credential Access] ×1
  T1110.001  Brute Force: Password Guessing  [Credential Access] ×1
  T1021.004  Remote Services: SSH  [Lateral Movement] ×1
```

Rapor, saldırının tamamını sırasıyla gösteriyor: brute force, ardından başarılı giriş, `/etc/shadow` okunması, yeni kullanıcı açılması ve bu kullanıcının `sudo` grubuna eklenmesi.

## Hızlı başlangıç

```bash
git clone https://github.com/yusufiyilmaz/auth-log-analyzer.git
cd auth-log-analyzer
python analyzer.py samples/generated.log
```

## Kullanım

```bash
python analyzer.py /var/log/auth.log
python analyzer.py auth.log auth.log.1 auth.log.2.gz --threshold 10 --window 5
python analyzer.py /var/log/auth.log --outdir raporlar
```

| Seçenek | Açıklama |
|---|---|
| `-t`, `--threshold` | Brute force eşiği, pencere içindeki deneme sayısı (varsayılan 5) |
| `-w`, `--window` | Brute force penceresi, dakika (varsayılan 10) |
| `-y`, `--year` | Klasik syslog satırlarında yıl yazmaz; logun başladığı yıl (varsayılan bu yıl) |
| `-n`, `--top` | Listelerde gösterilecek satır sayısı |
| `--outdir KLASÖR` | HTML, JSON ve blocklist dosyalarını tarih-saat damgalı adlarla bu klasöre yazar |
| `--html`, `--json`, `--blocklist` | Tek bir çıktıyı belirli bir dosyaya yazar (`--json -` ekrana basar) |
| `--geoip-db MMDB` | Yerel GeoLite2 veritabanıyla IP'lerin ülkesini gösterir (`pip install geoip2`); IP'ler dışarı gönderilmez |
| `--no-color` | Renksiz çıktı |

**Çıkış kodu:** `2` olası ele geçirme, `1` brute force, `0` temiz. Böylece araç bir script'ten veya cron'dan çağrılıp sonucuna göre uyarı üretilebilir.

## Neleri tespit eder

| Tespit | Nasıl |
|---|---|
| Brute force | Aynı IP'den kayan zaman penceresi içinde eşiği aşan başarısız denemeler |
| **Olası ele geçirme** | Başarısız denemelerden sonra aynı IP'den gelen başarılı giriş |
| Kullanıcı adı denemeleri | Sunucuda olmayan kullanıcı adlarıyla yapılan girişler |
| Şüpheli `sudo` | `/etc/shadow` okuma, shell açma, `useradd`, `curl \| sh`, `history -c` gibi komutlar |
| Reddedilen `sudo` / `su` | Yetkisi olmayan kullanıcıların denemeleri |
| Hesap değişiklikleri | Yeni kullanıcılar, silinen kullanıcılar, parola değişiklikleri, `sudo`/`docker` gibi gruplara eklemeler |

**Deneme sayımı:** OpenSSH, var olmayan bir kullanıcıyla yapılan tek deneme için iki satır yazar (`Invalid user` ve `Failed password for invalid user`). Araç bunları aynı bağlantı (IP ve port) üzerinden eşleyip tek deneme sayar. Aynı bağlantıda denenen birden fazla parola ise ayrı denemeler olarak sayılır.

## MITRE ATT&CK eşlemesi

Eşleme kuralları [mitre.py](mitre.py) dosyasındadır. Rapordaki her teknik MITRE sayfasına bağlanır.

| Bulgu | Teknik |
|---|---|
| Brute force | T1110.001 Password Guessing |
| Başarısız denemelerden sonra başarılı giriş | T1078.003 Local Accounts, T1021.004 SSH |
| `sudo` ile `/etc/shadow` okuma | T1003.008 /etc/passwd and /etc/shadow |
| `sudo` ile shell, Python veya Perl çalıştırma | T1059.004, T1059.006, T1059 |
| Reddedilen `sudo` | T1548.003 Sudo and Sudo Caching |
| Yeni kullanıcı | T1136.001 Local Account |
| Yetkili gruba ekleme, parola değişikliği | T1098 Account Manipulation |
| Komut geçmişini silme, firewall kurallarını temizleme | T1070.003, T1562.004 |
| `wget`/`curl` ile dosya indirme, `nc` | T1105, T1095 |

Bir tekniğin listelenmesi saldırının başarılı olduğunu değil, logda o tekniğe uyan bir iz bulunduğunu gösterir. Reddedilen `sudo` komutları çalışmadığı için yalnızca deneme (T1548.003) olarak sayılır.

## Sigma kuralları

[sigma/](sigma/) klasöründeki kurallar, aynı tespitleri bir SIEM'de (Splunk, Elastic, Wazuh vb.) çalıştırmak içindir. Hepsi `sigma check` ile doğrulandı ve örnek loglarda beklenen satırları yakalıyor.

| Kural | Teknik | Seviye |
|---|---|---|
| [lnx_sshd_invalid_user](sigma/lnx_sshd_invalid_user.yml) | T1110.001 | low |
| [lnx_sudo_not_in_sudoers](sigma/lnx_sudo_not_in_sudoers.yml) | T1548.003 | medium |
| [lnx_sudo_shadow_access](sigma/lnx_sudo_shadow_access.yml) | T1003.008 | high |
| [lnx_useradd_new_user](sigma/lnx_useradd_new_user.yml) | T1136.001 | low |
| [lnx_user_added_to_privileged_group](sigma/lnx_user_added_to_privileged_group.yml) | T1098 | medium |

```bash
pip install sigma-cli
sigma check sigma/
```

## Testler

```bash
python -m unittest -v
```

14 test; deneme sayımını, brute force eşiğini, olası ele geçirme tespitini ve MITRE ATT&CK eşlemesini kontrol eder.

## Proje yapısı

```text
analyzer.py        Log ayrıştırma, tespitler ve raporlama
mitre.py           Bulgu → MITRE ATT&CK teknik eşlemesi
make_sample.py     Sentetik test logu üretici
samples/           Örnek (sentetik) auth.log dosyaları
sigma/             SIEM için Sigma kuralları
tests/             Birim testleri
```

## Örnek veri

`samples/` içindeki loglar gerçek bir sunucudan alınmamıştır; test için hazırlanmış **sentetik** dosyalardır. IP adresleri dokümantasyon için ayrılmış aralıklardan (RFC 5737) seçilmiştir.

- `samples/auth.log`: elle yazılmış kısa senaryo
- `samples/generated.log`: `python make_sample.py` ile üretilir

## Sınırlamalar

- Debian/Ubuntu `auth.log` biçimi için yazıldı ve onunla test edildi. RHEL/CentOS'taki `/var/log/secure` aynı syslog biçimini kullanır, ancak ne o ne de `journalctl` çıktısı test edildi.
- Sigma kuralları tek tek log satırlarına bakar. Brute force tespiti IP alanının ayrıştırılmasını gerektirdiği için analizörde yapılır.
- SIEM'ler büyük/küçük harfe duyarsız aradığından `Invalid user` kuralı aynı denemenin ikinci satırıyla da eşleşebilir. Deneme sayımı analizörde tekilleştirilir.
