# auth-log-analyzer

Linux `auth.log` dosyalarını tarayıp şüpheli SSH ve yetki aktivitesini raporlayan bir komut satırı aracı.
Yalnızca Python standart kütüphanesini kullanır (GeoIP isteğe bağlıdır).

## Neleri tespit eder

- Brute force: aynı IP'den kayan pencere içinde eşiği aşan başarısız denemeler
- **Olası ele geçirme:** başarısız denemelerden sonra aynı IP'den gelen başarılı giriş
- Var olmayan kullanıcı adlarıyla denemeler
- Şüpheli `sudo` komutları (`/etc/shadow`, shell açma, `useradd` vb.) ve reddedilen `sudo`
- `su` denemeleri, yeni kullanıcılar ve hassas gruplara (`sudo`, `docker` vb.) eklemeler

## MITRE ATT&CK eşlemesi

Bulgular, rapordaki **MITRE ATT&CK** bölümünde tekniklere eşlenir (terminal, JSON ve HTML çıktısında).
Eşleme kuralları [mitre.py](mitre.py) dosyasındadır.

| Bulgu | Teknik |
|---|---|
| Brute force | T1110.001 Password Guessing |
| Başarısız denemelerden sonra başarılı giriş | T1078.003 Local Accounts, T1021.004 SSH |
| `sudo` ile `/etc/shadow` okuma | T1003.008 /etc/passwd and /etc/shadow |
| `sudo` ile shell, Python veya Perl çalıştırma | T1059.004, T1059.006, T1059 |
| Reddedilen `sudo` | T1548.003 Sudo and Sudo Caching |
| Yeni kullanıcı | T1136.001 Local Account |
| Hassas gruba ekleme, parola değişikliği | T1098 Account Manipulation |
| Komut geçmişini silme, firewall kurallarını temizleme | T1070.003, T1562.004 |
| `wget`/`curl` ile dosya indirme, `nc` | T1105, T1095 |

Bir tekniğin listelenmesi saldırının başarılı olduğunu değil, logda o tekniğe uyan bir iz bulunduğunu gösterir.
Reddedilen `sudo` komutları çalışmadığı için yalnızca deneme (T1548.003) olarak sayılır.

## Kullanım

```bash
python analyzer.py /var/log/auth.log
python analyzer.py auth.log auth.log.1 auth.log.2.gz --threshold 10 --window 5
python analyzer.py /var/log/auth.log --outdir raporlar
```

`--outdir`, HTML rapor, JSON rapor ve blocklist dosyalarını tarih-saat damgalı adlarla aynı klasöre yazar.
Ayrı ayrı yazmak için `--html`, `--json` ve `--blocklist` kullanılabilir.
IP'lerin ülkesini görmek için `--geoip-db GeoLite2-Country.mmdb` verilebilir (`pip install geoip2`); IP'ler dışarı gönderilmez.

Çıkış kodu: `2` olası ele geçirme, `1` brute force, `0` temiz.

## Örnek veri

`samples/` içindeki loglar gerçek bir sunucudan alınmamıştır, test için hazırlanmış **sentetik** dosyalardır.
IP adresleri dokümantasyon için ayrılmış aralıklardan (RFC 5737) seçilmiştir.

- `samples/auth.log`: elle yazılmış kısa senaryo
- `samples/generated.log`: `python make_sample.py samples/generated.log` ile üretilir

## Testler

```bash
python -m unittest -v
```

Testler; deneme sayımını (geçersiz kullanıcı, aynı bağlantıda birden fazla parola), brute force eşiğini, olası ele geçirme tespitini ve MITRE ATT&CK eşlemesini kontrol eder.

## Yapılacaklar

- [x] Bulguların MITRE ATT&CK tekniklerine eşlenmesi
- [ ] Sigma kuralları
- [x] Testler
