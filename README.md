# auth-log-analyzer

Linux `auth.log` dosyalarını tarayıp şüpheli SSH ve yetki aktivitesini raporlayan bir komut satırı aracı.
Yalnızca Python standart kütüphanesini kullanır (GeoIP isteğe bağlıdır).

## Neleri tespit eder

- Brute force: aynı IP'den kayan pencere içinde eşiği aşan başarısız denemeler
- **Olası ele geçirme:** başarısız denemelerden sonra aynı IP'den gelen başarılı giriş
- Var olmayan kullanıcı adlarıyla denemeler
- Şüpheli `sudo` komutları (`/etc/shadow`, shell açma, `useradd` vb.) ve reddedilen `sudo`
- `su` denemeleri, yeni kullanıcılar ve hassas gruplara (`sudo`, `docker` vb.) eklemeler

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

## Yapılacaklar

- [ ] Bulguların MITRE ATT&CK tekniklerine eşlenmesi
- [ ] Sigma kuralları
- [ ] Testler
