# auth-log-analyzer

Linux `auth.log` dosyalarını tarayıp şüpheli SSH aktivitesini raporlayan bir komut satırı aracı.

> Proje geliştirme aşamasında.

## Planlanan özellikler

- [ ] Başarısız SSH girişlerini ayrıştırma
- [ ] Brute force tespiti (kısa sürede çok sayıda başarısız deneme)
- [ ] Başarısız denemelerden sonra gelen başarılı giriş tespiti
- [ ] Var olmayan kullanıcı adlarıyla deneme (user enumeration) tespiti
- [ ] `sudo` kullanımı ve yetki yükseltme denemeleri
- [ ] Bulguların MITRE ATT&CK tekniklerine eşlenmesi
- [ ] Sigma kuralları
- [ ] Rapor çıktısı (terminal + JSON)

## Örnek veri

`samples/auth.log` gerçek bir sunucudan alınmamıştır; test için elle hazırlanmış **sentetik** bir dosyadır.
IP adresleri, dokümantasyon için ayrılmış aralıklardan (RFC 5737) seçilmiştir.
