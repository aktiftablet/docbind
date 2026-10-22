# DocBind kullanım kılavuzu

Güncel API sözleşmesi, kurulum, ortam değişkenleri, veritabanı geçişi ve SDK örnekleri [README.md](./README.md) içindedir.

## Güvenlik ve cihaz bağı

Belge, hedef cihazın değiştirilemeyen açık anahtarına mühürlenir. Yalnızca eşleşen özel anahtar belge anahtarını çözebilir. Aynı donanım hash'ini göndermek başka bir cihazın kaydını güncellemez; farklı anahtar ayrı cihaz ID'si alır. İptal edilmiş anahtar yeniden etkinleştirilemez. Hash yalnızca tanılama verisidir; zoom, ekran veya saat dilimi değişimi cihaz kimliğini değiştirmez.

Android donanım destekli Keystore gerektirir. iOS RSA anahtarını Keychain'de saklar; Secure Enclave kullanılmaz. Web'de anahtar IndexedDB içinde dışa aktarılamayan WebCrypto anahtarıdır. Sunucuda donanım attestation doğrulaması bulunmaz; tüm platformlar için fiziksel cihaz garantisi verilmez.

## Yetkiler

- Organizasyon oluşturma, ayrı `x-provisioning-key` gerektirir. Varsayılan geliştirme anahtarı ve kimlik doğrulama fallback'i kaldırılmıştır.
- Organizasyonun `x-api-key` değeri yalnızca güvenilir uygulama sunucusunda tutulur. İstemciye verilmez.
- Uygulama sunucusu kendi kullanıcısını doğrular ve cihazın public key'i için kısa ömürlü `enrollment_token` ister.
- SDK bu token ile kaydolur; dönen `device_token` yalnızca o aktif cihazın şifreli belgelerine erişir. Belge mühürleyemez ve cihaz iptal edemez.
- Cihaz token'ı bir saat geçerlidir. Süresi dolmadan aynı anahtarla kayıt çağrısı yenilenebilir; süre dolduğunda sunucudan yeniden kayıt onayı alınmalıdır.

## Sınırlar

Sunucu mühürleme sırasında açık dosyayı görür; mimari zero-knowledge değildir. İptal, daha önce indirilmiş belge veya açık kopyaları silemez. Özel anahtar kaybolursa eski belgeler kurtarılamaz. Ekran yakalama önlemleri platforma bağlıdır; özellikle web'de işletim sistemi ekran görüntüsü engellenemez.

Üretim için PostgreSQL, özel S3 bucket'ı, kalıcı token imzalama sırrı, TLS ve uygun kota/hız sınırları gerekir. Bellek adaptörleri yalnızca geliştirme/test içindir ve yeniden başlatmada veri kaybeder. Dağıtımdan önce gerçek veritabanı/S3 entegrasyonu ve iOS/Android cihaz testleri ayrıca çalıştırılmalıdır.
