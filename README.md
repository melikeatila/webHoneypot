Proje yolu -> PS C:\Users\melik\projects\honeypot\web\app
# PROJEYİ BAŞLATMAK İÇİN
1.Docker çalıştır
2.TERMİNALDE
.\.venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload --port 5001
 
# TEKNOLOJİ LİSTESİ
1.BACKEND
FastAPI - Modern web framework
Uvicorn - ASGI sunucusu (FastAPI için lazım)
Python 3.12.6

2.VERİTABANI
SQLite - Dosya tabanlı veritabanı (honeypot.db)
SQLAlchemy Core - Veritabanı ORM, SQL sorguları

3.VERİ ANALİZİ
Pandas - SQL verilerini DataFrame'e çevirme, gruplama, analiz
Scikit-learn - Makine öğrenmesi kütüphanesi (Isolation Forest - Anomali tespiti algoritması (saldırgan IP'leri bulur))

4.GÜVENLİK
SlowAPI - Rate limiting (dakikada 5 istek sınırı)
Custom Middleware - IP filtreleme, istek loglama
Hashlib - SHA256 hash (şifre maskeleme)

5.COĞRAFYA VE ZAMAN
Pytz - Timezone (UTC - Türkiye saati dönüşümü)
Requests - HTTP istekleri (GeoIP API'ye bağlanır)
ip-api.com - Ücretsiz IP lokasyon servisi (ülke, şehir, koordinat)

6.GERÇEK ZAMANLI İLETİŞİM
WebSocket - Anlık bildirimler (dashboard'a canlı veri akışı)
ConnectionManager - WebSocket bağlantı yönetimi

7.FRONTEND VE GÖRSELLEŞTİRME
Chart.js 4.4.0 - 7 farklı interaktif grafik (timeline, pie, bar, doughnut)
Vanilla JavaScript - Modern ES6+ (fetch API, async/await, WebSocket)
HTML5 
CSS3 

8.GELİŞTİRME ARAÇLARI
Docker - Container'da çalıştırma
Docker Compose - Servisleri yönetme
Virtual Environment (.venv) - İzole Python ortamı
Logging - Hata ve olay kaydı

9.SALDIRI TESPİT SİSTEMLERİ
SQL Injection Detection - Pattern matching (SELECT, UNION, DROP, OR 1=1)
XSS Detection - HTML tag tespiti 
Path Traversal Detection - Directory climbing (../, ..)
Brute Force Detection - Rate limiting + deneme sayısı
File Upload Analysis - SHA256 hash, boyut, content type


# Honeypot Özellikleri
- Hiçbir veri çalıştırılmaz (SQL, komut, script asla)
- Dosyalar saklanmaz (sadece hash tutulur)
- Sahte yanıtlar 
- Ağ izolasyonu (Docker network)

