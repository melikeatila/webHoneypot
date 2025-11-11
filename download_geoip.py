import requests
import tarfile
import os


print("GeoLite2-City veritabanı indiriliyor...")


url = "https://download.db-ip.com/free/dbip-city-lite-2024-10.mmdb.gz"

try:
    response = requests.get(url, timeout=30)
    
    if response.status_code == 200:
        
        with open('dbip-city-lite.mmdb.gz', 'wb') as f:
            f.write(response.content)
        
        
        import gzip
        import shutil
        
        with gzip.open('dbip-city-lite.mmdb.gz', 'rb') as f_in:
            with open('GeoLite2-City.mmdb', 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        
        os.remove('dbip-city-lite.mmdb.gz')
        
        print(" GeoIP veritabanı başarıyla indirildi: GeoLite2-City.mmdb")
        print(f"Dosya boyutu: {os.path.getsize('GeoLite2-City.mmdb') / 1024 / 1024:.2f} MB")
    else:
        print(f" İndirme başarısız: HTTP {response.status_code}")
        print("\nAlternatif çözüm: Manuel indirme")
        print("1. https://db-ip.com/db/download/ip-to-city-lite adresinden indirebilirsiniz")
        print("2. Veya MaxMind'a kaydolup: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        
except Exception as e:
    print(f" Hata: {e}")
    print("\nAlternatif: ip-api.com ücretsiz API kullanacağız (dakikada 45 istek limiti)")
