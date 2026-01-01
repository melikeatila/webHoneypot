
from fastapi import FastAPI, Request, Form, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta
from sqlalchemy import insert, select, func
from contextlib import asynccontextmanager
import logging
import pandas as pd
import asyncio
import json
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import pytz
import requests
import hashlib


from db import init_db, engine, admin_login_attempts, search_logs, upload_logs, contact_submissions, bait_clicks, command_executions, request_logs
from utils import mask_password, sha256_hex_bytes, sha256_hex_str, mask_email, mask_phone


try:
    from logger_middleware import LoggerMiddleware
except ImportError:
    LoggerMiddleware = None

try:
    from ip_filter_middleware import IPFilterMiddleware
except ImportError:
    IPFilterMiddleware = None


try:
    from websocket_manager import manager as ws_manager
    from websocket_manager import broadcast_bait_click, broadcast_admin_attempt, broadcast_upload
except ImportError:
    ws_manager = None
    broadcast_bait_click = None
    broadcast_admin_attempt = None
    broadcast_upload = None


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    
    try:
        dbpath = init_db()
        logger.info(f'[startup] DB ready: {dbpath}')
    except Exception as e:
        logger.error(f'[startup] DB init failed: {e}')
    
    yield
    
    
    logger.info('[shutdown] Application shutting down gracefully')


TURKEY_TZ = pytz.timezone('Europe/Istanbul')

def to_turkey_time(timestamp_str):
    """Convert UTC timestamp to Turkey time"""
    try:
        
        if isinstance(timestamp_str, str):
            dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
        else:
            dt = timestamp_str
        
        
        utc_dt = pytz.utc.localize(dt) if dt.tzinfo is None else dt
        turkey_dt = utc_dt.astimezone(TURKEY_TZ)
        return turkey_dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(timestamp_str)

def get_ip_location(ip):
    """Get real geolocation for IP address using ip-api.com (free, no key needed)"""
    try:
        
        if ip.startswith('127.') or ip == '::1' or ip == 'localhost':
            return {
                'country': 'Localhost',
                'city': 'Local Machine',
                'lat': 39.9334,  
                'lon': 32.8597,
                'status': 'local'
            }
        
        
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return {
                'country': 'Private Network',
                'city': 'LAN',
                'lat': 39.9334,
                'lon': 32.8597,
                'status': 'private'
            }
        
    
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon', timeout=2)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'status': 'success'
                }
        
       
        hash_val = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'lat': (hash_val % 180) - 90,  # -90 to 90
            'lon': (hash_val // 180 % 360) - 180,  # -180 to 180
            'status': 'fallback'
        }
        
    except Exception as e:
        logger.error(f"GeoIP error for {ip}: {e}")
        
        hash_val = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'lat': (hash_val % 180) - 90,
            'lon': (hash_val // 180 % 360) - 180,
            'status': 'error'
        }


app = FastAPI(title="OatsHobby Honeypot", lifespan=lifespan)


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)



BLOCKED_IPS = [
   
]


ALLOWED_IPS = [
    "127.0.0.1",  
    
]


if IPFilterMiddleware:
    app.add_middleware(
        IPFilterMiddleware,
        blocked_ips=BLOCKED_IPS,
        allowed_ips=ALLOWED_IPS,
        whitelist_mode=False,  
        exempt_paths=['/api/info', '/health', '/']
    )
    logger.info("IPFilterMiddleware added")

if LoggerMiddleware:
    app.add_middleware(LoggerMiddleware)
    logger.info("LoggerMiddleware added")


api = FastAPI()

@api.get('/info', response_class=HTMLResponse)
async def home_info():
    """Info sayfası"""
    return FileResponse('static/info.html')


@api.get('/robots.txt')
async def robots_txt(request: Request):
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    
    
    try:
        stmt = insert(request_logs).values(
            ip=ip, method='GET', path='/robots.txt', 
            user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.info(f"robots.txt requested from {ip}")
    except Exception as e:
        logger.error(f"DB error logging robots.txt: {e}")
    
    return HTMLResponse("""User-agent: *
Allow: /
Disallow: /cart/checkout
Disallow: /account/
Disallow: /search?
Disallow: /wishlist/

# Block bad bots
User-agent: AhrefsBot
Disallow: /

User-agent: SemrushBot
Disallow: /

# Sitemap
Sitemap: http://oatshobby.com/sitemap.xml
""", media_type="text/plain")


@api.get('/sitemap.xml')
async def sitemap_xml(request: Request):
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    
   
    try:
        stmt = insert(request_logs).values(
            ip=ip, method='GET', path='/sitemap.xml', 
            user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.info(f"sitemap.xml requested from {ip}")
    except Exception as e:
        logger.error(f"DB error logging sitemap.xml: {e}")
    
    return HTMLResponse("""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>http://oatshobby.com/</loc>
    <lastmod>2024-11-01</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>http://oatshobby.com/store.html</loc>
    <lastmod>2024-11-01</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>http://oatshobby.com/about.html</loc>
    <lastmod>2024-10-15</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>http://oatshobby.com/contact.html</loc>
    <lastmod>2024-10-15</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>http://oatshobby.com/reviews.html</loc>
    <lastmod>2024-10-20</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.6</priority>
  </url>
</urlset>
""", media_type="application/xml")


@api.get('/docs')
async def api_docs(request: Request):
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    
    
    try:
        stmt = insert(request_logs).values(
            ip=ip, method='GET', path='/api/docs', 
            user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.info(f"API docs requested from {ip}")
    except Exception as e:
        logger.error(f"DB error logging docs: {e}")
    
    return FileResponse('static/api_docs.html')

@api.get('/admin/login', response_class=HTMLResponse)
async def admin_login_page():
    """Admin login sayfası"""
    return FileResponse('static/admin_login.html')

@api.post('/admin/login')
@limiter.limit("5/minute")
async def admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    pwd_mask = mask_password(password)
    
    try:
        stmt = insert(admin_login_attempts).values(
            ip=ip, username=username, password_mask=pwd_mask, user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.info(f"Admin login attempt: {username} from {ip}")
        
        
        if broadcast_admin_attempt:
            asyncio.create_task(broadcast_admin_attempt(ip, username, success=False))
            
    except Exception as e:
        logger.error(f"DB error: {e}")
    
    return JSONResponse({'status': 'error', 'message': 'Invalid credentials'}, status_code=401)


@api.get('/upload')
async def upload_page():
    return FileResponse('static/upload.html')

@api.post('/upload')
@limiter.limit("5/minute")
async def upload_file(request: Request, file: UploadFile = File(...)):
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    filename = file.filename or 'unknown'
    content_type = file.content_type or 'unknown'
    
   
    content = await file.read()
    file_size = len(content)
    
    try:
        import hashlib
        file_hash = hashlib.sha256(content).hexdigest()
    except:
        file_hash = 'unknown'
    
    try:
        stmt = insert(upload_logs).values(
            ip=ip,
            filename=filename,
            content_type=content_type,
            file_size=file_size,
            file_hash=file_hash,
            user_agent=ua,
            timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.warning(f"Upload attempt: {filename} ({file_size} bytes) from {ip}")
        
        
        if broadcast_upload:
            asyncio.create_task(broadcast_upload(ip, filename, file_size))
            
    except Exception as e:
        logger.error(f"DB upload error: {e}")
        import traceback
        traceback.print_exc()
    
    return JSONResponse({
        'status': 'success',
        'message': 'File uploaded successfully',
        'filename': filename,
        'size': file_size
    })


@api.get('/stats')
async def get_stats():
    try:
        with engine.begin() as conn:
            total_req = conn.execute(select(func.count()).select_from(request_logs)).scalar()
            unique_ips = conn.execute(select(func.count(func.distinct(request_logs.c.ip))).select_from(request_logs)).scalar()
            admin_attempts = conn.execute(select(func.count()).select_from(admin_login_attempts)).scalar()
            bait_count = conn.execute(select(func.count()).select_from(bait_clicks)).scalar()
            
        stats = {
            'total_requests': total_req or 0,
            'unique_ips': unique_ips or 0,
            'admin_attempts': admin_attempts or 0,
            'bait_clicks': bait_count or 0
        }
        return JSONResponse(stats)
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)


@api.get('/ai/anomalies')
async def get_ai_anomalies():

    try:
        import pandas as pd
        from sklearn.ensemble import IsolationForest
        from datetime import timedelta
        
        
        with engine.begin() as conn:
           
            query = """
                SELECT 
                    ip,
                    COUNT(*) as request_count,
                    COUNT(DISTINCT path) as unique_paths,
                    MAX(timestamp) as last_seen
                FROM request_logs
                GROUP BY ip
                HAVING request_count > 1
            """
            df = pd.read_sql_query(query, conn)
        
        if len(df) == 0:
            return JSONResponse({
                'total_anomalies': 0,
                'anomaly_percentage': 0,
                'anomalies': [],
                'message': 'Henüz veri bulunamadı'
            })
        
        
        if len(df) < 3:
           
            anomalies = []
            for _, row in df.iterrows():
                if row['request_count'] > 3 or row['unique_paths'] > 2:
                    anomalies.append({
                        'ip': row['ip'],
                        'request_count': int(row['request_count']),
                        'unique_paths': int(row['unique_paths']),
                        'anomaly_score': -0.8,  
                        'timestamp': to_turkey_time(str(row['last_seen']))
                    })
            
            return JSONResponse({
                'total_anomalies': len(anomalies),
                'anomaly_percentage': (len(anomalies) / len(df) * 100) if len(df) > 0 else 0,
                'anomalies': anomalies,
                'model': 'SimpleThreshold',
                'message': 'Basit kural tabanlı tespit (az veri nedeniyle)'
            })
        
        
        features = df[['request_count', 'unique_paths']].values
        
       
        iso_forest = IsolationForest(
            contamination=0.15,  
            n_estimators=100,
            random_state=42
        )
        predictions = iso_forest.fit_predict(features)
        scores = iso_forest.score_samples(features)
        
        df['anomaly_score'] = scores
        df['is_anomaly'] = predictions == -1
        
      
        anomalies = df[df['is_anomaly']].sort_values('anomaly_score')
        
        anomaly_list = []
        for _, row in anomalies.iterrows():
            anomaly_list.append({
                'ip': row['ip'],
                'request_count': int(row['request_count']),
                'unique_paths': int(row['unique_paths']),
                'anomaly_score': float(row['anomaly_score']),
                'timestamp': to_turkey_time(str(row['last_seen']))
            })
        
        return JSONResponse({
            'total_anomalies': int(df['is_anomaly'].sum()),
            'anomaly_percentage': float(df['is_anomaly'].sum() / len(df) * 100),
            'anomalies': anomaly_list,
            'model': 'IsolationForest',
            'features': ['request_count', 'unique_paths']
        })
        
    except Exception as e:
        logger.error(f"AI anomaly detection error: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)


@api.get('/activity/recent')
async def get_recent_activity():
    """Get recent honeypot activity"""
    try:
        activities = []
        
        with engine.begin() as conn:
            
            bait_query = """
                SELECT ip, bait_path as path, timestamp, 'bait' as type
                FROM bait_clicks
                ORDER BY timestamp DESC
                LIMIT 5
            """
            bait_df = pd.read_sql_query(bait_query, conn)
            for _, row in bait_df.iterrows():
                activities.append({
                    'type': 'bait',
                    'title': f'Bait endpoint accessed: {row["path"]}',
                    'ip': row['ip'],
                    'timestamp': to_turkey_time(str(row['timestamp']))
                })
            
            
            xss_query = """
                SELECT ip, username, password_mask, timestamp, 'xss' as type
                FROM admin_login_attempts
                WHERE (username LIKE '%<script%' OR username LIKE '%<img%' OR username LIKE '%<svg%'
                       OR username LIKE '%onerror%' OR username LIKE '%onload%'
                       OR password_mask LIKE '%<script%' OR password_mask LIKE '%<img%'
                       OR password_mask LIKE '%<svg%' OR password_mask LIKE '%onerror%' OR password_mask LIKE '%onload%')
                ORDER BY timestamp DESC
                LIMIT 10
            """
            try:
                xss_df = pd.read_sql_query(xss_query, conn)
                for _, row in xss_df.iterrows():
                    
                    xss_payload = row["username"]
                    if '<' in str(row["password_mask"]):
                        xss_payload = f"pwd field"
                    
                    
                    xss_clean = xss_payload.replace('<', '&lt;').replace('>', '&gt;')
                    
                    activities.append({
                        'type': 'xss',
                        'title': f'XSS Injection: {xss_clean[:30]}...',
                        'ip': row['ip'],
                        'timestamp': to_turkey_time(str(row['timestamp']))
                    })
            except Exception as e:
                logger.error(f"XSS query error: {e}")
            
           
            brute_query = """
                SELECT ip, username, password_mask, timestamp, 'brute_force' as type
                FROM admin_login_attempts
                WHERE NOT (username LIKE '%<script%' OR username LIKE '%<img%' OR username LIKE '%<svg%'
                       OR username LIKE '%onerror%' OR username LIKE '%onload%'
                       OR password_mask LIKE '%<script%' OR password_mask LIKE '%<img%'
                       OR password_mask LIKE '%<svg%' OR password_mask LIKE '%onerror%' OR password_mask LIKE '%onload%')
                AND NOT (username LIKE '%SELECT%' OR username LIKE '%UNION%' OR username LIKE '%DROP%'
                       OR username LIKE '%INSERT%' OR username LIKE '%DELETE%' OR username LIKE '%UPDATE%'
                       OR username LIKE '%OR%1%1%' OR username LIKE '%''%' OR username LIKE '%--%'
                       OR username LIKE "%;%")
                ORDER BY timestamp DESC
                LIMIT 10
            """
            try:
                brute_df = pd.read_sql_query(brute_query, conn)
                for _, row in brute_df.iterrows():
                    activities.append({
                        'type': 'brute_force',
                        'title': f'Brute Force: user={row["username"]}, pwd={row["password_mask"]}',
                        'ip': row['ip'],
                        'timestamp': to_turkey_time(str(row['timestamp']))
                    })
            except Exception as e:
                logger.error(f"Brute force query error: {e}")
            
           
            search_query = """
                SELECT ip, query, timestamp, 'search' as type
                FROM search_logs
                ORDER BY timestamp DESC
                LIMIT 5
            """
            search_df = pd.read_sql_query(search_query, conn)
            for _, row in search_df.iterrows():
                activities.append({
                    'type': 'search',
                    'title': f'Search query: {row["query"][:50]}',
                    'ip': row['ip'],
                    'timestamp': to_turkey_time(str(row['timestamp']))
                })
            
           
            suspicious_query = """
                SELECT ip, path, timestamp, 'suspicious' as type
                FROM request_logs
                WHERE path IN ('/robots.txt', '/sitemap.xml', '/api/docs')
                ORDER BY timestamp DESC
                LIMIT 5
            """
            suspicious_df = pd.read_sql_query(suspicious_query, conn)
            for _, row in suspicious_df.iterrows():
                activities.append({
                    'type': 'suspicious',
                    'title': f'Suspicious path accessed: {row["path"]}',
                    'ip': row['ip'],
                    'timestamp': to_turkey_time(str(row['timestamp']))
                })
            
           
            api_query = """
                SELECT ip, path, timestamp, 'api_discovery' as type
                FROM request_logs
                WHERE path LIKE '/api/%'
                AND path NOT LIKE '/api/activity%'
                AND path NOT LIKE '/api/admin%'
                AND path NOT LIKE '/api/ai%'
                AND path NOT LIKE '/api/charts%'
                AND path NOT LIKE '/api/stats%'
                ORDER BY timestamp DESC
                LIMIT 10
            """
            try:
                api_df = pd.read_sql_query(api_query, conn)
                for _, row in api_df.iterrows():
                    activities.append({
                        'type': 'api_discovery',
                        'title': f'API Discovery: {row["path"]}',
                        'ip': row['ip'],
                        'timestamp': to_turkey_time(str(row['timestamp']))
                    })
            except Exception as e:
                logger.error(f"API discovery query error: {e}")
            
            
            traversal_query = """
                SELECT ip, path, timestamp, 'traversal' as type
                FROM request_logs
                WHERE (path LIKE '%../%' OR path LIKE '%..\\%')
                ORDER BY timestamp DESC
                LIMIT 5
            """
            traversal_df = pd.read_sql_query(traversal_query, conn)
            for _, row in traversal_df.iterrows():
                activities.append({
                    'type': 'traversal',
                    'title': f'Path Traversal: {row["path"]}',
                    'ip': row['ip'],
                    'timestamp': to_turkey_time(str(row['timestamp']))
                })
            
            
            sqli_query = """
                SELECT ip, query as payload, timestamp, 'sqli' as type
                FROM search_logs
                WHERE (query LIKE '%SELECT%' OR query LIKE '%UNION%' OR query LIKE '%DROP%'
                       OR query LIKE '%INSERT%' OR query LIKE '%DELETE%' OR query LIKE '%UPDATE%'
                       OR query LIKE '%OR 1=1%' OR query LIKE '%''%' OR query LIKE '%---%')
                ORDER BY timestamp DESC
                LIMIT 5
            """
            try:
                sqli_df = pd.read_sql_query(sqli_query, conn)
                for _, row in sqli_df.iterrows():
                    activities.append({
                        'type': 'sqli',
                        'title': f'SQL Injection: {row["payload"][:40]}...',
                        'ip': row['ip'],
                        'timestamp': to_turkey_time(str(row['timestamp']))
                    })
            except:
                pass  
            
           
            sqli_admin_query = """
                SELECT ip, username as payload, timestamp, 'sqli' as type
                FROM admin_login_attempts
                WHERE (username LIKE '%SELECT%' OR username LIKE '%UNION%' OR username LIKE '%DROP%'
                       OR username LIKE '%INSERT%' OR username LIKE '%DELETE%' OR username LIKE '%UPDATE%'
                       OR username LIKE '%OR%1%1%' OR username LIKE '%''%' OR username LIKE '%--%'
                       OR username LIKE "%;%")
                AND NOT (username LIKE '%<script%' OR username LIKE '%<img%' OR username LIKE '%<svg%')
                ORDER BY timestamp DESC
                LIMIT 10
            """
            try:
                sqli_admin_df = pd.read_sql_query(sqli_admin_query, conn)
                for _, row in sqli_admin_df.iterrows():
                    activities.append({
                        'type': 'sqli',
                        'title': f'SQL Injection: {row["payload"][:40]}...',
                        'ip': row['ip'],
                        'timestamp': to_turkey_time(str(row['timestamp']))
                    })
            except Exception as e:
                logger.error(f"SQL injection admin query error: {e}")
        
        
        upload_query = """
            SELECT ip, filename, file_size, timestamp, 'upload' as type
            FROM upload_logs
            ORDER BY timestamp DESC
            LIMIT 10
        """
        try:
            upload_df = pd.read_sql_query(upload_query, conn)
            for _, row in upload_df.iterrows():
                file_size_kb = row['file_size'] / 1024
                size_str = f"{file_size_kb:.1f}KB" if file_size_kb < 1024 else f"{file_size_kb/1024:.1f}MB"
                activities.append({
                    'type': 'upload',
                    'title': f'File Upload: {row["filename"]} ({size_str})',
                    'ip': row['ip'],
                    'timestamp': to_turkey_time(str(row['timestamp']))
                })
        except Exception as e:
            logger.error(f"Upload query error: {e}")
        
       
        activities.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return JSONResponse({
            'activities': activities[:15],
            'count': len(activities)
        })
        
    except Exception as e:
        logger.error(f"Activity feed error: {e}")
        return JSONResponse({'error': str(e), 'activities': []}, status_code=500)


@api.get('/ai/patterns')
async def get_attack_patterns():
    """Analyze attack patterns using AI"""
    try:
        patterns = []
        
        with engine.begin() as conn:
            
            sqli_search_count = conn.execute(
                select(func.count()).select_from(search_logs).where(
                    search_logs.c.query.like('%SELECT%') | 
                    search_logs.c.query.like('%UNION%') |
                    search_logs.c.query.like('%DROP%')
                )
            ).scalar()
            
            sqli_admin_count = conn.execute(
                select(func.count()).select_from(admin_login_attempts).where(
                    (
                        admin_login_attempts.c.username.like('%SELECT%') |
                        admin_login_attempts.c.username.like('%UNION%') |
                        admin_login_attempts.c.username.like('%DROP%') |
                        admin_login_attempts.c.username.like('%OR%1%1%') |
                        admin_login_attempts.c.username.like('%--%')
                    ) &
                    ~(
                        admin_login_attempts.c.username.like('%<script%') |
                        admin_login_attempts.c.username.like('%<img%') |
                        admin_login_attempts.c.username.like('%<svg%') |
                        admin_login_attempts.c.username.like('%onerror%') |
                        admin_login_attempts.c.username.like('%onload%')
                    )
                )
            ).scalar()
            
            sqli_count = (sqli_search_count or 0) + (sqli_admin_count or 0)
            
            if sqli_count > 0:
                patterns.append({
                    'type': 'SQL Injection Attempts',
                    'count': sqli_count,
                    'description': f'Detected {sqli_count} potential SQL injection attempts'
                })
            
            
            admin_count = conn.execute(
                select(func.count()).select_from(admin_login_attempts).where(
                    ~(
                        admin_login_attempts.c.username.like('%SELECT%') |
                        admin_login_attempts.c.username.like('%UNION%') |
                        admin_login_attempts.c.username.like('%DROP%') |
                        admin_login_attempts.c.username.like('%OR%1%1%') |
                        admin_login_attempts.c.username.like('%--%') |
                        admin_login_attempts.c.username.like('%<script%') |
                        admin_login_attempts.c.username.like('%<img%') |
                        admin_login_attempts.c.username.like('%<svg%') |
                        admin_login_attempts.c.username.like('%onerror%') |
                        admin_login_attempts.c.username.like('%onload%')
                    )
                )
            ).scalar()
            if admin_count > 0:
                patterns.append({
                    'type': 'Admin Panel Probing',
                    'count': admin_count,
                    'description': f'{admin_count} unauthorized admin login attempts detected'
                })
            
            
            bait_count = conn.execute(select(func.count()).select_from(bait_clicks)).scalar()
            if bait_count > 0:
                patterns.append({
                    'type': 'Honeypot Trap Triggers',
                    'count': bait_count,
                    'description': f'{bait_count} bait endpoints accessed by potential attackers'
                })
            
           
            traversal_count = conn.execute(
                select(func.count()).select_from(request_logs).where(
                    request_logs.c.path.like('%../%') |
                    request_logs.c.path.like('%..\\%')
                )
            ).scalar()
            
            if traversal_count > 0:
                patterns.append({
                    'type': 'Path Traversal Attempts',
                    'count': traversal_count,
                    'description': f'Detected {traversal_count} potential directory traversal attempts'
                })
            
            
            upload_count = conn.execute(select(func.count()).select_from(upload_logs)).scalar()
            if upload_count > 0:
                patterns.append({
                    'type': 'File Upload Attempts',
                    'count': upload_count,
                    'description': f'{upload_count} suspicious file upload attempts detected'
                })
            
            
            xss_count = conn.execute(
                select(func.count()).select_from(admin_login_attempts).where(
                    admin_login_attempts.c.username.like('%<script%') |
                    admin_login_attempts.c.username.like('%<img%') |
                    admin_login_attempts.c.username.like('%<svg%') |
                    admin_login_attempts.c.username.like('%onerror%') |
                    admin_login_attempts.c.username.like('%onload%') |
                    admin_login_attempts.c.password_mask.like('%<script%') |
                    admin_login_attempts.c.password_mask.like('%<img%') |
                    admin_login_attempts.c.password_mask.like('%<svg%')
                )
            ).scalar()
            
            if xss_count > 0:
                patterns.append({
                    'type': 'XSS Injection Attempts',
                    'count': xss_count,
                    'description': f'Detected {xss_count} potential XSS injection attempts'
                })
        
        return JSONResponse({
            'patterns': patterns,
            'total_patterns': len(patterns),
            'analysis_timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Pattern analysis error: {e}")
        return JSONResponse({'error': str(e), 'patterns': []}, status_code=500)


@api.get('/charts/timeline')
async def get_timeline_chart_data():
    """Get 7-day timeline data for charts with real data from all sources"""
    try:
        from datetime import timedelta
        
        
        turkey_tz = pytz.timezone('Europe/Istanbul')
        now_utc = datetime.utcnow()
        now_turkey = pytz.utc.localize(now_utc).astimezone(turkey_tz)
        
        labels = []
        for i in range(7, 0, -1):
            day = now_turkey - timedelta(days=i)
            labels.append(day.strftime('%d %b'))  
        
        
        bait_data = [0] * 7
        admin_data = [0] * 7
        
       
        cutoff_time = now_utc - timedelta(days=7)
        
        with engine.begin() as conn:
            
            bait_stmt = select(bait_clicks.c.timestamp).where(
                bait_clicks.c.timestamp > cutoff_time
            )
            bait_times = [row[0] for row in conn.execute(bait_stmt).fetchall()]
            
            for ts in bait_times:
                if ts:
                    if isinstance(ts, str):
                        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    else:
                        dt = ts
                    
                    if dt.tzinfo is None:
                        dt = pytz.utc.localize(dt)
                    
                    turkey_time = dt.astimezone(turkey_tz)
                    days_ago = (now_turkey.date() - turkey_time.date()).days
                    
                    if 0 <= days_ago < 7:
                        idx = 6 - days_ago
                        if 0 <= idx < 7:
                            bait_data[idx] += 1
            
            
            admin_stmt = select(admin_login_attempts.c.timestamp).where(
                admin_login_attempts.c.timestamp > cutoff_time
            )
            admin_times = [row[0] for row in conn.execute(admin_stmt).fetchall()]
            
            for ts in admin_times:
                if ts:
                    if isinstance(ts, str):
                        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    else:
                        dt = ts
                    
                    if dt.tzinfo is None:
                        dt = pytz.utc.localize(dt)
                    
                    turkey_time = dt.astimezone(turkey_tz)
                    days_ago = (now_turkey.date() - turkey_time.date()).days
                    
                    if 0 <= days_ago < 7:
                        idx = 6 - days_ago
                        if 0 <= idx < 7:
                            admin_data[idx] += 1
        
        return JSONResponse({
            'labels': labels,
            'bait_clicks': bait_data,
            'admin_attempts': admin_data
        })
        
    except Exception as e:
        logger.error(f"Timeline chart error: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)

@api.get('/charts/top-ips')
async def get_top_ips_chart_data():
    """Get top attacking IPs for chart"""
    try:
        with engine.begin() as conn:
            query = """
                SELECT ip, COUNT(*) as count
                FROM request_logs
                GROUP BY ip
                ORDER BY count DESC
                LIMIT 5
            """
            df = pd.read_sql_query(query, conn)
        
        if len(df) == 0:
            return JSONResponse({'labels': ['No data'], 'data': [1]})
        
        return JSONResponse({
            'labels': df['ip'].tolist(),
            'data': df['count'].tolist()
        })
        
    except Exception as e:
        logger.error(f"Top IPs chart error: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)

@api.get('/charts/top-paths')
async def get_top_paths_chart_data():
    """Get most targeted endpoints for chart"""
    try:
        with engine.begin() as conn:
            
            query = """
                SELECT path, COUNT(*) as count
                FROM (
                    SELECT bait_path as path FROM bait_clicks
                    UNION ALL
                    SELECT path FROM request_logs
                    WHERE (path LIKE '%admin%' OR path LIKE '%backup%' OR path LIKE '%config%')
                )
                GROUP BY path
                ORDER BY count DESC
                LIMIT 10
            """
            df = pd.read_sql_query(query, conn)
        
        if len(df) == 0:
            return JSONResponse({'labels': ['No data'], 'data': [1]})
        
        return JSONResponse({
            'labels': df['path'].tolist(),
            'data': df['count'].tolist()
        })
        
    except Exception as e:
        logger.error(f"Top paths chart error: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)

@api.get('/charts/attack-distribution')
async def get_attack_distribution():
    """Get attack type distribution for geographic visualization"""
    try:
        with engine.begin() as conn:
            
            query = """
                SELECT 
                    r.ip,
                    COUNT(DISTINCT r.path) as unique_paths,
                    COUNT(*) as total_requests,
                    MAX(r.timestamp) as last_seen,
                    (SELECT COUNT(*) FROM bait_clicks b WHERE b.ip = r.ip) as bait_count,
                    (SELECT COUNT(*) FROM admin_login_attempts a WHERE a.ip = r.ip) as admin_count
                FROM request_logs r
                GROUP BY r.ip
                ORDER BY total_requests DESC
                LIMIT 20
            """
            df = pd.read_sql_query(query, conn)
        
        if len(df) == 0:
            return JSONResponse({'ips': []})
        
        ips_data = []
        for _, row in df.iterrows():
            ips_data.append({
                'ip': row['ip'],
                'unique_paths': int(row['unique_paths']),
                'total_requests': int(row['total_requests']),
                'bait_count': int(row['bait_count'] or 0),
                'admin_count': int(row['admin_count'] or 0),
                'last_seen': str(row['last_seen']),
                'threat_level': 'high' if row['bait_count'] > 0 or row['admin_count'] > 0 else 'medium'
            })
        
        return JSONResponse({'ips': ips_data, 'count': len(ips_data)})
        
    except Exception as e:
        logger.error(f"Attack distribution error: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)

@api.get('/charts/user-agents')
async def get_user_agents_chart_data():
    """Get User Agent distribution from all logs"""
    try:
        with engine.begin() as conn:
            
            query = """
                SELECT user_agent, COUNT(*) as count
                FROM (
                    SELECT user_agent FROM request_logs
                    WHERE user_agent IS NOT NULL AND user_agent != ''
                    UNION ALL
                    SELECT user_agent FROM bait_clicks
                    WHERE user_agent IS NOT NULL AND user_agent != ''
                    UNION ALL
                    SELECT user_agent FROM admin_login_attempts
                    WHERE user_agent IS NOT NULL AND user_agent != ''
                )
                GROUP BY user_agent
                ORDER BY count DESC
                LIMIT 6
            """
            df = pd.read_sql_query(query, conn)
        
        if len(df) == 0:
            return JSONResponse({'labels': ['No data'], 'data': [1]})
        
       
        def simplify_ua(ua):
            ua = str(ua).lower()
            if 'chrome' in ua and 'edg' not in ua:
                return 'Chrome'
            elif 'firefox' in ua:
                return 'Firefox'
            elif 'safari' in ua and 'chrome' not in ua:
                return 'Safari'
            elif 'edg' in ua:
                return 'Edge'
            elif 'bot' in ua or 'crawler' in ua or 'spider' in ua:
                return 'Bot'
            elif 'curl' in ua or 'wget' in ua or 'python' in ua:
                return 'Script/Tool'
            else:
                return 'Other'
        
        
        df['simplified'] = df['user_agent'].apply(simplify_ua)
        grouped = df.groupby('simplified')['count'].sum().sort_values(ascending=False)
        
        return JSONResponse({
            'labels': grouped.index.tolist(),
            'data': grouped.values.tolist()
        })
        
    except Exception as e:
        logger.error(f"User agents chart error: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)

@api.get('/charts/top-countries')
async def get_top_countries_chart():
    """Get top countries by attack count with real GeoIP data"""
    try:
        with engine.begin() as conn:
           
            query = """
                SELECT ip, COUNT(*) as count
                FROM (
                    SELECT ip FROM request_logs
                    UNION ALL
                    SELECT ip FROM bait_clicks
                    UNION ALL
                    SELECT ip FROM admin_login_attempts
                )
                GROUP BY ip
                ORDER BY count DESC
            """
            df = pd.read_sql_query(query, conn)
        
        if len(df) == 0:
            return JSONResponse({'labels': ['No data'], 'data': [1]})
        
        
        country_counts = {}
        for _, row in df.iterrows():
            ip = row['ip']
            count = row['count']
            
          
            loc_data = get_ip_location(ip)
            country = loc_data['country']
            
            if country not in country_counts:
                country_counts[country] = 0
            country_counts[country] += count
        
        
        sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        labels = [country for country, _ in sorted_countries]
        data = [count for _, count in sorted_countries]
        
       
        filtered_labels = []
        filtered_data = []
        for label, count in zip(labels, data):
            if label not in ['Localhost', 'Private Network', 'Unknown']:
                filtered_labels.append(label)
                filtered_data.append(count)
        
       
        if len(filtered_labels) == 0:
            return JSONResponse({
                'labels': ['Veri Bekleniyor'],
                'data': [0],
                'note': 'Gerçek saldırı verisi bekleniyor'
            })
        
        return JSONResponse({
            'labels': filtered_labels,
            'data': filtered_data
        })
        
    except Exception as e:
        logger.error(f"Top countries chart error: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)

@api.get('/charts/hourly-pattern')
async def hourly_attack_pattern():
    """Get attack pattern for last 12 hours"""
    try:
        from datetime import timedelta
        
        
        turkey_tz = pytz.timezone('Europe/Istanbul')
        now_utc = datetime.utcnow()
        now_turkey = pytz.utc.localize(now_utc).astimezone(turkey_tz)
        
        
        cutoff_time = now_utc - timedelta(hours=12)
        
        with engine.connect() as conn:
            
            bait_stmt = select(bait_clicks.c.timestamp).where(
                bait_clicks.c.timestamp > cutoff_time
            )
            bait_times = [row[0] for row in conn.execute(bait_stmt).fetchall()]
            
            
            admin_stmt = select(admin_login_attempts.c.timestamp).where(
                admin_login_attempts.c.timestamp > cutoff_time
            )
            admin_times = [row[0] for row in conn.execute(admin_stmt).fetchall()]
            
           
            request_stmt = select(request_logs.c.timestamp).where(
                request_logs.c.timestamp > cutoff_time
            )
            request_times = [row[0] for row in conn.execute(request_stmt).fetchall()]
        
        
        all_times = bait_times + admin_times + request_times
        
        
        hour_counts = [0] * 12
        labels = []
        
        
        for i in range(12, 0, -1):
            hour_time = now_turkey - timedelta(hours=i)
            labels.append(hour_time.strftime('%H:00'))
        
       
        for ts in all_times:
            if ts:
                
                if isinstance(ts, str):
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                else:
                    dt = ts
                
                
                if dt.tzinfo is None:
                    dt = pytz.utc.localize(dt)
                
               
                turkey_time = dt.astimezone(turkey_tz)
                
                
                hours_ago = int((now_turkey - turkey_time).total_seconds() / 3600)
                
                
                if 0 <= hours_ago < 12:
                    idx = 11 - hours_ago
                    if 0 <= idx < 12:
                        hour_counts[idx] += 1
        
        return JSONResponse({
            'labels': labels,
            'data': hour_counts
        })
        
    except Exception as e:
        logger.error(f"Hourly pattern error: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)


    except Exception as e:
        logger.error(f"Hourly pattern error: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)




@app.get('/admin', response_class=HTMLResponse)
async def admin_bait(request: Request):
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    
    try:
        stmt = insert(bait_clicks).values(
            ip=ip, bait_path='/admin', referer='', user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.warning(f"BAIT CLICKED: /admin from {ip}")
        
        if broadcast_bait_click:
            asyncio.create_task(broadcast_bait_click(ip, '/admin', ua))
    except Exception as e:
        logger.error(f"DB error: {e}")
    
    return FileResponse('static/admin_login.html')


@app.get('/backup', response_class=HTMLResponse)
async def backup_bait(request: Request):
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    
    try:
        stmt = insert(bait_clicks).values(
            ip=ip, bait_path='/backup', referer='', user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.warning(f"BAIT CLICKED: /backup from {ip}")
        
        if broadcast_bait_click:
            asyncio.create_task(broadcast_bait_click(ip, '/backup', ua))
    except Exception as e:
        logger.error(f"DB error: {e}")
    
    return FileResponse('static/bait_backup.html')


@app.get('/config')
async def config_bait(request: Request):
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    
    try:
        stmt = insert(bait_clicks).values(
            ip=ip, bait_path='/config', referer='', user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.warning(f"BAIT CLICKED: /config from {ip}")
        
        if broadcast_bait_click:
            asyncio.create_task(broadcast_bait_click(ip, '/config', ua))
    except Exception as e:
        logger.error(f"DB error: {e}")
    
    return FileResponse('static/bait_config.html')


@app.get('/.env')
async def env_bait(request: Request):
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    
    try:
        stmt = insert(bait_clicks).values(
            ip=ip, bait_path='/.env', referer='', user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.warning(f"BAIT CLICKED: /.env from {ip}")
        
        if broadcast_bait_click:
            asyncio.create_task(broadcast_bait_click(ip, '/.env', ua))
    except Exception as e:
        logger.error(f"DB error: {e}")
    
    return FileResponse('static/bait_env.txt', media_type="text/plain")


@app.get('/.git')
async def git_bait(request: Request):
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    
    try:
        stmt = insert(bait_clicks).values(
            ip=ip, bait_path='/.git', referer='', user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.warning(f"BAIT CLICKED: /.git from {ip}")
        
        if broadcast_bait_click:
            asyncio.create_task(broadcast_bait_click(ip, '/.git', ua))
    except Exception as e:
        logger.error(f"DB error: {e}")
    
    return FileResponse('static/bait_git.html')


@app.get('/db')
async def db_bait(request: Request):
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    
    try:
        stmt = insert(bait_clicks).values(
            ip=ip, bait_path='/db', referer='', user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.warning(f"BAIT CLICKED: /db from {ip}")
        
        if broadcast_bait_click:
            asyncio.create_task(broadcast_bait_click(ip, '/db', ua))
    except Exception as e:
        logger.error(f"DB error: {e}")
    
    return FileResponse('static/bait_db.html')


@app.websocket("/ws/updates")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time updates
    Clients connect here to receive live events
    """
    if not ws_manager:
        await websocket.close(code=1011, reason="WebSocket not available")
        return
    
    client_ip = websocket.client.host if websocket.client else "unknown"
    await ws_manager.connect(websocket, client_id=f"dashboard_{client_ip}")
    
    try:
        while True:
            
            data = await websocket.receive_text()
            
            
            try:
                message = json.loads(data) if data else {}
                msg_type = message.get("type", "")
                
                if msg_type == "ping":
                    
                    await websocket.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat()})
                elif msg_type == "get_stats":
                   
                    stats = await get_current_stats()
                    await websocket.send_json({"type": "stats", "data": stats})
                else:
                    logger.debug(f"Unknown WebSocket message type: {msg_type}")
                    
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from WebSocket client: {data}")
                
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
        logger.info(f"WebSocket disconnected: {client_ip}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket)


async def get_current_stats() -> dict:
    """Helper function to get current stats for WebSocket"""
    try:
        with engine.begin() as conn:
            total_req = conn.execute(select(func.count()).select_from(request_logs)).scalar()
            unique_ips = conn.execute(select(func.count(func.distinct(request_logs.c.ip))).select_from(request_logs)).scalar()
            admin_attempts = conn.execute(select(func.count()).select_from(admin_login_attempts)).scalar()
            bait_count = conn.execute(select(func.count()).select_from(bait_clicks)).scalar()
        
        return {
            'total_requests': total_req or 0,
            'unique_ips': unique_ips or 0,
            'admin_attempts': admin_attempts or 0,
            'bait_clicks': bait_count or 0
        }
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return {}



@api.get('/ws/status')
async def websocket_status():
    """Get WebSocket connection status"""
    if not ws_manager:
        return JSONResponse({"status": "unavailable", "message": "WebSocket not enabled"})
    
    stats = ws_manager.get_stats()
    return JSONResponse({
        "status": "active",
        "connections": stats["total_connections"],
        "details": stats["connections"]
    })


DASHBOARD_PASSWORD = "meladmin2025"
from fastapi.responses import RedirectResponse

@app.get("/dashboard/login")
async def dashboard_login_page():
    """Dashboard login page"""
    return FileResponse('static/dashboard_login.html')

@app.post("/dashboard/auth")
async def dashboard_auth(request: Request, username: str = Form(...), password: str = Form(...)):
    """Authenticate with username and password"""
    logger.info(f"Login attempt - Username: {username}, Password: {'*' * len(password)}")
    
    if username != "admin" or password != DASHBOARD_PASSWORD:
        logger.warning(f"Failed login attempt - Username: {username}")
        return RedirectResponse(url="/dashboard/login", status_code=303)
    
    
    logger.info("Login successful - Setting cookie")
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="dashboard_session",
        value="authenticated",
        path="/",
        httponly=True,  
        max_age=7200,  
        samesite="lax",  
        secure=False  
    )
    logger.info("Cookie set successfully")
    return response

@app.get("/dashboard")
async def dashboard_page(request: Request):
    """Protected dashboard - check cookie"""
    session = request.cookies.get("dashboard_session")
    logger.info(f"Dashboard access - Cookie value: {session}")
    
    if session != "authenticated":
        logger.warning("Unauthorized dashboard access - redirecting to login")
        return RedirectResponse(url="/dashboard/login")
    
    
    logger.info("Dashboard access authorized")
    with open("static/dashboard.html", "r", encoding="utf-8") as f:
        dashboard_content = f.read()
    return HTMLResponse(dashboard_content)

@app.get("/dashboard/logout")
async def dashboard_logout():
    """Logout and clear cookie"""
    response = RedirectResponse(url="/dashboard/login")
    response.delete_cookie("dashboard_session")
    return response


@app.get('/robots.txt')
async def main_robots_txt(request: Request):
    """Same as /api/robots.txt but on main app"""
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    
    try:
        stmt = insert(request_logs).values(
            ip=ip, method='GET', path='/robots.txt', 
            user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.info(f"robots.txt requested from {ip}")
    except Exception as e:
        logger.error(f"DB error logging robots.txt: {e}")
    
    return HTMLResponse("""User-agent: *
Allow: /
Disallow: /cart/checkout
Disallow: /account/
Disallow: /search?
Disallow: /wishlist/

# Block bad bots
User-agent: AhrefsBot
Disallow: /

User-agent: SemrushBot
Disallow: /

# Sitemap
Sitemap: http://oatshobby.com/sitemap.xml
""", media_type="text/plain")

@app.get('/sitemap.xml')
async def main_sitemap_xml(request: Request):
    """Same as /api/sitemap.xml but on main app"""
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', '')
    
    try:
        stmt = insert(request_logs).values(
            ip=ip, method='GET', path='/sitemap.xml', 
            user_agent=ua, timestamp=datetime.utcnow()
        )
        with engine.begin() as conn:
            conn.execute(stmt)
        logger.info(f"sitemap.xml requested from {ip}")
    except Exception as e:
        logger.error(f"DB error logging sitemap.xml: {e}")
    
    return HTMLResponse("""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>http://oatshobby.com/</loc>
    <lastmod>2024-11-01</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>http://oatshobby.com/store.html</loc>
    <lastmod>2024-11-01</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>http://oatshobby.com/about.html</loc>
    <lastmod>2024-10-15</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>http://oatshobby.com/contact.html</loc>
    <lastmod>2024-10-15</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>http://oatshobby.com/reviews.html</loc>
    <lastmod>2024-10-20</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.6</priority>
  </url>
</urlset>
""", media_type="application/xml")


app.mount("/api", api)


app.mount("/", StaticFiles(directory="static", html=True), name="static")
