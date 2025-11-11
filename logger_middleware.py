from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime
from sqlalchemy import insert
import logging


from db import engine, request_logs

logger = logging.getLogger(__name__)

class LoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
       
        ip = request.client.host if request.client else request.headers.get('x-forwarded-for', 'unknown')
        
        if ',' in ip:
            ip = ip.split(',')[0].strip()
        
        ua = request.headers.get('user-agent', '')
        path = request.url.path
        method = request.method
        query = request.url.query or ""

        
        try:
            with engine.begin() as conn:
                conn.execute(
                    insert(request_logs).values(
                        ip=ip,
                        path=path,
                        method=method,
                        query=query,
                        user_agent=ua,
                        timestamp=datetime.utcnow()
                    )
                )
        except Exception as e:
            
            logger.error(f'[LoggerMiddleware] logging error: {e}')

        response = await call_next(request)
        return response

