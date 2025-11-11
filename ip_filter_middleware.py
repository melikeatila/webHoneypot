
"""
IP Filtering Middleware for Honeypot
Provides whitelist/blacklist functionality to control access
"""
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import logging

logger = logging.getLogger(__name__)

class IPFilterMiddleware(BaseHTTPMiddleware):
    """
    Middleware to filter requests based on IP whitelist/blacklist
    
    Configuration:
    - blocked_ips: List of IPs to block (returns 403)
    - allowed_ips: If set, only these IPs are allowed (whitelist mode)
    - whitelist_mode: If True, only allowed_ips can access
    """
    
    def __init__(
        self, 
        app, 
        blocked_ips: list = None,
        allowed_ips: list = None,
        whitelist_mode: bool = False,
        exempt_paths: list = None
    ):
        super().__init__(app)
        self.blocked_ips = set(blocked_ips or [])
        self.allowed_ips = set(allowed_ips or [])
        self.whitelist_mode = whitelist_mode
        
        self.exempt_paths = set(exempt_paths or ['/api/info', '/health'])
        
        logger.info(f"IPFilterMiddleware initialized")
        logger.info(f"Blocked IPs: {len(self.blocked_ips)}")
        logger.info(f"Allowed IPs: {len(self.allowed_ips)}")
        logger.info(f"Whitelist mode: {whitelist_mode}")
    
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else 'unknown'
        path = request.url.path
        
        
        if path in self.exempt_paths:
            return await call_next(request)
        
        
        if client_ip in self.blocked_ips:
            logger.warning(f" Blocked IP attempted access: {client_ip} → {path}")
            return JSONResponse(
                {
                    "error": "Forbidden",
                    "message": "Access denied",
                    "code": "IP_BLOCKED"
                },
                status_code=403
            )
        
        
        if self.whitelist_mode:
            if client_ip not in self.allowed_ips and client_ip != '127.0.0.1':
                logger.warning(f" Non-whitelisted IP attempted access: {client_ip} → {path}")
                return JSONResponse(
                    {
                        "error": "Forbidden",
                        "message": "Access denied",
                        "code": "IP_NOT_WHITELISTED"
                    },
                    status_code=403
                )
        
        
        response = await call_next(request)
        return response
    
    def add_blocked_ip(self, ip: str):
        """Add an IP to the blocklist"""
        self.blocked_ips.add(ip)
        logger.info(f"Added {ip} to blocklist")
    
    def remove_blocked_ip(self, ip: str):
        """Remove an IP from the blocklist"""
        self.blocked_ips.discard(ip)
        logger.info(f"Removed {ip} from blocklist")
    
    def add_allowed_ip(self, ip: str):
        """Add an IP to the whitelist"""
        self.allowed_ips.add(ip)
        logger.info(f"Added {ip} to whitelist")
    
    def remove_allowed_ip(self, ip: str):
        """Remove an IP from the whitelist"""
        self.allowed_ips.discard(ip)
        logger.info(f"Removed {ip} from whitelist")
