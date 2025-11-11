import hashlib
import re

def sha256_hex_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_hex_str(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def mask_password(pw: str) -> str:
    if not pw:
        return ""
    if len(pw) <= 4:
        return pw[0] + "***"
    return pw[:2] + "***" + pw[-2:]

def mask_email(email: str) -> str:
    """
    Email maskeleme: isim kısmını maskeler/hash'ler, domain korur
    Örnek: melike@example.com -> m***e@example.com veya <hash>@example.com
    """
    if not email or '@' not in email:
        return sha256_hex_str(email)[:16] + "@masked"
    
    local, domain = email.split('@', 1)
    if len(local) <= 3:
        masked_local = local[0] + "***"
    else:
        
        masked_local = local[0] + sha256_hex_str(local)[:6] + local[-1]
    
    return f"{masked_local}@{domain}"

def mask_phone(phone: str) -> str:
    """
    Telefon maskeleme: İlk 3 ve son 2 hane dışında *
    Örnek: 05551234567 -> 055******67
    """
    if not phone:
        return ""
    
    
    digits = re.sub(r'\D', '', phone)
    
    if len(digits) <= 5:
        return digits[0] + "***"
    
    
    return digits[:3] + "*" * (len(digits) - 5) + digits[-2:]

