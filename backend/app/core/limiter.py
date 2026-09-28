from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Real-IP")
    return forwarded.strip() if forwarded else get_remote_address(request)


limiter = Limiter(key_func=get_client_ip)
