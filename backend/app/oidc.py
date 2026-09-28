import time
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oidc.core import CodeIDToken
from fastapi import HTTPException
from joserfc import jwt
from joserfc.jwk import KeySet

from .config import settings

_METADATA_TTL = 600
_metadata_cache: dict[str, Any] | None = None
_metadata_cached_at = 0.0
_jwks_cache: KeySet | None = None
_jwks_cached_at = 0.0


async def google_metadata() -> dict[str, Any]:
    global _metadata_cache, _metadata_cached_at
    now = time.monotonic()
    if _metadata_cache and now - _metadata_cached_at < _METADATA_TTL:
        return _metadata_cache
    url = f"{settings.GOOGLE_ISSUER.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()
    if data.get("issuer") != settings.GOOGLE_ISSUER:
        raise HTTPException(502, "Google OIDC issuer mismatch")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise HTTPException(502, "Google OIDC configuration is incomplete")
    _metadata_cache, _metadata_cached_at = data, now
    return data


async def google_authorization_url() -> tuple[str, str, str, str]:
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(503, "Google login is not configured")
    metadata = await google_metadata()
    client = AsyncOAuth2Client(
        settings.GOOGLE_CLIENT_ID,
        settings.GOOGLE_CLIENT_SECRET,
        scope="openid email profile",
        code_challenge_method="S256",
    )
    code_verifier = __import__("secrets").token_urlsafe(64)
    nonce = __import__("secrets").token_urlsafe(32)
    uri, state = client.create_authorization_url(
        metadata["authorization_endpoint"],
        redirect_uri=settings.GOOGLE_REDIRECT_URI,
        code_verifier=code_verifier,
        nonce=nonce,
        access_type="online",
        prompt="select_account",
    )
    return uri, state, nonce, code_verifier


async def google_id_token_claims(
    code: str,
    state: str,
    nonce: str,
    code_verifier: str,
) -> dict[str, Any]:
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(503, "Google login is not configured")
    metadata = await google_metadata()
    client = AsyncOAuth2Client(
        settings.GOOGLE_CLIENT_ID,
        settings.GOOGLE_CLIENT_SECRET,
        scope="openid email profile",
        state=state,
    )
    try:
        token = await client.fetch_token(
            metadata["token_endpoint"],
            code=code,
            redirect_uri=settings.GOOGLE_REDIRECT_URI,
            code_verifier=code_verifier,
        )
    except Exception as exc:
        raise HTTPException(401, "Google authorization failed") from exc

    id_token = token.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise HTTPException(401, "Google ID token missing")

    global _jwks_cache, _jwks_cached_at
    now = time.monotonic()
    if _jwks_cache is None or now - _jwks_cached_at >= _METADATA_TTL:
        async with httpx.AsyncClient(timeout=10) as http:
            response = await http.get(metadata["jwks_uri"])
            response.raise_for_status()
            _jwks_cache = KeySet.import_key_set(response.json())
        _jwks_cached_at = now

    try:
        token_obj = jwt.decode(id_token, _jwks_cache)
        claims = CodeIDToken(token_obj.claims, token_obj.header)
        claims.validate()
    except Exception as exc:
        raise HTTPException(401, "Invalid Google ID token") from exc

    payload = dict(claims)
    issuer = payload.get("iss")
    audience = payload.get("aud")
    token_nonce = payload.get("nonce")
    expires_at = payload.get("exp")
    email = payload.get("email")
    verified = payload.get("email_verified")
    client_id = settings.GOOGLE_CLIENT_ID

    valid_audience = audience == client_id or (
        isinstance(audience, list) and client_id in audience
    )
    if not (
        issuer == settings.GOOGLE_ISSUER
        and valid_audience
        and token_nonce == nonce
        and isinstance(expires_at, int | float)
        and expires_at > time.time()
        and verified is True
        and isinstance(email, str)
        and email
    ):
        raise HTTPException(401, "Invalid Google identity claims")

    if isinstance(audience, list) and len(audience) > 1 and payload.get("azp") != client_id:
        raise HTTPException(401, "Invalid Google authorized party")

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        raise HTTPException(401, "Google subject missing")
    return {"sub": sub, "email": email}
