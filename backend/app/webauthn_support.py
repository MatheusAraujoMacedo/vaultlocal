import base64
import json

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .config import settings


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def registration_options(
    email: str,
    user_id: str,
    excluded_ids: list[bytes],
    challenge: bytes,
) -> dict:
    excluded = [PublicKeyCredentialDescriptor(id=cid) for cid in excluded_ids]
    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        challenge=challenge,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_name=email,
        user_id=user_id.encode("utf-8"),
        user_display_name=email,
        timeout=60000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            require_resident_key=True,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=excluded,
    )
    return json.loads(options_to_json(options))


def authentication_options(
    credential_ids: list[bytes],
    challenge: bytes,
) -> dict:
    allow = [PublicKeyCredentialDescriptor(id=cid) for cid in credential_ids]
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        challenge=challenge,
        timeout=60000,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options))


def credential_descriptors(credentials) -> list[dict]:
    return [
        {
            "id": item.credential_id,
            "type": "public-key",
            "transports": [],
        }
        for item in credentials
    ]
