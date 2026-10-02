from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePublicNumbers,
)

KTY = 1
ALG = 3
CRV = -1
X = -2
Y = -3

KTY_EC2 = 2
ALG_ES256 = -7
CRV_P256 = 1
P256_FIELD_SIZE = 32


class WebAuthnError(ValueError):
    pass


def decode_es256_p256_key(cose_key: object) -> bytes:
    """Validate a COSE_Key and return its SPKI DER encoding."""
    if not isinstance(cose_key, dict):
        raise WebAuthnError("COSE public key must be a map")
    allowed = {KTY, ALG, CRV, X, Y}
    if set(cose_key) != allowed:
        raise WebAuthnError("COSE key contains unsupported fields")
    if cose_key.get(KTY) != KTY_EC2:
        raise WebAuthnError("only EC2 keys are supported")
    if cose_key.get(ALG) != ALG_ES256:
        raise WebAuthnError("only ES256 (-7) is supported")
    if cose_key.get(CRV) != CRV_P256:
        raise WebAuthnError("only P-256 (crv 1) is supported")
    x = cose_key.get(X)
    y = cose_key.get(Y)
    if not isinstance(x, bytes) or not isinstance(y, bytes):
        raise WebAuthnError("COSE coordinates must be byte strings")
    if len(x) != P256_FIELD_SIZE or len(y) != P256_FIELD_SIZE:
        raise WebAuthnError("P-256 coordinates must each be 32 bytes")
    x_int = int.from_bytes(x, "big")
    y_int = int.from_bytes(y, "big")
    try:
        public_key = EllipticCurvePublicNumbers(
            x_int, y_int, SECP256R1()
        ).public_key()
    except Exception as exc:
        raise WebAuthnError("point is not a valid P-256 public key") from exc
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_es256_public_key(spki_der: bytes) -> ec.EllipticCurvePublicKey:
    key = serialization.load_der_public_key(spki_der)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise WebAuthnError("stored key is not an ES256 P-256 key")
    return key


def verify_es256(public_key_der: bytes, signed_data: bytes, signature: bytes) -> None:
    public_key = load_es256_public_key(public_key_der)
    try:
        public_key.verify(signature, signed_data, ECDSA(hashes.SHA256()))
    except Exception as exc:
        raise WebAuthnError("signature verification failed") from exc
