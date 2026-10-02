from __future__ import annotations

from dataclasses import dataclass

from app.cose import WebAuthnError

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40
FLAG_ED = 0x80


@dataclass(frozen=True)
class AttestedCredentialData:
    aaguid: bytes
    credential_id: bytes
    credential_public_key: object


@dataclass(frozen=True)
class AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    attested_credential: AttestedCredentialData | None

    @property
    def up(self) -> bool:
        return bool(self.flags & FLAG_UP)

    @property
    def uv(self) -> bool:
        return bool(self.flags & FLAG_UV)


def _slice(data: bytes, start: int, length: int, name: str) -> tuple[bytes, int]:
    end = start + length
    if end > len(data):
        raise WebAuthnError(f"authenticator data truncated while reading {name}")
    return data[start:end], end


def parse_authenticator_data(
    data: bytes, *, expect_attested_credential: bool, cbor_decoder
) -> AuthenticatorData:
    if len(data) < 37:
        raise WebAuthnError("authenticator data must be at least 37 bytes")
    rp_id_hash = data[:32]
    flags = data[32]
    sign_count = int.from_bytes(data[33:37], "big")
    offset = 37

    if flags & FLAG_ED:
        raise WebAuthnError("authenticator extensions are not supported")

    attested = None
    has_at = bool(flags & FLAG_AT)
    if expect_attested_credential:
        if not has_at:
            raise WebAuthnError("attested credential data flag (AT) is required")
        aaguid, offset = _slice(data, offset, 16, "aaguid")
        length_bytes, offset = _slice(data, offset, 2, "credential id length")
        credential_id_length = int.from_bytes(length_bytes, "big")
        if credential_id_length == 0 or credential_id_length > 1023:
            raise WebAuthnError("invalid credential id length")
        credential_id, offset = _slice(
            data, offset, credential_id_length, "credential id"
        )
        try:
            cose_key, consumed = cbor_decoder(data[offset:])
        except Exception as exc:
            raise WebAuthnError("invalid CBOR credential public key") from exc
        offset += consumed
        attested = AttestedCredentialData(
            aaguid=aaguid,
            credential_id=credential_id,
            credential_public_key=cose_key,
        )
    elif has_at:
        raise WebAuthnError("assertion authenticator data must not include AT")

    if offset != len(data):
        raise WebAuthnError("unexpected trailing bytes in authenticator data")

    return AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        attested_credential=attested,
    )
