from functools import wraps
from flask import request, g
import jwt as pyjwt

from utils import decode_jwt, error


def _extract_token() -> str | None:
    """
    Pull Bearer token from Authorization header.
    """

    auth = request.headers.get("Authorization", "")

    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1]

    return None


# ── @login_required ───────────────────────────────────────────────────────────
def login_required(f):
    """
    Protect a route:
      • JWT must be present and valid.
      • Sets g.user_id and g.role.
    """

    @wraps(f)
    def decorated(*args, **kwargs):

        token = _extract_token()

        if not token:
            return error(
                "Missing authentication token",
                401
            )

        try:
            payload = decode_jwt(token)

            g.user_id = payload["sub"]
            g.role = payload["role"]

        except pyjwt.ExpiredSignatureError:
            return error(
                "Token has expired. Please log in again.",
                401
            )

        except pyjwt.InvalidTokenError:
            return error(
                "Invalid token.",
                401
            )

        return f(*args, **kwargs)

    return decorated


# ── @admin_required ───────────────────────────────────────────────────────────
def admin_required(f):
    """
    Protect a route:
      • JWT must be valid
      • Role must be admin
    """

    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):

        if g.role != "admin":
            return error(
                "Admin access required.",
                403
            )

        return f(*args, **kwargs)

    return decorated


# ── @voter_required ───────────────────────────────────────────────────────────
def voter_required(f):
    """
    Protect a route:
      • JWT must be valid
      • Role must be voter/admin
    """

    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):

        if g.role not in ("voter", "admin"):
            return error(
                "Voter access required.",
                403
            )

        return f(*args, **kwargs)

    return decorated


# ── @validate_encrypted_payload ──────────────────────────────────────────────
def validate_encrypted_payload(f):
    """
    Validate encrypted ballot payload structure.

    Required JSON body:
    {
        "encrypted_ballot": {
            "ciphertext": "...",
            "nonce": "...",
            "voter_ephemeral_pub": "...",
            "scheme": "ECDH-AES256-GCM"
        }
    }
    """

    @wraps(f)
    def decorated(*args, **kwargs):

        data = request.get_json(silent=True)

        if not data:
            return error(
                "Missing request body.",
                400
            )

        # ── Validate encrypted_ballot exists ────────────────────────────
        if "encrypted_ballot" not in data:
            return error(
                "Missing encrypted ballot.",
                400
            )

        ballot = data["encrypted_ballot"]

        if not isinstance(ballot, dict):
            return error(
                "encrypted_ballot must be an object.",
                400
            )

        # ── Required fields ─────────────────────────────────────────────
        required = [
            "ciphertext",
            "nonce",
            "voter_ephemeral_pub",
            "scheme",
        ]

        missing = [
            field for field in required
            if field not in ballot
        ]

        if missing:
            return error(
                f"Invalid ballot format. Missing: {', '.join(missing)}",
                400
            )

        # ── Validate encryption scheme ──────────────────────────────────
        allowed_schemes = [
            "ECDH-AES256-GCM"
        ]

        if ballot["scheme"] not in allowed_schemes:
            return error(
                "Unsupported encryption scheme.",
                400
            )

        # ── Validate field types ────────────────────────────────────────
        string_fields = [
            "ciphertext",
            "nonce",
            "voter_ephemeral_pub",
            "scheme",
        ]

        for field in string_fields:

            if not isinstance(ballot[field], str):
                return error(
                    f"{field} must be a string.",
                    400
                )

            if not ballot[field].strip():
                return error(
                    f"{field} cannot be empty.",
                    400
                )

        # ── Attach validated payload to request context ─────────────────
        g.encrypted_ballot = ballot

        return f(*args, **kwargs)

    return decorated