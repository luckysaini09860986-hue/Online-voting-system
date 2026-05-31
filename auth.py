from flask import Blueprint, request, g
from firebase_admin import firestore
from datetime import datetime, timezone
import os

from config import Collections
from models import User, OTPRecord
from utils import (
    generate_otp,
    hash_otp,
    verify_otp,
    otp_expiry_iso,
    is_otp_expired,
    send_otp_email,
    create_jwt,
    success,
    error,
)
from middleware import login_required

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

ADMIN_SECRET_CODE = os.getenv("ADMIN_SECRET_CODE", "")


def _db():
    return firestore.client()


# ── Aadhaar / DID Identity Verification ──────────────────────────────────────
def verify_voter_eligibility(
    user_id,
    poll_id,
    poll_category,
    poll_subcategory
):
    """
    Aadhaar / DID-based voter eligibility verification.

    Checks whether the authenticated user is eligible
    to vote in the specified poll category.
    """

    db = _db()

    user_doc = (
        db.collection(Collections.USERS)
        .document(user_id)
        .get()
    )

    if not user_doc.exists:
        return False

    user = user_doc.to_dict()

    # Optional DID verification gate
    if not user.get("did_verified", False):
        return False

    # Optional Aadhaar verification gate
    if not user.get("aadhaar_verified", False):
        return False

    # ── State Election ────────────────────────────────────────────────────
    if poll_category == "state":
        # Voter's registered state must match
        return (
            user.get("registered_state")
            == poll_subcategory
        )

    # ── Corporate Voting ──────────────────────────────────────────────────
    elif poll_category == "corporate":
        # User must belong to / own shares in company
        return (
            user.get("company_id")
            == poll_subcategory
        )

    # ── Parliament Voting ────────────────────────────────────────────────
    elif poll_category == "parliament":
        # Must be MP in matching chamber
        return (
            user.get("mp_chamber")
            == poll_subcategory
        )

    return False


# ── POST /api/auth/register/send-otp ─────────────────────────────────────────
@auth_bp.post("/register/send-otp")
def register_send_otp():
    """
    Step 1 of registration.

    Body:
    {
        name,
        email,
        role?,
        admin_code?,

        # NEW Identity fields
        aadhaar_id?,
        did?,
        registered_state?,
        company_id?,
        mp_chamber?
    }
    """

    data = request.get_json(silent=True) or {}

    name = (data.get("name") or "").strip()

    email = (data.get("email") or "").strip().lower()

    requested_role = (
        data.get("role") or "voter"
    ).strip()

    admin_code = (
        data.get("admin_code") or ""
    ).strip()

    # ── Identity fields ──────────────────────────────────────────────────
    aadhaar_id = (
        data.get("aadhaar_id") or ""
    ).strip()

    did = (
        data.get("did") or ""
    ).strip()

    registered_state = (
        data.get("registered_state") or ""
    ).strip()

    company_id = (
        data.get("company_id") or ""
    ).strip()

    mp_chamber = (
        data.get("mp_chamber") or ""
    ).strip()

    if not name:
        return error("Name is required.")

    if not email or "@" not in email:
        return error("A valid email is required.")

    # ── Role security gate ───────────────────────────────────────────────
    if requested_role == "admin":

        if (
            not ADMIN_SECRET_CODE
            or admin_code != ADMIN_SECRET_CODE
        ):
            return error("Invalid admin code.", 403)

        role = "admin"

    else:
        role = "voter"

    db = _db()

    # ── Duplicate email check ────────────────────────────────────────────
    existing = (
        db.collection(Collections.USERS)
        .where(
            filter=firestore.FieldFilter(
                "email",
                "==",
                email
            )
        )
        .limit(1)
        .get()
    )

    if existing:
        return error(
            "An account with this email already exists.",
            409
        )

    # ── Generate OTP ─────────────────────────────────────────────────────
    otp = generate_otp()

    otp_record = OTPRecord(
        email=email,
        otp_hash=hash_otp(otp),
        expires_at=otp_expiry_iso(),
    )

    # ── Store temporary registration state ───────────────────────────────
    db.collection(Collections.OTPS).document(email).set({
        **otp_record.to_dict(),

        "pending_name": name,
        "pending_role": role,

        # Identity fields
        "aadhaar_id": aadhaar_id,
        "did": did,
        "registered_state": registered_state,
        "company_id": company_id,
        "mp_chamber": mp_chamber,
    })

    send_otp_email(email, otp)

    return success(
        message="OTP sent. Check your inbox."
    )


# ── POST /api/auth/register/verify-otp ───────────────────────────────────────
@auth_bp.post("/register/verify-otp")
def register_verify_otp():
    """
    Step 2 of registration.

    Body:
    {
        email,
        otp
    }
    """

    data = request.get_json(silent=True) or {}

    email = (data.get("email") or "").strip().lower()

    otp = (data.get("otp") or "").strip()

    if not email or not otp:
        return error("Email and OTP are required.")

    db = _db()

    otp_ref = (
        db.collection(Collections.OTPS)
        .document(email)
    )

    otp_doc = otp_ref.get()

    if not otp_doc.exists:
        return error(
            "No OTP found for this email.",
            404
        )

    otp_data = otp_doc.to_dict()

    if otp_data.get("used"):
        return error("OTP already used.")

    if is_otp_expired(otp_data["expires_at"]):
        return error("OTP expired.")

    if not verify_otp(
        otp,
        otp_data["otp_hash"]
    ):
        return error("Invalid OTP.")

    # ── Mark OTP used ────────────────────────────────────────────────────
    otp_ref.update({
        "used": True
    })

    # ── Aadhaar / DID verification simulation ────────────────────────────
    aadhaar_verified = bool(
        otp_data.get("aadhaar_id")
    )

    did_verified = bool(
        otp_data.get("did")
    )

    # ── Create user ──────────────────────────────────────────────────────
    user = User(
        name=otp_data.get(
            "pending_name",
            "User"
        ),

        email=email,

        role=otp_data.get(
            "pending_role",
            "voter"
        ),
    )

    user_data = {
        **user.to_dict(),

        # Identity fields
        "aadhaar_id": otp_data.get("aadhaar_id"),
        "did": otp_data.get("did"),

        # Eligibility metadata
        "registered_state": otp_data.get(
            "registered_state"
        ),

        "company_id": otp_data.get(
            "company_id"
        ),

        "mp_chamber": otp_data.get(
            "mp_chamber"
        ),

        # Verification flags
        "aadhaar_verified": aadhaar_verified,
        "did_verified": did_verified,

        # Identity timestamps
        "identity_verified_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    db.collection(Collections.USERS).document(
        user.id
    ).set(user_data)

    # ── Generate JWT ─────────────────────────────────────────────────────
    token = create_jwt(
        user.id,
        user.role
    )

    return success(
        data={
            "token": token,
            "user": user_data,
        },
        message="Registration successful.",
        status=201,
    )


# ── POST /api/auth/login/send-otp ────────────────────────────────────────────
@auth_bp.post("/login/send-otp")
def login_send_otp():
    """
    Step 1 of login.
    """

    data = request.get_json(silent=True) or {}

    email = (
        data.get("email") or ""
    ).strip().lower()

    if not email or "@" not in email:
        return error(
            "A valid email is required."
        )

    db = _db()

    user_q = (
        db.collection(Collections.USERS)
        .where(
            filter=firestore.FieldFilter(
                "email",
                "==",
                email
            )
        )
        .limit(1)
        .get()
    )

    if not user_q:
        return error(
            "No account found with this email.",
            404
        )

    otp = generate_otp()

    otp_record = OTPRecord(
        email=email,
        otp_hash=hash_otp(otp),
        expires_at=otp_expiry_iso(),
    )

    db.collection(Collections.OTPS).document(
        email
    ).set(
        otp_record.to_dict()
    )

    send_otp_email(email, otp)

    return success(
        message="OTP sent. Check your inbox."
    )


# ── POST /api/auth/login/verify-otp ──────────────────────────────────────────
@auth_bp.post("/login/verify-otp")
def login_verify_otp():
    """
    Step 2 of login.
    """

    data = request.get_json(silent=True) or {}

    email = (
        data.get("email") or ""
    ).strip().lower()

    otp = (
        data.get("otp") or ""
    ).strip()

    if not email or not otp:
        return error(
            "Email and OTP are required."
        )

    db = _db()

    otp_ref = (
        db.collection(Collections.OTPS)
        .document(email)
    )

    otp_doc = otp_ref.get()

    if not otp_doc.exists:
        return error(
            "No OTP found.",
            404
        )

    otp_data = otp_doc.to_dict()

    if otp_data.get("used"):
        return error("OTP already used.")

    if is_otp_expired(
        otp_data["expires_at"]
    ):
        return error("OTP expired.")

    if not verify_otp(
        otp,
        otp_data["otp_hash"]
    ):
        return error("Invalid OTP.")

    otp_ref.update({
        "used": True
    })

    user_docs = (
        db.collection(Collections.USERS)
        .where(
            filter=firestore.FieldFilter(
                "email",
                "==",
                email
            )
        )
        .limit(1)
        .get()
    )

    user_data = user_docs[0].to_dict()

    user = User.from_dict(user_data)

    token = create_jwt(
        user.id,
        user.role
    )

    return success(
        data={
            "token": token,
            "user": user_data,
        },
        message="Login successful.",
    )


# ── GET /api/auth/me ─────────────────────────────────────────────────────────
@auth_bp.get("/me")
@login_required
def me():
    """
    Return authenticated user profile.
    """

    db = _db()

    user_doc = (
        db.collection(Collections.USERS)
        .document(g.user_id)
        .get()
    )

    if not user_doc.exists:
        return error(
            "User not found.",
            404
        )

    return success(
        data={
            "user": user_doc.to_dict()
        }
    )