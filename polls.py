from flask import Blueprint, request, g
from firebase_admin import firestore
from datetime import datetime, timezone, timedelta

from config import Collections, POLL_CATEGORIES
from models import Poll, PollOption
from utils import success, error
from middleware import login_required, admin_required

# Encryption utilities
from encryption import (
    generate_election_keypair,
    generate_blind_signature_keys,
)

polls_bp = Blueprint("polls", __name__, url_prefix="/api/polls")


def _db():
    return firestore.client()


def _auto_close_expired(db, poll_data: dict, poll_ref) -> dict:
    """Auto-close a poll if its expires_at has passed."""

    expires_at = poll_data.get("expires_at")

    if expires_at and poll_data.get("status") == Poll.STATUS_ACTIVE:
        expiry_dt = datetime.fromisoformat(expires_at)

        if datetime.now(timezone.utc) > expiry_dt:
            closed_at = datetime.now(timezone.utc).isoformat()

            poll_ref.update({
                "status": Poll.STATUS_CLOSED,
                "closed_at": closed_at,
            })

            poll_data["status"] = Poll.STATUS_CLOSED
            poll_data["closed_at"] = closed_at

    return poll_data


# ── POST /api/polls ───────────────────────────────────────────────────────────
@polls_bp.post("/")
@admin_required
def create_poll():
    """
    Create a new poll with category + encryption support.

    Body:
    {
        "question": "...",
        "description": "...",
        "options": ["Yes", "No"],

        "category": "state|corporate|parliament",
        "subcategory": "Maharashtra",
        "sector": "Technology",
        "company_name": "Acme Corp",
        "bill_number": "Bill 47 of 2025",
        "chamber": "lok|rajya|joint",
        "eligible_states": ["Maharashtra"],

        "expires_in_hours": 24
    }
    """

    data = request.get_json(silent=True) or {}

    question = (data.get("question") or "").strip()
    options = data.get("options", [])

    if not question:
        return error("Poll question is required.")

    if not isinstance(options, list) or len(options) < 2:
        return error("At least 2 options are required.")

    poll_options = [
        PollOption(text=str(o).strip())
        for o in options
        if str(o).strip()
    ]

    if len(poll_options) < 2:
        return error("At least 2 non-empty options are required.")

    # ── Category validation ───────────────────────────────────────────────
    category = data.get("category")

    if category not in POLL_CATEGORIES:
        return error("Invalid category.", 400)

    subcategory = data.get("subcategory")
    chamber = data.get("chamber")
    sector = data.get("sector")
    company_name = data.get("company_name")
    bill_number = data.get("bill_number")
    eligible_states = data.get("eligible_states", [])

    # ── Parliament validation ────────────────────────────────────────────
    if category == "parliament":
        if chamber not in ("lok", "rajya", "joint"):
            return error(
                "Parliament polls require chamber: lok|rajya|joint.",
                400
            )

    # ── Corporate validation ─────────────────────────────────────────────
    if category == "corporate":
        if not company_name:
            return error(
                "Corporate polls require company_name.",
                400
            )

    # ── State validation ─────────────────────────────────────────────────
    if category == "state":
        if not eligible_states:
            return error(
                "State polls require eligible_states.",
                400
            )

    # ── Optional expiry ──────────────────────────────────────────────────
    expires_at = None

    expires_in = data.get("expires_in_hours")

    if expires_in:
        try:
            hours = float(expires_in)

            expires_at = (
                datetime.now(timezone.utc)
                + timedelta(hours=hours)
            ).isoformat()

        except ValueError:
            return error("expires_in_hours must be a number.")

    # ── Generate E2E election keypair ────────────────────────────────────
    election_private_key, election_public_key = (
        generate_election_keypair()
    )

    # ── Generate blind signature keys ────────────────────────────────────
    blind_private_key, blind_public_key = (
        generate_blind_signature_keys()
    )

    # TODO:
    # Store private keys securely in:
    # - AWS KMS
    # - GCP KMS
    # - Azure Key Vault
    # - HSM
    #
    # NEVER store private keys directly in Firestore.

    # ── Build Poll model ─────────────────────────────────────────────────
    poll = Poll(
        question=question,
        description=(data.get("description") or "").strip(),
        created_by=g.user_id,
        options=poll_options,
        status=data.get("status", Poll.STATUS_ACTIVE),
        expires_at=expires_at,

        # Category fields
        category=category,
        subcategory=subcategory,
        bill_number=bill_number,
        company_name=company_name,
        sector=sector,
        chamber=chamber,
        eligible_states=eligible_states,

        # Encryption fields
        election_public_key=election_public_key,
        blind_sig_public_key=blind_public_key,
        homomorphic_enabled=True,
        tally_encrypted=True,
        encryption_scheme="ECDH-AES256-GCM",
    )

    db = _db()

    poll_dict = poll.to_dict()

    db.collection(Collections.POLLS).document(poll.id).set(
        poll_dict
    )

    return success(
        data={"poll": poll_dict},
        message="Poll created successfully.",
        status=201,
    )


# ── GET /api/polls ────────────────────────────────────────────────────────────
@polls_bp.get("/")
@login_required
def list_polls():
    """
    Return polls with filtering support.

    Query params:
      ?category=state|corporate|parliament
      ?subcategory=Maharashtra
      ?chamber=lok|rajya|joint
      ?sector=Technology
      ?status=active|closed
    """

    category = request.args.get("category")
    subcategory = request.args.get("subcategory")
    chamber = request.args.get("chamber")
    sector = request.args.get("sector")
    status_filter = request.args.get("status")

    db = _db()

    query = db.collection(Collections.POLLS)

    # ── Filters ──────────────────────────────────────────────────────────
    if status_filter in (
        Poll.STATUS_ACTIVE,
        Poll.STATUS_CLOSED
    ):
        query = query.where(
            filter=firestore.FieldFilter(
                "status",
                "==",
                status_filter
            )
        )

    if category:
        query = query.where(
            filter=firestore.FieldFilter(
                "category",
                "==",
                category
            )
        )

    if subcategory:
        query = query.where(
            filter=firestore.FieldFilter(
                "subcategory",
                "==",
                subcategory
            )
        )

    if chamber:
        query = query.where(
            filter=firestore.FieldFilter(
                "chamber",
                "==",
                chamber
            )
        )

    if sector:
        query = query.where(
            filter=firestore.FieldFilter(
                "sector",
                "==",
                sector
            )
        )

    docs = query.order_by(
        "created_at",
        direction=firestore.Query.DESCENDING
    ).get()

    polls = []

    for d in docs:
        poll_data = _auto_close_expired(
            db,
            d.to_dict(),
            d.reference
        )

        polls.append({
            **poll_data,
            "id": d.id,
        })

    return success(
        data={
            "polls": polls,
            "count": len(polls)
        }
    )


# ── GET /api/polls/states ────────────────────────────────────────────────────
@polls_bp.get("/states")
@login_required
def get_state_polls():
    """
    Returns polls grouped by state.
    """

    db = _db()

    docs = (
        db.collection(Collections.POLLS)
        .where(
            filter=firestore.FieldFilter(
                "category",
                "==",
                "state"
            )
        )
        .get()
    )

    grouped = {}

    for d in docs:
        poll = d.to_dict()

        for state in poll.get("eligible_states", []):
            grouped.setdefault(state, []).append({
                "id": d.id,
                "question": poll["question"],
                "total_votes": poll.get("total_votes", 0),
                "status": poll.get("status"),
                "expires_at": poll.get("expires_at"),
            })

    return success(
        data={
            "states": grouped,
            "count": len(grouped),
        }
    )


# ── GET /api/polls/parliament ────────────────────────────────────────────────
@polls_bp.get("/parliament")
@login_required
def get_parliament_polls():
    """
    Return parliament polls filtered by chamber.

    Query:
      ?chamber=lok|rajya|joint
    """

    chamber = request.args.get("chamber")

    db = _db()

    query = (
        db.collection(Collections.POLLS)
        .where(
            filter=firestore.FieldFilter(
                "category",
                "==",
                "parliament"
            )
        )
    )

    if chamber:
        query = query.where(
            filter=firestore.FieldFilter(
                "chamber",
                "==",
                chamber
            )
        )

    docs = query.get()

    polls = []

    for d in docs:
        poll_data = d.to_dict()

        polls.append({
            "id": d.id,
            **poll_data,
        })

    return success(
        data={
            "polls": polls,
            "count": len(polls),
        }
    )


# ── GET /api/polls/<poll_id> ─────────────────────────────────────────────────
@polls_bp.get("/<poll_id>")
@login_required
def get_poll(poll_id: str):
    """
    Return a single poll.
    """

    db = _db()

    ref = db.collection(Collections.POLLS).document(
        poll_id
    )

    doc = ref.get()

    if not doc.exists:
        return error("Poll not found.", 404)

    poll_data = _auto_close_expired(
        db,
        doc.to_dict(),
        ref
    )

    return success(
        data={
            "poll": {
                **poll_data,
                "id": doc.id,
            }
        }
    )


# ── PATCH /api/polls/<poll_id>/close ─────────────────────────────────────────
@polls_bp.patch("/<poll_id>/close")
@admin_required
def close_poll(poll_id: str):
    """
    Manually close a poll.
    """

    db = _db()

    ref = db.collection(Collections.POLLS).document(
        poll_id
    )

    doc = ref.get()

    if not doc.exists:
        return error("Poll not found.", 404)

    if doc.to_dict()["status"] == Poll.STATUS_CLOSED:
        return error("Poll is already closed.")

    ref.update({
        "status": Poll.STATUS_CLOSED,
        "closed_at": datetime.now(
            timezone.utc
        ).isoformat(),
    })

    return success(
        message="Poll closed successfully."
    )


# ── DELETE /api/polls/<poll_id> ──────────────────────────────────────────────
@polls_bp.delete("/<poll_id>")
@admin_required
def delete_poll(poll_id: str):
    """
    Delete a poll and all associated votes.
    """

    db = _db()

    ref = db.collection(Collections.POLLS).document(
        poll_id
    )

    if not ref.get().exists:
        return error("Poll not found.", 404)

    vote_docs = (
        db.collection(Collections.VOTES)
        .where(
            filter=firestore.FieldFilter(
                "poll_id",
                "==",
                poll_id
            )
        )
        .get()
    )

    for vdoc in vote_docs:
        vdoc.reference.delete()

    ref.delete()

    return success(
        message="Poll deleted."
    )


# ── GET /api/polls/<poll_id>/results ─────────────────────────────────────────
@polls_bp.get("/<poll_id>/results")
@login_required
def poll_results(poll_id: str):
    """
    Return detailed poll results.
    """

    db = _db()

    ref = db.collection(Collections.POLLS).document(
        poll_id
    )

    doc = ref.get()

    if not doc.exists:
        return error("Poll not found.", 404)

    poll_data = _auto_close_expired(
        db,
        doc.to_dict(),
        ref
    )

    total = poll_data.get("total_votes", 0)

    results = []

    for opt in poll_data.get("options", []):
        vc = opt.get("vote_count", 0)

        pct = (
            round((vc / total * 100), 2)
            if total > 0 else 0.0
        )

        results.append({
            "id": opt["id"],
            "text": opt["text"],
            "vote_count": vc,
            "percentage": pct,
        })

    results.sort(
        key=lambda x: x["vote_count"],
        reverse=True
    )

    return success(
        data={
            "poll_id": poll_id,
            "question": poll_data["question"],
            "category": poll_data.get("category"),
            "subcategory": poll_data.get("subcategory"),
            "status": poll_data["status"],
            "total_votes": total,
            "expires_at": poll_data.get("expires_at"),
            "results": results,
        }
    )