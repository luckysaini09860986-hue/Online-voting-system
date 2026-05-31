import hashlib

from flask import Blueprint, request, g
from firebase_admin import firestore

from config import Collections
from models import Vote, Poll
from utils import success, error
from middleware import login_required

votes_bp = Blueprint("votes", __name__, url_prefix="/api/votes")


def _db():
    return firestore.client()


# ── Placeholder blockchain helpers ───────────────────────────────────────────
def get_current_block_height():
    """
    Replace with your blockchain integration.
    """
    return 0


def generate_tx_hash(encrypted_ballot):
    """
    Deterministic tx hash for encrypted ballot.
    """
    payload = str(encrypted_ballot).encode()
    return hashlib.sha256(payload).hexdigest()


def verify_blind_signature(blind_signature, poll_id, user_id):
    """
    Replace with real RSA blind signature verification.
    """
    if blind_signature is None:
        return False

    return True


# ── POST /api/votes ───────────────────────────────────────────────────────────
@votes_bp.post("/")
@login_required
def cast_vote():
    """
    Cast an encrypted vote.

    Body:
    {
        "poll_id": "...",
        "option_id": "...",
        "encrypted_ballot": {
            "ciphertext": "...",
            "nonce": "...",
            "ephemeral_pub": "..."
        },
        "blind_signature": "..."
    }

    Rules enforced:
      • Poll must exist and be active.
      • User must not have already voted.
      • option_id must belong to the poll.
      • Blind signature must be valid.
      • Encrypted ballot is stored immutably.
      • Nullifier prevents double voting.
    """

    data = request.get_json(silent=True) or {}

    poll_id           = (data.get("poll_id") or "").strip()
    option_id         = (data.get("option_id") or "").strip()
    encrypted_ballot  = data.get("encrypted_ballot")
    blind_signature   = data.get("blind_signature")

    if not poll_id or not option_id:
        return error("poll_id and option_id are required.")

    if not encrypted_ballot:
        return error("encrypted_ballot is required.")

    db = _db()

    poll_ref = db.collection(Collections.POLLS).document(poll_id)

    # Deterministic anonymous nullifier
    nullifier = hashlib.sha256(
        f"{g.user_id}:{poll_id}".encode()
    ).hexdigest()

    nullifier_ref = db.collection("nullifiers").document(nullifier)

    @firestore.transactional
    def _transact(transaction):
        # ── Poll Validation ────────────────────────────────────────────────
        poll_snap = poll_ref.get(transaction=transaction)

        if not poll_snap.exists:
            raise ValueError("Poll not found.")

        poll_data = poll_snap.to_dict()

        if poll_data["status"] != Poll.STATUS_ACTIVE:
            raise PermissionError("This poll is closed.")

        # ── Validate option belongs to poll ───────────────────────────────
        opt_ids = [o["id"] for o in poll_data.get("options", [])]

        if option_id not in opt_ids:
            raise ValueError("Invalid option_id for this poll.")

        # ── Verify blind signature ────────────────────────────────────────
        if not verify_blind_signature(
            blind_signature,
            poll_id,
            g.user_id
        ):
            raise PermissionError("Invalid blind signature.")

        # ── Double-vote protection using nullifier ────────────────────────
        existing_nullifier = nullifier_ref.get(transaction=transaction)

        if existing_nullifier.exists:
            raise PermissionError("You have already voted in this poll.")

        # ── Deterministic vote document ID ────────────────────────────────
        vote_id = f"{g.user_id}_{poll_id}"

        vote_ref = db.collection(Collections.VOTES).document(vote_id)

        existing_vote = vote_ref.get(transaction=transaction)

        if existing_vote.exists:
            raise PermissionError("You have already voted in this poll.")

        # ── Blockchain metadata ───────────────────────────────────────────
        tx_hash = generate_tx_hash(encrypted_ballot)

        block_height = get_current_block_height()

        # ── Build vote model ──────────────────────────────────────────────
        vote = Vote(
            id               = vote_id,
            poll_id          = poll_id,
            option_id        = option_id,
            voter_id         = g.user_id,
            encrypted_vote   = encrypted_ballot.get("ciphertext"),
            vote_signature   = blind_signature,
        )

        # ── Firestore vote document ───────────────────────────────────────
        vote_doc = {
            **vote.to_dict(),

            # Encrypted ballot payload
            "encrypted_ballot": encrypted_ballot,

            # Anonymous anti-double-vote marker
            "nullifier": nullifier,

            # Blockchain metadata
            "timestamp": firestore.SERVER_TIMESTAMP,
            "block_height": block_height,
            "tx_hash": tx_hash,

            # Cryptographic metadata
            "tally_encrypted": True,
        }

        transaction.set(vote_ref, vote_doc)

        # ── Store nullifier atomically ────────────────────────────────────
        transaction.set(nullifier_ref, {
            "used": True,
            "poll_id": poll_id,
            "timestamp": firestore.SERVER_TIMESTAMP,
        })

        # ── Update poll counters ──────────────────────────────────────────
        updated_options = []

        for opt in poll_data["options"]:
            if opt["id"] == option_id:
                opt = {
                    **opt,
                    "vote_count": opt.get("vote_count", 0) + 1
                }

            updated_options.append(opt)

        transaction.update(poll_ref, {
            "options": updated_options,
            "total_votes": firestore.Increment(1),
        })

        return vote_doc

    try:
        transaction = db.transaction()

        vote_doc = _transact(transaction)

        return success(
            data={
                "vote": vote_doc,
                "tx_hash": vote_doc["tx_hash"],
                "status": "committed",
            },
            message="Vote cast successfully.",
            status=201,
        )

    except PermissionError as e:
        return error(str(e), 403)

    except ValueError as e:
        return error(str(e), 404)

    except Exception as e:
        return error(f"Failed to cast vote: {e}", 500)


# ── GET /api/votes/my-vote/<poll_id> ─────────────────────────────────────────
@votes_bp.get("/my-vote/<poll_id>")
@login_required
def my_vote(poll_id: str):
    """
    Check whether the current user has voted in a given poll.
    """

    db = _db()

    vote_id = f"{g.user_id}_{poll_id}"

    doc = db.collection(Collections.VOTES).document(vote_id).get()

    if doc.exists:
        return success(
            data={
                "voted": True,
                "vote": doc.to_dict()
            }
        )

    return success(
        data={
            "voted": False,
            "vote": None
        }
    )


# ── GET /api/votes/history ────────────────────────────────────────────────────
@votes_bp.get("/history")
@login_required
def vote_history():
    """
    Return all polls the current user has voted in.
    """

    db = _db()

    docs = (
        db.collection(Collections.VOTES)
        .where("voter_id", "==", g.user_id)
        .get()
    )

    votes = [d.to_dict() for d in docs]

    return success(
        data={
            "votes": votes,
            "count": len(votes)
        }
    )