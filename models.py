from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional
import uuid


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _uid() -> str:
    return str(uuid.uuid4())


# ── User ─────────────────────────────────────────────────────────────────────
@dataclass
class User:
    name:       str
    email:      str
    role:       str  = "voter"          # "voter" | "admin"
    id:         str  = field(default_factory=_uid)
    created_at: str  = field(default_factory=_now)
    is_active:  bool = True

    ROLES = ("voter", "admin")

    def to_dict(self) -> dict:
        return asdict(self)

    def public_dict(self) -> dict:
        return self.to_dict()

    @staticmethod
    def from_dict(data: dict) -> "User":
        return User(
            id         = data.get("id", _uid()),
            name       = data["name"],
            email      = data["email"],
            role       = data.get("role", "voter"),
            created_at = data.get("created_at", _now()),
            is_active  = data.get("is_active", True),
        )


# ── Poll Option ───────────────────────────────────────────────────────────────
@dataclass
class PollOption:
    text:       str
    id:         str = field(default_factory=_uid)
    vote_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "PollOption":
        return PollOption(
            id         = data.get("id", _uid()),
            text       = data["text"],
            vote_count = data.get("vote_count", 0),
        )


# ── Poll ──────────────────────────────────────────────────────────────────────
@dataclass
class Poll:
    question:    str
    created_by:  str
    options:     List[PollOption]

    # --- Core fields ---
    id:          str           = field(default_factory=_uid)
    description: str           = ""
    status:      str           = "active"       # "active" | "closed"
    created_at:  str           = field(default_factory=_now)
    closed_at:   Optional[str] = None
    expires_at:  Optional[str] = None
    total_votes: int           = 0

    # --- NEW: Category fields ---
    category:         Optional[str]      = None   # "state" | "corporate" | "parliament"
    subcategory:      Optional[str]      = None   # e.g. "Maharashtra" | "Lok Sabha"
    bill_number:      Optional[str]      = None   # parliament only
    company_name:     Optional[str]      = None   # corporate only
    sector:           Optional[str]      = None   # corporate only
    chamber:          Optional[str]      = None   # lok | rajya | joint
    eligible_states:  List[str]          = field(default_factory=list)

    # --- NEW: E2E Encryption fields ---
    election_public_key: Optional[str] = None
    blind_sig_public_key: Optional[str] = None
    homomorphic_enabled: bool = True
    tally_encrypted: bool = True
    encryption_scheme: str = "ECDH-AES256-GCM"

    STATUS_ACTIVE = "active"
    STATUS_CLOSED = "closed"

    CATEGORIES = ("state", "corporate", "parliament")

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "Poll":
        options = [PollOption.from_dict(o) for o in data.get("options", [])]

        return Poll(
            # --- Existing fields ---
            id          = data.get("id", _uid()),
            question    = data["question"],
            description = data.get("description", ""),
            created_by  = data["created_by"],
            options     = options,
            status      = data.get("status", "active"),
            created_at  = data.get("created_at", _now()),
            closed_at   = data.get("closed_at"),
            expires_at  = data.get("expires_at"),
            total_votes = data.get("total_votes", 0),

            # --- Category fields ---
            category        = data.get("category"),
            subcategory     = data.get("subcategory"),
            bill_number     = data.get("bill_number"),
            company_name    = data.get("company_name"),
            sector          = data.get("sector"),
            chamber         = data.get("chamber"),
            eligible_states = data.get("eligible_states", []),

            # --- Encryption fields ---
            election_public_key = data.get("election_public_key"),
            blind_sig_public_key = data.get("blind_sig_public_key"),
            homomorphic_enabled = data.get("homomorphic_enabled", True),
            tally_encrypted     = data.get("tally_encrypted", True),
            encryption_scheme   = data.get(
                "encryption_scheme",
                "ECDH-AES256-GCM"
            ),
        )


# ── Vote ──────────────────────────────────────────────────────────────────────
@dataclass
class Vote:
    poll_id:    str
    option_id:  str
    voter_id:   str
    id:         str = field(default_factory=_uid)
    cast_at:    str = field(default_factory=_now)

    # Optional encrypted ballot payload
    encrypted_vote: Optional[str] = None
    vote_signature: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "Vote":
        return Vote(
            id              = data.get("id", _uid()),
            poll_id         = data["poll_id"],
            option_id       = data["option_id"],
            voter_id        = data["voter_id"],
            cast_at         = data.get("cast_at", _now()),
            encrypted_vote  = data.get("encrypted_vote"),
            vote_signature  = data.get("vote_signature"),
        )


# ── OTP Record ────────────────────────────────────────────────────────────────
# ── OTP Record ────────────────────────────────────────────────────────────────
@dataclass
class OTPRecord:
    email:      str
    otp_hash:   str
    expires_at: str
    id:         str  = field(default_factory=_uid)
    used:       bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "OTPRecord":
        return OTPRecord(
            id         = data.get("id", _uid()),
            email      = data["email"],
            otp_hash   = data["otp_hash"],
            expires_at = data["expires_at"],
            used       = data.get("used", False),
        )