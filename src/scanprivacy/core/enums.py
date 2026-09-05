"""Canonical vocabularies.

These values are identifiers, not text. They are always English, they are
never shown to a user as they are, and they are the contract the API, the
rules and any future export format (SARIF, OSCAL) depend on. Display strings
for every member live in the locale catalogues under `i18n/locales/<lang>/`.

Adding a member here is a breaking change for consumers; renaming one is a
breaking change for every stored scan. Both are deliberate acts.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """How much the finding weighs in legal terms."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER[self]

    @property
    def blocking(self) -> bool:
        """Severities that prevent a conformant verdict."""
        return self in (Severity.CRITICAL, Severity.HIGH)


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Confidence(StrEnum):
    """Whether the engine states a fact or an indication.

    CERTAIN is reserved for what was directly observed. Anything inferred from
    text matching is PROBABLE — the difference is what keeps the report honest
    when a supplier pushes back.
    """

    CERTAIN = "certain"
    PROBABLE = "probable"


class Effort(StrEnum):
    """How much work the fix takes, from the point of view of whoever does it."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Priority(StrEnum):
    """Backlog order: severity corrected for effort. Not a legal measure."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"


class Owner(StrEnum):
    """Who holds the lever to close the finding — not who is legally liable."""

    DPO = "dpo"
    CTO = "cto"
    SYSOPS = "sysops"
    SECURITY = "security"
    LEGAL = "legal"
    PROCUREMENT = "procurement"


class SubjectKind(StrEnum):
    """What a rule iterates over."""

    SITE = "site"
    VENDOR = "vendor"
    COOKIE = "cookie"
    STORAGE = "storage"
    FORM = "form"


class ConsentClass(StrEnum):
    """Whether prior consent is needed before the service may load.

    UNCERTAIN is a first-class answer: some services are defensible either
    way, and the engine reports them without pretending to settle the point.
    """

    REQUIRED = "required"
    TECHNICAL = "technical"
    UNCERTAIN = "uncertain"


class TransferScope(StrEnum):
    """Where the recipient processes the data, in GDPR terms."""

    EEA = "eea"
    ADEQUACY = "adequacy"  # third country covered by an adequacy decision
    NON_EEA = "non_eea"


class DataClass(StrEnum):
    """What a cookie or storage key is, as far as can be told from outside."""

    TRACKING = "tracking"
    FUNCTIONAL = "functional"
    UNKNOWN = "unknown"


class VendorCategory(StrEnum):
    ANALYTICS = "analytics"
    ADS = "ads"
    FONTS = "fonts"
    CDN = "cdn"
    TAG_MANAGER = "tag_manager"
    CAPTCHA = "captcha"
    EMBED = "embed"
    SOCIAL = "social"
    MAPS = "maps"
    MEDIA = "media"
    CHAT = "chat"
    FORMS = "forms"
    PAYMENTS = "payments"
    CONSENT = "consent"
    EMAIL = "email"
    INFRA = "infra"
    SECURITY = "security"
    IDENTITY = "identity"


class Detection(StrEnum):
    """How the vendor came to our attention. Changes what the evidence is."""

    REQUEST = "request"  # the browser contacted it
    HEADER = "header"  # only visible in the response headers (CDN, hosting)


class FindingStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"


class Grade(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
    INCONCLUSIVE = "INCONCLUSIVE"


class ScanStatus(StrEnum):
    OK = "ok"
    UNREACHABLE = "unreachable"
    ROBOTS_SKIP = "robots_skip"
    ERROR = "error"


class DocumentKind(StrEnum):
    PRIVACY = "privacy"
    COOKIE = "cookie"
    TERMS = "terms"
    ACCESSIBILITY = "accessibility"


class DataType(StrEnum):
    """Categories of personal data leaving the browser. Keys, not prose: the
    description of each lives in the locale catalogue."""

    IP = "ip"
    USER_AGENT = "user_agent"
    REFERER = "referer"
    PAGE_VIEWED = "page_viewed"
    CLIENT_ID = "client_id"
    BROWSING_HISTORY = "browsing_history"
    SESSION_RECORDING = "session_recording"
    MOUSE_MOVEMENTS = "mouse_movements"
    FINGERPRINTING = "fingerprinting"
    AD_IDENTIFIERS = "ad_identifiers"
    INFERRED_INTERESTS = "inferred_interests"
    EMAIL = "email"
    FORM_ANSWERS = "form_answers"
    CONVERSATIONS = "conversations"
    CONSENT_PROOF = "consent_proof"
    APPROXIMATE_LOCATION = "approximate_location"
    REQUESTED_LOCATION = "requested_location"
    ANTIFRAUD_SIGNALS = "antifraud_signals"
    DEVICE_IDENTIFIERS = "device_identifiers"
    REQUEST_METADATA = "request_metadata"
    AGGREGATED_METRICS = "aggregated_metrics"
    VIDEOS_WATCHED = "videos_watched"
    OPEN_RATE = "open_rate"
    COMMENTS = "comments"
    EMAIL_HASH = "email_hash"
    VISITOR_ID = "visitor_id"
    # identity surface: what an authentication flow discloses
    IDENTITY_ATTRIBUTES = "identity_attributes"
    ACCOUNT_IDENTIFIER = "account_identifier"
    AUTHENTICATION_EVENTS = "authentication_events"


# Every enum that has display strings in the locale catalogues, so a test can
# assert the catalogues are complete instead of discovering a gap in a PDF.
LOCALISED_ENUMS: tuple[type[StrEnum], ...] = (
    Severity,
    Confidence,
    Effort,
    Owner,
    ConsentClass,
    TransferScope,
    DataClass,
    VendorCategory,
    Detection,
    FindingStatus,
    Grade,
    ScanStatus,
    DocumentKind,
    DataType,
)
