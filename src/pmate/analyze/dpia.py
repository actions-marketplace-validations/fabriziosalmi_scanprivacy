"""Screening for a data protection impact assessment, and prompts for transfers.

Two work products, both deliberately incomplete, and honest about it.

**DPIA screening.** The EDPB (WP248 rev.01) lists nine criteria; two or more met
usually means an assessment is due. Some of them are visible from outside — a
profiling vendor, a session recorder, systematic monitoring across pages, an AI
component. Others are not visible from any distance: scale, vulnerable subjects,
special categories, legal effects. This module reports the ones it observed
**and names the ones it could not assess**, so the reader knows what is still
theirs to answer. A screening that presented itself as complete would be worse
than none: it would let someone conclude "no DPIA needed" from evidence that
never covered the question.

**Transfer prompts.** For every recipient outside the EEA, the questions a
transfer impact assessment has to answer, pre-filled with what was observed:
who, where, what data, on what basis, and — where the knowledge base has one —
whether an equivalent exists that would remove the transfer instead of
documenting it. The cheapest transfer impact assessment is the transfer you do
not make.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..core.enums import DataType, TransferScope, VendorCategory
from .context import Context

# WP248 rev.01, in the order the guidelines list them. `observable` says whether
# this engine can see the criterion from outside at all — the honest half of the
# screening lives in that flag.
CRITERIA: tuple[tuple[str, bool], ...] = (
    ("evaluation_scoring", True),
    ("automated_decision", False),
    ("systematic_monitoring", True),
    ("sensitive_data", False),
    ("large_scale", False),
    ("matching_combining", True),
    ("vulnerable_subjects", False),
    ("innovative_technology", True),
    ("prevents_rights", False),
)

# Session recording captures what a person typed, hovered over and hesitated on.
# It is the one observable signal that reaches the "highly personal nature" of
# criterion 4 without seeing the data itself.
_RECORDING_TYPES = frozenset({DataType.SESSION_RECORDING, DataType.MOUSE_MOVEMENTS})


@dataclass(slots=True)
class Criterion:
    key: str
    met: bool
    observable: bool
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DpiaScreening:
    criteria: list[Criterion] = field(default_factory=list)

    @property
    def met(self) -> list[Criterion]:
        return [c for c in self.criteria if c.met]

    @property
    def not_assessable(self) -> list[Criterion]:
        return [c for c in self.criteria if not c.observable]

    @property
    def threshold_reached(self) -> bool:
        """Two or more met criteria: the EDPB's own rule of thumb."""
        return len(self.met) >= 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "criteria": [asdict(c) for c in self.criteria],
            "met": [c.key for c in self.met],
            "not_assessable": [c.key for c in self.not_assessable],
            "threshold_reached": self.threshold_reached,
        }


@dataclass(slots=True)
class TransferAssessment:
    vendor_id: str
    product: str
    vendor: str | None
    vendor_key: str | None
    jurisdiction: str
    transfer: str
    transfer_basis: str | None
    data_types: list[str]
    declared: bool
    alternatives: list[str] = field(default_factory=list)
    """Equivalents from the knowledge base. The cheapest transfer impact
    assessment is the transfer you do not make."""


def screen(ctx: Context) -> DpiaScreening:
    screening = DpiaScreening()
    third_parties = ctx.third_party_vendors

    profiling = [
        fact
        for fact in third_parties
        if fact.vendor.category in (VendorCategory.ADS,)
        or DataType.INFERRED_INTERESTS in fact.vendor.data_types
        or DataType.AD_IDENTIFIERS in fact.vendor.data_types
    ]
    recording = [
        fact for fact in third_parties if _RECORDING_TYPES & set(fact.vendor.data_types)
    ]
    analytics = [fact for fact in third_parties if fact.vendor.category is VendorCategory.ANALYTICS]
    tag_managers = [
        fact for fact in third_parties if fact.vendor.category is VendorCategory.TAG_MANAGER
    ]
    tracking_state = [c for c in ctx.cookies if c.data_class.value == "tracking"]
    tracking_state += [s for s in ctx.storage if s.data_class.value == "tracking"]
    multi_page_tracking = [
        fact for fact in third_parties if len(fact.pages) > 1 and fact.vendor.storage_access
    ]

    def add(key: str, met: bool, evidence: list[str]) -> None:
        observable = dict(CRITERIA)[key]
        satisfied = bool(met and observable)
        screening.criteria.append(
            Criterion(
                key=key,
                met=satisfied,
                observable=observable,
                # Evidence belongs to a criterion that is actually met. Listing
                # what was observed next to a "not met" row reads as a finding
                # the engine then declines to draw, which is worse than silence.
                evidence=sorted(set(evidence)) if satisfied else [],
            )
        )

    add(
        "evaluation_scoring",
        bool(profiling),
        [f"{fact.vendor.product}" for fact in profiling],
    )
    add("automated_decision", False, [])
    add(
        "systematic_monitoring",
        bool(recording or (tracking_state and multi_page_tracking)),
        [f"{fact.vendor.product}" for fact in recording + multi_page_tracking],
    )
    add("sensitive_data", False, [])
    add("large_scale", False, [])
    add(
        "matching_combining",
        bool(tag_managers) or len(analytics) > 1,
        [f"{fact.vendor.product}" for fact in tag_managers + analytics],
    )
    add("vulnerable_subjects", False, [])
    add(
        "innovative_technology",
        bool({"ai-chat-widget"} & set(ctx.ai_markers)),
        list(ctx.ai_markers),
    )
    add("prevents_rights", False, [])
    return screening


def transfer_assessments(ctx: Context) -> list[TransferAssessment]:
    out: list[TransferAssessment] = []
    for fact in sorted(ctx.third_party_vendors, key=lambda f: f.vendor.id):
        if fact.transfer is TransferScope.EEA:
            continue
        vendor = fact.vendor
        out.append(
            TransferAssessment(
                vendor_id=vendor.id,
                product=vendor.product,
                vendor=vendor.vendor,
                vendor_key=vendor.vendor_key,
                jurisdiction=vendor.jurisdiction,
                transfer=fact.transfer.value,
                transfer_basis=vendor.transfer_basis,
                data_types=[d.value for d in vendor.data_types],
                declared=fact.declared,
                alternatives=list(vendor.remediation.alternatives),
            )
        )
    return out
