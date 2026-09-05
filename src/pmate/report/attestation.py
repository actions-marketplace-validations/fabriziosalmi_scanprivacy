"""Signed attestation of a scan and its artefacts.

The reproducibility record already lets a reader recompute every digest. It
does not stop someone from editing the report *and* the digest together. An
attestation closes that: the digests are bound into an in-toto statement, the
statement is signed, and — with keyless signing — the signature is recorded in
a public transparency log. Altering an artefact afterwards is then detectable
by anyone, without trusting whoever sent it.

The chain each link of which is independently checkable:

    report states an evidence digest
      → statement binds that digest and the digest of every artefact
        → cosign signs the statement
          → Rekor records the signature

Fail-closed, as everywhere else in this engine: an unsigned statement is
labelled unsigned, in the file and in the exit code. A tool that let an
unsigned attestation pass for a signed one would be worse than one that does
not attest at all.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __version__
from ..core.models import ScanResult

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://privacymate.org/attestation/scan/v1"

SIGNATURE_NONE = "unsigned"
SIGNATURE_KEYLESS = "cosign-keyless"
SIGNATURE_KEY = "cosign-key"


class AttestationError(RuntimeError):
    """Raised when signing was asked for and could not be done.

    Never downgraded to a warning: a caller that asked for a signature and got
    a file without one must find out now, not when a recipient checks it.
    """


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(payload: dict[str, Any]) -> str:
    """What gets signed. Sorted keys and no incidental whitespace, so the bytes
    a verifier hashes are the bytes the signer signed."""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def cosign_available() -> bool:
    return shutil.which("cosign") is not None


@dataclass(frozen=True, slots=True)
class Signature:
    mode: str
    bundle_path: str | None = None
    certificate_identity: str | None = None
    certificate_oidc_issuer: str | None = None
    transparency_log: bool = False
    error: str | None = None

    @property
    def signed(self) -> bool:
        return self.mode in (SIGNATURE_KEYLESS, SIGNATURE_KEY)


def build_statement(
    result: ScanResult,
    artifacts: list[Path],
    produced_at: str | None = None,
) -> dict[str, Any]:
    """An in-toto statement whose subjects are the artefacts a recipient holds.

    The predicate carries the same facts the report prints, so a verifier never
    has to open the PDF to know what was claimed: target, verdict, counts, and
    every configuration digest that determined the analysis.
    """
    record = result.record or {}
    digests = record.get("digests") or {}
    verdict = result.verdict

    subjects = []
    for artifact in artifacts:
        path = Path(artifact)
        if not path.is_file():
            raise AttestationError(f"artefact does not exist: {path}")
        subjects.append({"name": path.name, "digest": {"sha256": file_digest(path)}})

    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "scan": {
                "scanId": result.scan_id,
                "url": result.url,
                "finalUrl": result.final_url,
                "startedAt": result.started_at,
                "finishedAt": result.finished_at,
                "status": result.status.value,
            },
            "verdict": {
                "grade": verdict.grade.value if verdict else None,
                "conformant": bool(verdict and verdict.conformant),
                "counts": verdict.counts if verdict else {},
                "findings": len(result.findings),
            },
            "digests": {
                "evidence": (record.get("evidence_digest") or {}).get("sha256"),
                "ruleset": digests.get("ruleset"),
                "knowledge": digests.get("knowledge"),
                "catalogues": digests.get("catalogues"),
            },
            "engine": record.get("engine") or {"engine": f"privacymate {__version__}"},
            "posture": record.get("posture") or {},
            "producedAt": produced_at or datetime.now(timezone.utc).isoformat(),
        },
    }


def _run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, timeout=180, **kwargs)


def sign_statement(statement_path: Path, mode: str, key: Path | None = None) -> Signature:
    """Sign with cosign. Keyless in CI, with a key elsewhere.

    Keyless signing needs an OIDC identity — GitHub Actions provides one when
    the job declares `id-token: write` — and publishes to Rekor, which is what
    makes the signature verifiable by a stranger.
    """
    if mode == SIGNATURE_NONE:
        return Signature(mode=SIGNATURE_NONE)
    if not cosign_available():
        raise AttestationError("signing was requested but cosign is not on PATH")

    bundle = statement_path.with_suffix(statement_path.suffix + ".sigbundle")
    command = ["cosign", "sign-blob", "--yes", "--bundle", str(bundle)]

    if mode == SIGNATURE_KEY:
        if key is None:
            raise AttestationError("--sign key requires --key <path to cosign.key>")
        if not Path(key).is_file():
            raise AttestationError(f"signing key not found: {key}")
        command += ["--key", str(key)]
    elif mode != SIGNATURE_KEYLESS:
        raise AttestationError(f"unknown signing mode: {mode}")

    command.append(str(statement_path))
    completed = _run(command)
    if completed.returncode != 0:
        raise AttestationError(f"cosign sign-blob failed: {completed.stderr.strip()[:500]}")

    identity = os.environ.get("GITHUB_WORKFLOW_REF") if mode == SIGNATURE_KEYLESS else None
    return Signature(
        mode=mode,
        bundle_path=str(bundle),
        certificate_identity=identity,
        certificate_oidc_issuer=(
            "https://token.actions.githubusercontent.com" if mode == SIGNATURE_KEYLESS else None
        ),
        transparency_log=(mode == SIGNATURE_KEYLESS),
    )


def write_attestation(
    result: ScanResult,
    artifacts: list[Path],
    out: Path,
    sign: str = SIGNATURE_NONE,
    key: Path | None = None,
) -> tuple[dict[str, Any], Signature]:
    statement = build_statement(result, artifacts)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(canonical_json(statement), encoding="utf-8")
    signature = sign_statement(out, sign, key)
    return statement, signature


# ---------------------------------------------------------------- verifying


@dataclass(slots=True)
class AttestationCheck:
    statement_valid: bool
    subjects_checked: int
    subjects_matching: int
    mismatched: list[str]
    missing: list[str]
    signature_mode: str
    signature_verified: bool | None  # None: not checked (no bundle, or no cosign)
    signature_detail: str = ""

    @property
    def ok(self) -> bool:
        """Fail-closed: an unverified signature is not a pass."""
        return (
            self.statement_valid
            and not self.mismatched
            and not self.missing
            and self.signature_verified is True
        )


def verify_attestation(
    statement_path: Path,
    artifacts_dir: Path | None = None,
    certificate_identity: str | None = None,
    certificate_oidc_issuer: str | None = None,
    public_key: Path | None = None,
) -> AttestationCheck:
    statement_path = Path(statement_path)
    raw = statement_path.read_text(encoding="utf-8")
    statement = json.loads(raw)

    valid = statement.get("_type") == STATEMENT_TYPE and statement.get("predicateType") == PREDICATE_TYPE
    base = Path(artifacts_dir) if artifacts_dir else statement_path.parent

    mismatched: list[str] = []
    missing: list[str] = []
    matching = 0
    subjects = statement.get("subject", [])
    for subject in subjects:
        artifact = base / subject["name"]
        if not artifact.is_file():
            missing.append(subject["name"])
            continue
        if file_digest(artifact) == subject["digest"]["sha256"]:
            matching += 1
        else:
            mismatched.append(subject["name"])

    bundle = statement_path.with_suffix(statement_path.suffix + ".sigbundle")
    signature_verified: bool | None = None
    mode = SIGNATURE_NONE
    detail = "no signature bundle next to the statement"

    if bundle.is_file():
        mode = SIGNATURE_KEY if public_key else SIGNATURE_KEYLESS
        if not cosign_available():
            detail = "signature present but cosign is not on PATH: not verified"
        else:
            command = ["cosign", "verify-blob", "--bundle", str(bundle)]
            if public_key:
                command += ["--key", str(public_key), "--insecure-ignore-tlog=true"]
            else:
                # keyless verification is only meaningful when the expected
                # identity is stated: anyone can sign anything with any identity
                command += [
                    "--certificate-identity-regexp",
                    certificate_identity or ".*",
                    "--certificate-oidc-issuer-regexp",
                    certificate_oidc_issuer or ".*",
                ]
            command.append(str(statement_path))
            completed = _run(command)
            signature_verified = completed.returncode == 0
            detail = (completed.stderr or completed.stdout).strip()[:300]

    return AttestationCheck(
        statement_valid=valid,
        subjects_checked=len(subjects),
        subjects_matching=matching,
        mismatched=mismatched,
        missing=missing,
        signature_mode=mode,
        signature_verified=signature_verified,
        signature_detail=detail,
    )
