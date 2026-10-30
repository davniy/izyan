"""Offline validator for the structured Evidence Contract (spec §4,
plan §4/§8 — phase 6.2; NOT a production Gate).

Runs four purely structural checks over a saved attempt's
``(agent_assessment, audit_records, observations, snapshot_hash,
advisory_record)`` — no LLM, no ground truth, no model calls, and the
agent's answer is NEVER mutated (the validator result is stored
alongside it):

    C1  Schema/ref existence + snapshot hash.  Every cited ref must
        resolve: ``ev:OBS-NNNN`` → a minted observation in the audit
        trail; ``sha256:<hex>`` → an ``Observation.evidence_refs``
        entry; ``src:<path>#L<line>@<hash>`` → hash must equal the
        attempt's snapshot hash AND the path must exist in the
        snapshot file index when one is provided — without an index
        the path is unverifiable (never snapshot-bound).
        Unresolved/forged refs → ``INVALID_EVIDENCE``.

    C2  No ERROR / UNKNOWN / PARTIAL / missing-completeness as
        evidence.  An observation supports a negative claim only when
        ``tool_status`` is OK/NOT_FOUND AND ``completeness`` is exactly
        ``COMPLETE`` — an ERROR/UNSUPPORTED status, an UNKNOWN or
        PARTIAL completeness, or a MISSING completeness field is never
        evidence of absence (the error-as-absence mechanism).  PARTIAL
        enumerations are flagged for C3.

    C3  Subject/scope/build-context match.  The claim's ``subject``
        must relate to the cited observation's ``ScopeDetails.Subject``
        AND the claim's declared ``scope`` must stay inside the
        observation's declared boundaries — a claim asserting a global
        property may not rest on a product-only / dependency-internal /
        package-subset / single-build-context enumeration, and an
        explicit claim GOOS/GOARCH/build-tag must be covered by the
        observation's BuildContext → ``SCOPE_MISMATCH``.

    C4  Safe-verdict falsifier + declared-scope coverage.  A safe
        ``category`` needs (a) at least one negative claim that
        survives C1–C3 bound to real evidence and (b) the advisory's
        declared scope: every subject the advisory declares affected
        covered by such a claim — ``COMPLETE`` observation coverage or
        a snapshot-bound source ref.  A missing advisory record (or
        one declaring no affected subjects) is NOT vacuous coverage —
        absent declared scope → ``INSUFFICIENT_EVIDENCE``.  Semantic
        correctness beyond the loaded scope (dynamic dispatch,
        interface resolution, dependency-internal paths, other build
        configurations, reflection/linkname/cgo) → ``UNVERIFIABLE`` —
        abstain, never auto-accepted and never proven.

Decision precedence (worst-of, per attempt):
INVALID_EVIDENCE > SCOPE_MISMATCH > INSUFFICIENT_EVIDENCE >
UNVERIFIABLE > ACCEPTED.

Generality: no case names, no product identifiers, no task ids —
only the structured claim fields and the audit trail
(docs/agent-rules/generality.md is binding).  Smoke cases are test
fixtures only, never validator logic.
"""

from __future__ import annotations

import re
from typing import Iterable, Literal, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from .assessment_v2 import (
    AgentAssessmentV2,
    AssessmentPayloadV2,
    ExtractionResultV2,
    NegativeClaim,
    SAFE_CATEGORIES,
    split_src_ref,
)

VALIDATOR_VERSION = "task6-validator/1"

Decision = Literal[
    "ACCEPTED",
    "INSUFFICIENT_EVIDENCE",
    "UNVERIFIABLE",
    "INVALID_EVIDENCE",
    "SCOPE_MISMATCH",
]

# Worst-first ordering; index is the rank used for max().
_DECISION_RANK: tuple[Decision, ...] = (
    "INVALID_EVIDENCE",
    "SCOPE_MISMATCH",
    "INSUFFICIENT_EVIDENCE",
    "UNVERIFIABLE",
    "ACCEPTED",
)

# ---------------------------------------------------------------------------
# Observation classification vocabularies (generic — mechanism classes
# from the evidence-tools contract, never case/product identifiers)
# ---------------------------------------------------------------------------

# Claim-scope words that mean "the whole reachable universe" — a global
# assertion.  Word-boundary regex so "global" matches but a scope that
# merely mentions a package containing these characters does not.
_GLOBAL_SCOPE_RE = re.compile(
    r"\b(global(?:ly)?|all\b[^.;]*|every|any\b[^.;]*|entire|whole|"
    r"throughout|no\s+call(?:er|s)?\s+(?:in|from|anywhere)|"
    r"nowhere|unreachable\b[^.;]*$)", re.IGNORECASE)

# Words that mark an OBSERVATION's declared scope as a narrowed
# enumeration (product-only, dep-internal, single build context...).
_NARROW_SCOPE_RE = re.compile(
    r"(only\b|product\s+packages|dependency-internal|dep-internal|"
    r"own\s+(?:package|module|frame)|loaded\s+(?:\.\/\.\.\.\s+)?roots|"
    r"not\s+covered|out\s+of\s+scope|this\s+snapshot's|"
    r"single\s+advisory|intra-module|within\s+the\s+module|"
    r"bounded\s+by|capped\s+at)", re.IGNORECASE)

# Semantic-opaque mechanisms (spec §4 UNVERIFIABLE list): evidence whose
# completeness cannot be established by the loaded scope.
_OPAQUE_SCOPE_RE = re.compile(
    r"(dynamic(?:ally)?|interface[-\s]?dispatch|reflect(?:ion)?|"
    r"linkname|cgo|unsafe|plugin|func[-\s]?value|goroutine|"
    r"other\s+build|build\s+configuration|tagged-out|unresolved|"
    r"not\s+enumerated)", re.IGNORECASE)

# Observation ``data`` keys carrying an enumeration count — a zero
# there means "empty result set" (shared semantics with freeze.py).
_ZERO_COUNT_KEYS = ("count", "possible_count", "callers_inside_module",
                    "matches")

# List keys whose bare-string members are affected subjects (plural
# forms of the leaf subject keys — ``affected_symbols: ["pkg.Fn"]``).
_SUBJECT_LIST_KEYS = frozenset({
    "affected_symbols", "affected_modules", "affected_packages",
    "symbols", "modules", "packages", "affected_subjects"})

# tool_status values that mean "the check ran and produced a result".
_USABLE_STATUS = frozenset({"OK", "NOT_FOUND"})

# Advisory-record leaf keys that name an affected subject or a fixed
# version (OSV-style; only collected below an ``affected*`` ancestor).
_AFFECTED_SUBJECT_KEYS = frozenset(
    {"module", "package", "symbol", "name", "path", "package_name"})
_FIXED_VERSION_KEYS = frozenset(
    {"fixed", "fixed_version", "fixed_versions", "patched"})


class ClaimVerdict(BaseModel):
    """Validator projection of ONE negative claim."""

    model_config = ConfigDict(extra="forbid")

    predicate: str
    subject: str
    scope: str
    evidence_refs: list[str] = Field(default_factory=list)
    resolved_refs: list[str] = Field(default_factory=list)
    binding: Literal["audit", "snapshot", "self_declared", "none"] = "none"
    supported: bool = False
    decision: Optional[Decision] = None   # worst defect on this claim
    defects: list[str] = Field(default_factory=list)


class CoverageEntry(BaseModel):
    """One advisory-declared affected subject and how it is covered."""

    model_config = ConfigDict(extra="forbid")

    subject: str
    status: Literal["audit_complete", "declared", "unverifiable",
                    "uncovered"]
    by: Optional[str] = None     # "claim[i] via <ref>" when covered


class CoverageReport(BaseModel):
    """The C4 coverage summary over the advisory's declared scope."""

    model_config = ConfigDict(extra="forbid")

    declared_subjects: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    entries: list[CoverageEntry] = Field(default_factory=list)
    advisory_present: bool = False


class ValidatorResult(BaseModel):
    """The stored validator verdict — alongside, never replacing, the
    agent's ``category``."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision
    category: Optional[str] = None
    safe_verdict: bool = False
    per_claim: list[ClaimVerdict] = Field(default_factory=list)
    falsifier: dict = Field(default_factory=dict)
    coverage: CoverageReport = Field(default_factory=CoverageReport)
    reason: str = ""
    validator_version: str = VALIDATOR_VERSION


# ---------------------------------------------------------------------------
# Observation index
# ---------------------------------------------------------------------------


def _flat_observations(
    observations: Optional[Sequence[dict]],
    audit_records: Optional[Sequence[dict]],
) -> list[dict]:
    """Flattened Observation rows; audit records contribute their
    ``observation`` field so ev: refs resolve from either input."""
    out: list[dict] = []
    for rec in audit_records or ():
        obs = rec.get("observation")
        if isinstance(obs, dict):
            out.append(obs)
    for obs in observations or ():
        if isinstance(obs, dict):
            out.append(obs)
    seen, uniq = set(), []
    for obs in out:
        oid = obs.get("id")
        key = oid if isinstance(oid, str) else id(obs)
        if key not in seen:
            seen.add(key)
            uniq.append(obs)
    return uniq


def _obs_index(obs: Sequence[dict]) -> dict[str, dict]:
    return {o["id"]: o for o in obs if isinstance(o.get("id"), str)}



def _is_empty_result(obs: dict) -> bool:
    """True iff the observation's ``data`` carries a zero enumeration —
    an empty result set, usable only within its declared scope."""
    data = obs.get("data")
    if not isinstance(data, dict):
        return False
    return any(
        isinstance(data.get(k), (int, float)) and data[k] == 0
        for k in _ZERO_COUNT_KEYS
    )


def _obs_scope_text(obs: dict) -> str:
    """Every string the observation uses to declare its scope."""
    sd = obs.get("scope_details")
    sd = sd if isinstance(sd, dict) else {}
    parts = [obs.get("scope"), sd.get("coverage_rule")]
    parts.extend(obs.get("limitations") or [])
    parts.extend(str(v) for v in sd.get("extra", {}).values()
                 if isinstance(v, str))
    return " ".join(str(p) for p in parts if p)


def _obs_subject(obs: dict) -> Optional[str]:
    sd = obs.get("scope_details")
    if isinstance(sd, dict) and isinstance(sd.get("subject"), str):
        return sd["subject"]
    return None


def _is_opaque(obs: dict) -> bool:
    text = _obs_scope_text(obs) + " " + str(obs.get("tool", ""))
    return bool(_OPAQUE_SCOPE_RE.search(text))


def _is_narrow(obs: dict) -> bool:
    return bool(_NARROW_SCOPE_RE.search(_obs_scope_text(obs)))


# ---------------------------------------------------------------------------
# Subject relation and advisory parsing (generic)
# ---------------------------------------------------------------------------


_SEPS = frozenset("./:<>*?@ ")


def _bounded_contains(hay: str, needle: str) -> bool:
    """``needle`` inside ``hay`` with token boundaries on both sides."""
    if not needle:
        return False
    start = 0
    while True:
        i = hay.find(needle, start)
        if i < 0:
            return False
        left_ok = i == 0 or hay[i - 1] in _SEPS
        right_ok = i + len(needle) == len(hay) or hay[i + len(needle)] in _SEPS
        if left_ok and right_ok:
            return True
        start = i + 1


def _subjects_related(claim_subject: str, other: str) -> bool:
    """Loose subject equality: same module/package/symbol/file written
    two ways (``pkg/sub.Mod`` ↔ ``pkg/sub``; ``/work/...`` stripped)."""
    a = (claim_subject or "").strip()
    b = (other or "").strip()
    if not a or not b:
        return True        # nothing to contradict
    a = a.removeprefix("/work/").lstrip("/")
    b = b.removeprefix("/work/").lstrip("/")
    if a == b:
        return True
    return _bounded_contains(a, b) or _bounded_contains(b, a)


def declared_affected(advisory_record: Optional[dict]) -> dict:
    """Normalize an OSV-style advisory record into
    ``{subjects, fixed_versions}``.

    Only leaf strings under an ``affected*`` ancestor count as subjects
    (``affected[].package.name``, ``affected[].module``,
    ``affected_symbols[]``, ``affected_modules[]``...); ``fixed`` /
    ``fixed_version(s)`` / ``patched`` leaf values count as fixed
    versions.  The whole ``get_vulnerability`` ``data`` record is
    accepted — the walk is shape-agnostic; no benchmark GT.
    """
    subjects: list[str] = []
    fixed: list[str] = []

    def walk(node, in_affected: bool, parent_key: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                kl = str(k).lower()
                aff = in_affected or kl.startswith("affected")
                if aff and kl in _AFFECTED_SUBJECT_KEYS \
                        and isinstance(v, str) and v.strip():
                    subjects.append(v.strip())
                elif aff and kl in _FIXED_VERSION_KEYS:
                    for x in v if isinstance(v, list) else [v]:
                        if isinstance(x, str) and x.strip():
                            fixed.append(x.strip())
                else:
                    walk(v, aff, kl)
        elif isinstance(node, list):
            for v in node:
                # bare strings count as subjects only under a
                # subject-ish key — ``affected[].versions`` lists are
                # NOT subjects
                if isinstance(v, str) and v.strip() and in_affected \
                        and parent_key in _SUBJECT_LIST_KEYS:
                    subjects.append(v.strip())
                else:
                    walk(v, in_affected, parent_key)

    if isinstance(advisory_record, dict):
        walk(advisory_record, False)

    def dedup(xs: Iterable[str]) -> list[str]:
        return sorted(set(xs))
    return {"subjects": dedup(subjects), "fixed_versions": dedup(fixed)}


# Build-axis tokens a claim scope can name — a claim asserting a
# different GOOS/GOARCH or an unpinned build tag than the observation
# ran under is broader than the evidence (C3).
_GOOS_TOKENS = frozenset({
    "aix", "android", "darwin", "dragonfly", "freebsd", "illumos",
    "ios", "linux", "netbsd", "openbsd", "plan9", "solaris", "windows",
    "wasip1", "js"})
_GOARCH_TOKENS = frozenset({
    "386", "amd64", "arm", "arm64", "loong64", "mips", "mips64",
    "mips64le", "mipsle", "ppc64", "ppc64le", "riscv64", "s390x",
    "wasm"})


# ---------------------------------------------------------------------------
# C1 — ref resolution
# ---------------------------------------------------------------------------

# ref binding kinds: audit = resolves to a recorded observation,
# snapshot = bound to meta.snapshot_hash / confirmed snapshot file,
# self_declared = agent-written, existence not machine-checked here,
# invalid = forged/dangling/contradictory.

def _resolve_ref(
    ref: str,
    obs_by_id: dict[str, dict],
    owners: dict[str, list[dict]],
    snapshot_hash: Optional[str],
    snapshot_files: Optional[set[str]],
) -> tuple[str, list[dict], Optional[str]]:
    """Resolve one evidence ref → (binding, owner_obs, defect)."""
    if ref.startswith("ev:"):
        obs = obs_by_id.get(ref[3:])
        if obs is None:
            return "invalid", [], (
                f"evidence ref {ref!r} names an observation id not in "
                "the attempt audit trail")
        return "audit", [obs], None

    if ref.startswith("sha256:"):
        owners_of = owners.get(ref) or []
        if not owners_of:
            return "invalid", [], (
                f"sha256 ref {ref[:19]}… not minted by any observation "
                "in the audit trail")
        return "audit", owners_of, None

    if ref.startswith("src:"):
        parsed = split_src_ref(ref)
        if parsed is None:
            return "invalid", [], f"unparseable src ref {ref!r}"
        path, _line, ref_hash = parsed
        owners_of = owners.get(ref) or []
        if ref_hash is not None:
            if snapshot_hash is not None and ref_hash != snapshot_hash:
                return "invalid", [], (
                    f"src ref {ref!r} carries snapshot hash "
                    f"{ref_hash[:16]}… != attempt snapshot hash")
            if snapshot_files is None:
                # F2/N2: a hash-bound src ref needs the snapshot file
                # index to bind — owner-minted or not, existence is
                # unverifiable without it; never audit/snapshot-bind
                if snapshot_hash is None:
                    return "self_declared", [], (
                        f"src ref {ref!r} carries a snapshot hash that "
                        "cannot be verified — no attempt snapshot hash "
                        "was supplied to the validator")
                return "self_declared", [], (
                    f"src ref {ref!r} binds the attempt snapshot hash "
                    "but the path's existence is unverifiable — no "
                    "snapshot file index was supplied to the validator")
            rel = path.removeprefix("/work/").removeprefix("/")
            if rel not in snapshot_files and path not in snapshot_files:
                return "invalid", [], (
                    f"src ref {ref!r} names a file absent from the "
                    "attempt snapshot index")
            if snapshot_hash is None:
                return "self_declared", [], (
                    f"src ref {ref!r} carries a snapshot hash that "
                    "cannot be verified — no attempt snapshot hash "
                    "was supplied to the validator")
            if owners_of:
                # a tool actually minted this bound ref — verified hash
                # AND index-confirmed path
                return "audit", owners_of, None
            return "snapshot", [], None
        if owners_of:
            # tool-minted live form (no @hash)
            return "audit", owners_of, None
        return "self_declared", [], (
            f"src ref {ref!r} carries no snapshot hash — existence "
            "unverifiable without @<snapshot-hash>")

    if ref.startswith("file:"):
        path = ref[5:]
        # grammar already enforced: strip trailing :<line>[-<line>]
        m = re.match(r"^(.*?)(?::\d+(?:-\d+)?)?$", path)
        fpath = m.group(1) if m else path
        if snapshot_files is not None:
            rel = fpath.removeprefix("/work/").removeprefix("/")
            if rel not in snapshot_files and fpath not in snapshot_files:
                return "invalid", [], (
                    f"file ref {ref!r} names a path absent from the "
                    "attempt snapshot index")
            return "snapshot", [], None
        return "self_declared", [], None

    if ref.startswith("url:"):
        return "self_declared", [], None

    return "invalid", [], f"unresolvable evidence ref {ref!r}"


# ---------------------------------------------------------------------------
# Claim adjudication (C1 → C2 → C3)
# ---------------------------------------------------------------------------


def _claim_is_global(claim: NegativeClaim) -> bool:
    return bool(_GLOBAL_SCOPE_RE.search(claim.scope))


def _claim_build_axes(scope: str) -> dict:
    """Build-context axes a claim's free-text scope explicitly names —
    goos/goarch tokens (word-boundary) and ``build tag`` phrases."""
    text = " " + re.sub(r"[^a-zA-Z0-9_+.-]+", " ", scope.lower()) + " "
    words = text.split()
    axes: dict[str, set[str]] = {}
    goos = {w for w in words if w in _GOOS_TOKENS}
    if goos:
        axes["goos"] = goos
    goarch = {w for w in words if w in _GOARCH_TOKENS}
    if goarch:
        axes["goarch"] = goarch
    tags: set[str] = set()
    for m in re.finditer(
            r"build[\s_-]?tags?\s*[:=]?\s*([a-zA-Z0-9_,+ .-]+)", scope,
            re.IGNORECASE):
        tags.update(
            t for t in re.split(r"[,\s]+", m.group(1).strip()) if t)
    if tags:
        axes["build_tags"] = tags
    return axes


def _obs_build_context(obs: dict) -> dict:
    """The observation's declared build context (ScopeDetails.BuildContext)."""
    sd = obs.get("scope_details")
    bc = (sd or {}).get("build_context") if isinstance(sd, dict) else None
    return bc if isinstance(bc, dict) else {}


def _scope_breach(claim: NegativeClaim, obs: dict) -> Optional[str]:
    """C3 scope check — a defect string when the claim's declared scope
    exceeds the observation's declared boundaries, else None.

    Compared axes (observation side): narrowed-scope text markers,
    scope_details.packages subset, ScopeDetails.BuildContext
    (goos/goarch/build_tags). Claim side: global-scope markers and any
    explicitly named build axis. A named axis the observation doesn't
    establish (absent OR different) is a mismatch — same rule as
    build_tags.
    """
    obs_id = obs.get("id", "?")
    # (a) explicit build-axis contradiction
    axes = _claim_build_axes(claim.scope)
    bc = _obs_build_context(obs)
    if "goos" in axes and bc.get("goos") not in axes["goos"]:
        return (f"{obs_id}: claim scope {claim.scope!r} names "
                f"{sorted(axes['goos'])} but the observation ran "
                f"under GOOS={bc.get('goos')!r}")
    if "goarch" in axes and bc.get("goarch") not in axes["goarch"]:
        return (f"{obs_id}: claim scope {claim.scope!r} names "
                f"{sorted(axes['goarch'])} but the observation ran "
                f"under GOARCH={bc.get('goarch')!r}")
    if "build_tags" in axes:
        obs_tags = set(bc.get("build_tags") or [])
        missing = sorted(axes["build_tags"] - obs_tags)
        if missing:
            return (f"{obs_id}: claim scope {claim.scope!r} requires "
                    f"build tags {missing} the observation did not run "
                    f"under (observed build_tags={sorted(obs_tags)})")
    # (b) claim subject outside the observation's package subset
    sd = obs.get("scope_details")
    pkgs = (sd or {}).get("packages") if isinstance(sd, dict) else None
    if isinstance(pkgs, list) and pkgs and \
            all(isinstance(p, str) for p in pkgs):
        if not any(_subjects_related(claim.subject, p) for p in pkgs):
            return (f"{obs_id}: claim subject {claim.subject!r} is "
                    f"outside the observation's enumerated packages "
                    f"{sorted(pkgs)!r}")
    # (c) global claim resting on a narrowed observation
    narrowed = (_is_narrow(obs)
                or (isinstance(pkgs, list) and bool(pkgs))
                or bool(_obs_build_context(obs)))
    if _claim_is_global(claim) and narrowed:
        return (f"{obs_id}: claim scope {claim.scope!r} asserts a "
                f"global property but the observation's declared scope "
                f"({obs.get('scope')!r}) is narrowed — scoped evidence "
                "cannot generalize")
    return None


def _adjudicate_claim(
    claim: NegativeClaim,
    obs_by_id: dict[str, dict],
    owners: dict[str, list[dict]],
    snapshot_hash: Optional[str],
    snapshot_files: Optional[set[str]],
) -> ClaimVerdict:
    """Run C1→C2→C3 over one claim; the returned verdict carries the
    worst defect and the binding level of its surviving evidence."""
    defects: list[str] = []
    decisions: list[Decision] = []
    binding = "none"
    bound_obs: list[dict] = []
    resolved_refs: list[str] = []

    for ref in claim.evidence_refs:
        kind, owners_of, defect = _resolve_ref(
            ref, obs_by_id, owners, snapshot_hash, snapshot_files)
        if defect is not None:
            defects.append(defect)
        if kind == "invalid":
            decisions.append("INVALID_EVIDENCE")
            continue
        resolved_refs.append(ref)
        bound_obs.extend(owners_of)
        if kind == "audit":
            binding = "audit"
        elif kind == "snapshot" and binding != "audit":
            binding = "snapshot"
        elif binding == "none":
            binding = "self_declared"

    # C2 — error/unknown/partial/empty must not read as global absence.
    unverifiable_seen = False
    for obs in bound_obs:
        oid = obs.get("id", "?")
        status = obs.get("tool_status")
        completeness = obs.get("completeness")
        if status not in _USABLE_STATUS:
            decisions.append("INSUFFICIENT_EVIDENCE")
            defects.append(
                f"{oid}: tool_status {status!r} — a failed/unsupported "
                "check is not evidence of absence (error-as-absence)")
            continue
        if completeness == "UNKNOWN":
            decisions.append("INSUFFICIENT_EVIDENCE")
            defects.append(
                f"{oid}: completeness UNKNOWN — unknown enumeration "
                "cannot support a negative claim")
            continue
        if completeness == "PARTIAL":
            # C3 — scoped evidence vs. the claim's declared scope.
            if _claim_is_global(claim):
                decisions.append("SCOPE_MISMATCH")
                defects.append(
                    f"{oid}: claim scope {claim.scope!r} asserts a "
                    f"global property but {obs.get('scope')!r} is a "
                    "narrowed (PARTIAL) enumeration — scoped-zero "
                    "cannot generalize")
            else:
                unverifiable_seen = True
                defects.append(
                    f"{oid}: completeness PARTIAL — scope-limited "
                    "evidence cannot prove a negative in its own "
                    "bounds either" if _is_opaque(obs) else
                    f"{oid}: completeness PARTIAL — enumeration was "
                    "bounded; absence inside the listed limits is not "
                    "fully enumerated")
            continue
        if completeness != "COMPLETE":
            # F4: only an explicit COMPLETE enumeration may support a
            # negative claim — a missing/invalid completeness value is
            # insufficient, never silently treated as complete
            decisions.append("INSUFFICIENT_EVIDENCE")
            defects.append(
                f"{oid}: completeness {completeness!r} — only a "
                "COMPLETE enumeration supports a negative claim; a "
                "missing or unrecognized completeness is not evidence "
                "of absence")
            continue
        # COMPLETE + OK: still must relate to the claim's subject and
        # stay inside the observation's declared scope/build context.
        obs_subj = _obs_subject(obs)
        if obs_subj and not _subjects_related(claim.subject, obs_subj):
            decisions.append("SCOPE_MISMATCH")
            defects.append(
                f"{oid}: observation subject {obs_subj!r} does not "
                f"match claim subject {claim.subject!r}")
            continue
        breach = _scope_breach(claim, obs)
        if breach is not None:
            decisions.append("SCOPE_MISMATCH")
            defects.append(breach)

    if unverifiable_seen and "SCOPE_MISMATCH" not in decisions:
        # PARTIAL scope-limited evidence that isn't a scope mismatch is
        # either opaque (UNVERIFIABLE) or merely bounded; opaque
        # mechanisms are the spec §4 UNVERIFIABLE class, bounded-but-
        # honest partials are insufficient proof of a negative.
        opaque = any(
            _is_opaque(o) for o in bound_obs
            if o.get("completeness") == "PARTIAL")
        decisions.append("UNVERIFIABLE" if opaque
                         else "INSUFFICIENT_EVIDENCE")

    if not decisions and binding == "self_declared" and defects:
        # every resolved ref carried a defect and nothing bound to
        # audit/snapshot evidence — the claim is unverifiable as
        # written (e.g. hash-bound src ref with no file index)
        decisions.append("UNVERIFIABLE")

    worst: Optional[Decision] = None
    for d in _DECISION_RANK:
        if d in decisions:
            worst = d
            break

    supported = (
        worst is None
        and bool(resolved_refs)
        and binding != "none"
    )

    return ClaimVerdict(
        predicate=claim.predicate,
        subject=claim.subject,
        scope=claim.scope,
        evidence_refs=list(claim.evidence_refs),
        resolved_refs=resolved_refs,
        binding=binding,  # type: ignore[arg-type]
        supported=supported,
        decision=worst,
        defects=defects,
    )


# ---------------------------------------------------------------------------
# C4 — safe-verdict falsifier + declared-scope coverage
# ---------------------------------------------------------------------------


def _claim_covers(verdict: ClaimVerdict, subject: str) -> Optional[str]:
    """The coverage level verdict affords *subject*, or None."""
    if not verdict.supported or not _subjects_related(
            verdict.subject, subject):
        return None
    if verdict.binding == "audit":
        return "audit_complete"
    if verdict.binding == "snapshot":
        return "declared"
    return "unverifiable"


def validate_attempt(
    assessment,
    audit_records: Optional[Sequence[dict]] = None,
    observations: Optional[Sequence[dict]] = None,
    snapshot_hash: Optional[str] = None,
    advisory_record: Optional[dict] = None,
    snapshot_files: Optional[Iterable[str]] = None,
) -> ValidatorResult:
    """Validate one attempt's structured assessment — C1–C4.

    ``assessment`` may be an ``AgentAssessmentV2``, an
    ``ExtractionResultV2``, or a raw dict (stored artifact / final JSON
    object — the agent's answer is consumed as-is, never normalized
    into something else).  ``observations`` are flat Observation rows
    (``observations.jsonl``); ``audit_records`` are AuditRecord rows
    (``tool_calls.jsonl``) — either may carry the minted observation.
    ``snapshot_files`` (optional) enables the file-existence branch of
    C1 against the snapshot index.
    """
    category, payload = _coerce_assessment(assessment)
    obs = _flat_observations(observations, audit_records)
    obs_by_id = _obs_index(obs)
    owners: dict[str, list[dict]] = {}
    for o in obs:
        for r in o.get("evidence_refs") or []:
            if isinstance(r, str):
                owners.setdefault(r, []).append(o)
    file_index = (
        {f.lstrip("/") for f in snapshot_files} | set(snapshot_files)
        if snapshot_files is not None else None)

    claims = list(payload.negative_claims) if payload else []
    unresolved = [
        u for u in (payload.unresolved if payload else []) if u.strip()]
    safe = category in SAFE_CATEGORIES

    verdicts = [
        _adjudicate_claim(c, obs_by_id, owners,
                          snapshot_hash, file_index)
        for c in claims
    ]

    # ---- C4: falsifier + declared-scope coverage ----------------------
    declared = declared_affected(advisory_record)
    coverage = CoverageReport(
        declared_subjects=declared["subjects"],
        fixed_versions=declared["fixed_versions"],
        advisory_present=advisory_record is not None)

    c4_decision: Optional[Decision] = None
    falsifier: dict = {}
    reasons: list[str] = []

    if safe:
        # a checkable falsifier must bind to audit or snapshot
        # evidence — self-declared refs can support a claim-level pass
        # but cannot falsify a safe verdict
        supporting = [
            v for v in verdicts
            if v.supported and v.binding in {"audit", "snapshot"}]
        if not claims:
            c4_decision = "INSUFFICIENT_EVIDENCE"
            reasons.append(
                "safe verdict without any negative claim — no "
                "checkable falsifier")
        elif not supporting:
            # the verdict rests on the claims it has — surface their
            # worst defect class, else INSUFFICIENT_EVIDENCE
            claim_ds = [v.decision for v in verdicts if v.decision]
            if claim_ds and all(d == "UNVERIFIABLE" for d in claim_ds):
                c4_decision = "UNVERIFIABLE"
            else:
                c4_decision = "INSUFFICIENT_EVIDENCE"
            reasons.append(
                "no negative claim survives C1–C3 bound to resolvable "
                "evidence — the safe verdict has no checkable "
                "falsifier")
        else:
            best = max(
                supporting,
                key=lambda v: ("audit", "snapshot", "self_declared")
                .index(v.binding))
            falsifier = {
                "predicate": best.predicate,
                "subject": best.subject,
                "scope": best.scope,
                "binding": best.binding,
                "resolved_refs": best.resolved_refs,
                "cleared": True,
            }

        if unresolved:
            c4_decision = "INSUFFICIENT_EVIDENCE"
            reasons.append(
                f"safe verdict with {len(unresolved)} non-empty "
                "unresolved[] entries — unexplored paths are not "
                "compatible with a safe category")

        # Coverage over the advisory's declared affected subjects.
        # Worst propagation is UNCOVERED > UNVERIFIABLE > DECLARED >
        # AUDIT (a subject nobody claims is insufficient; a subject
        # covered only by unverifiable evidence is unverifiable).
        if declared["subjects"]:
            cov_rank = {"audit_complete": 0, "declared": 1,
                        "unverifiable": 2, "uncovered": 3}
            worst_cov = 0
            for subj in declared["subjects"]:
                level = None
                by = None
                for i, v in enumerate(verdicts):
                    lvl = _claim_covers(v, subj)
                    if lvl is not None:
                        level, by = lvl, f"claim[{i}]"
                        break
                if level is None:
                    # a claim NAMED the subject but failed C1–C3 —
                    # coverage was attempted with unverifiable
                    # evidence, not absent
                    for i, v in enumerate(verdicts):
                        if _subjects_related(v.subject, subj):
                            level, by = "unverifiable", f"claim[{i}]"
                            break
                status = level or "uncovered"
                worst_cov = max(worst_cov, cov_rank[status])
                coverage.entries.append(
                    CoverageEntry(subject=subj, status=status, by=by))
            if worst_cov == cov_rank["uncovered"]:
                c4_decision = "INSUFFICIENT_EVIDENCE"
                missing = [e.subject for e in coverage.entries
                           if e.status == "uncovered"]
                reasons.append(
                    "advisory-declared affected subject(s) lack any "
                    f"supported claim: {missing}")
            elif worst_cov == cov_rank["unverifiable"]:
                if c4_decision is None:
                    c4_decision = "UNVERIFIABLE"
                weak = [e.subject for e in coverage.entries
                        if e.status == "unverifiable"]
                reasons.append(
                    "declared subject(s) covered only by "
                    f"unverifiable (self-declared) evidence: {weak}")
        elif advisory_record is None:
            # no declared scope → coverage cannot be established at
            # all; absent scope is NEVER vacuous for a safe verdict
            c4_decision = "INSUFFICIENT_EVIDENCE"
            reasons.append(
                "no advisory record provided — the declared CVE scope "
                "is unknown, so claim-level checks alone cannot carry "
                "a safe verdict")
        else:
            # advisory present but declares no affected subjects —
            # equally no declared scope to bind against
            c4_decision = "INSUFFICIENT_EVIDENCE"
            reasons.append(
                "advisory declares no affected subjects — the declared "
                "CVE scope is empty, so claim-level checks alone "
                "cannot carry a safe verdict")
    else:
        falsifier = {"applicable": False,
                     "reason": f"category {category!r} is not a safe "
                               "verdict; C4 coverage not required"}

    # ---- aggregate ---------------------------------------------------
    decision: Decision = "ACCEPTED"
    for d in _DECISION_RANK:
        if d == "ACCEPTED":
            break
        if any(v.decision == d for v in verdicts) or c4_decision == d:
            decision = d
            break

    reason = "; ".join(reasons) if reasons else (
        "all cited evidence resolves cleanly"
        if decision == "ACCEPTED"
        else "; ".join(
            f"{d}: " + "; ".join(
                v.defects[0] for v in verdicts if v.decision == d)
            for d in _DECISION_RANK
            if any(v.decision == d for v in verdicts)))

    return ValidatorResult(
        decision=decision,
        category=category,
        safe_verdict=safe,
        per_claim=verdicts,
        falsifier=falsifier,
        coverage=coverage,
        reason=reason or "no claims to check",
        validator_version=VALIDATOR_VERSION,
    )


# ---------------------------------------------------------------------------
# Input coercion (the agent's answer is consumed as stored — no edit)
# ---------------------------------------------------------------------------


def _coerce_assessment(
    assessment,
) -> tuple[Optional[str], Optional[AssessmentPayloadV2]]:
    """(category, payload) from any stored form of the agent answer."""
    if isinstance(assessment, AgentAssessmentV2):
        return assessment.category, assessment.assessment
    if isinstance(assessment, ExtractionResultV2):
        return assessment.category, assessment.assessment
    if isinstance(assessment, dict):
        category = assessment.get("category")
        if not isinstance(category, str):
            category = None
        payload = assessment.get("assessment")
        if isinstance(payload, AssessmentPayloadV2):
            return category, payload
        if isinstance(payload, dict):
            try:
                return category, AssessmentPayloadV2.model_validate(
                    payload)
            except Exception:
                # stored as-is; schema-invalid payload → no claims to
                # check (schema defects are recorded at collect time)
                return category, None
        return category, None
    return None, None


__all__ = [
    "ClaimVerdict",
    "CoverageEntry",
    "CoverageReport",
    "Decision",
    "VALIDATOR_VERSION",
    "ValidatorResult",
    "declared_affected",
    "validate_attempt",
]
