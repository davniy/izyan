"""First-layer VEX parity ablation — frozen prompt protocol (Task 1).

The experiment varies ONE prompt treatment at a time over the exact
plain VEX control.  The five arms are cumulative:

    A = frozen official VEX template, only ``{cve_id}`` substituted
    B = A + the frozen advisory as reference data
    C = B + the semantic advisory-binding rules (r0-v1 rules 1-3)
    D = C + the eight-section research assessment format
    E = D + the izyan evidence-tools description

Deliberate split for C
----------------------
``eval/agent7/prompts/r0-v1.txt`` appends two things after the plain
baseline: the ``<RESEARCH_ASSESSMENT>`` block and the
``<ADVISORY_BINDING_RULES>`` block.  The binding block itself mixes the
semantic rules (items 1-3) with output-shape rules for the assessment
sections (items 4-5).  Arm C must change only the advisory-scope factor,
so it carries rules 1-3 verbatim and excludes rules 4-5.  Arm D then adds
the assessment format.  If C carried the assessment instructions too, two
factors would change in one step and the ablation would be confounded.

Frozen-source convention
------------------------
The official template hash is checked exactly as ``eval/task5/protocol.py``
does (sha256 over the stripped template bytes).  The frozen file has no
leading/trailing whitespace, so the raw file bytes and the stripped bytes
are identical; both are asserted.  The r0-v1 prompt and the k8s advisory
are pinned by their raw sha256 as recorded by the saved agent7 manifest.
The assessment block is r0-v1's ``<RESEARCH_ASSESSMENT>`` with exactly one
lead-in replacement: its stale "B1 instructions" cross-reference names the
rewritten r0 baseline, which is not this experiment's control.  The eight
section definitions and ``<RESEARCH_RULES>`` stay verbatim.

Nothing in this module calls a model, Docker, the network or the izyan
MCP server.  It only renders deterministic prompt strings and hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

PROMPT_HASH_LEN = 12

_REPO_ROOT = Path(__file__).resolve().parents[2]
_OFFICIAL_PROMPT_FILE = (
    _REPO_ROOT / "eval" / "vexbench-prompts" / "official-vuln-c0a5c8458b77.txt"
)
_R0_V1_PROMPT_FILE = _REPO_ROOT / "eval" / "agent7" / "prompts" / "r0-v1.txt"
_ADVISORY_FILE = _REPO_ROOT / "eval" / "agent7" / "advisories" / "k8s-44487.json"

# Frozen sha256 of the official template bytes (stripped), pinned by the
# filename and by the Task 4 manifest — asserted, never recomputed blindly.
FROZEN_OFFICIAL_SHA256 = (
    "c0a5c8458b77015d57b82eefca563d01c870ea027562381715c8ab9d70ffabda"
)
# Raw sha256 of eval/agent7/prompts/r0-v1.txt (same value as the saved
# agent7 run manifest's prompt_sha256).
FROZEN_R0_V1_SHA256 = (
    "55b01e9a505bd058cb7be568f08c0e58364b8048e5acea030a14534f7031a0ae"
)
# Raw sha256 of eval/agent7/advisories/k8s-44487.json (agent7 raw_sha256).
FROZEN_ADVISORY_SHA256 = (
    "077330160d3adbbb93b2294e3db541c70a746677a4128a1bd8843dab688dae39"
)

# --- experiment identity and policy -----------------------------------------

EXPERIMENT_ID = "first-layer-vex-parity"
MANIFEST_SCHEMA = "first-layer-ablation-manifest/1"

ARM_ORDER = ("A", "B", "C", "D", "E")

ARM_ROLES = {
    "A": "plain_control_exact_frozen_vex",
    "B": "plain_plus_frozen_advisory_data",
    "C": "plus_semantic_advisory_binding",
    "D": "plus_extended_assessment_format",
    "E": "plus_izyan_mcp_tools",
}

# Cumulative treatment order per arm.  Every adjacent pair below differs
# by exactly the last treatment block (asserted byte-for-byte).
ARM_TREATMENTS = {
    "A": (),
    "B": ("advisory_data",),
    "C": ("advisory_data", "semantic_advisory_binding"),
    "D": ("advisory_data", "semantic_advisory_binding", "extended_assessment"),
    "E": ("advisory_data", "semantic_advisory_binding", "extended_assessment",
          "izyan_mcp_tools"),
}

# Agent adapter binding for the shared legacy C1 runtime (architect
# decision A, 2026-10-24).  A-D use ``opencode-c1-nomcp``: the same C1
# image and legacy launch pipeline as E, with no MCP block.  E uses
# ``opencode-c1``: identical image/pipeline plus exactly ``mcp.izyan``.
# The profile name and the MCP wiring are the only declared deltas.  The
# adapter's own launch facts (image suffix, pipeline id, generated
# config, model binding, resolved credential path) are checked at
# preflight, not merely assumed from this mapping.
ARM_RUNTIME = {
    "A": {"agent": "opencode-c1-nomcp", "mcp": False},
    "B": {"agent": "opencode-c1-nomcp", "mcp": False},
    "C": {"agent": "opencode-c1-nomcp", "mcp": False},
    "D": {"agent": "opencode-c1-nomcp", "mcp": False},
    "E": {"agent": "opencode-c1", "mcp": True},
}
ARM_RUNTIME_DELTA = ("agent", "mcp")

# Both profiles must resolve to this image suffix and this launch path;
# Task 2 preflight compares the adapters' reported facts against these
# pins so "same runtime" is demonstrated rather than declared.
RUNTIME_IMAGE_SUFFIX = "opencode-c1"
RUNTIME_PIPELINE = "opencode-run-export/v1"

MODEL_ID = "Qwen/Qwen3.6-35B-A3B"
MODEL_ALIAS = "qwen3.6-35b"
PROVIDER = "custom-openai"
PROVIDER_MODEL_ID = "custom-openai/Qwen/Qwen3.6-35B-A3B"

# The plan fixes these values; they are constants rather than arguments so
# a caller cannot silently change the attempt policy.  Editing them changes
# this module's hash and therefore the frozen manifest.
ATTEMPT_POLICY = {
    "timeout_seconds": 1800,
    "repeats": 3,
    "parallel": 1,
    "retries": 0,
    "cache_admission": "forbidden",
    "attempt_key": "(experiment_id, arm, repeat)",
    "schedule_order": "repeat-major",
}

SEMANTIC_BINDING_RULES = (1, 2, 3)
EXCLUDED_BINDING_RULES = (4, 5)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


# --- frozen sources ------------------------------------------------------------


def sha256_text(text: str) -> str:
    """Full sha256 of UTF-8 text bytes."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def prompt_hash(text: str) -> str:
    """Harness-compatible short fingerprint (evaluate.common._prompt_hash)."""
    return sha256_text(text)[:PROMPT_HASH_LEN]


def canonical_json(obj: Any) -> str:
    """Stable JSON used for every hash in this module."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _load_official_template() -> str:
    """Frozen official ``vuln`` template, byte-exact and CVE-substitutable.

    The Task 5 convention hashes ``text.strip()``; this file has no
    leading/trailing whitespace, so its raw bytes and its stripped bytes
    are the same (asserted below).  Keeping the raw text means arm A is
    the frozen prompt itself, not a normalized copy.
    """
    text = _OFFICIAL_PROMPT_FILE.read_text(encoding="utf-8")
    raw_digest = sha256_text(text)
    stripped_digest = sha256_text(text.strip())
    if raw_digest != FROZEN_OFFICIAL_SHA256:
        raise AssertionError(
            f"frozen official template drifted: raw sha256 {raw_digest} != "
            f"{FROZEN_OFFICIAL_SHA256}"
        )
    if stripped_digest != FROZEN_OFFICIAL_SHA256:
        raise AssertionError(
            "official template has leading/trailing whitespace; the Task 5 "
            "stripped-hash convention and the raw bytes disagree"
        )
    if text.count("{cve_id}") != 1:
        raise AssertionError(
            "official template must contain exactly one {cve_id} placeholder"
        )
    return text


def _load_r0_v1() -> str:
    """Frozen r0-v1 source (assessment + advisory-binding blocks)."""
    text = _R0_V1_PROMPT_FILE.read_text(encoding="utf-8")
    digest = sha256_text(text)
    if digest != FROZEN_R0_V1_SHA256:
        raise AssertionError(
            f"frozen r0-v1 prompt drifted: sha256 {digest} != "
            f"{FROZEN_R0_V1_SHA256}"
        )
    return text


def _extract_tagged_block(text: str, tag: str) -> str:
    """Return the literal ``<tag>...</tag>`` section, verbatim."""
    open_tag = "<{}>".format(tag)
    close_tag = "</{}>".format(tag)
    if text.count(open_tag) != 1 or text.count(close_tag) != 1:
        raise AssertionError(
            "expected exactly one {} block in the frozen source".format(tag)
        )
    start = text.index(open_tag)
    end = text.index(close_tag, start) + len(close_tag)
    return text[start:end]


def _split_numbered_rules(block: str, tag: str) -> tuple:
    """Split a tagged block into its intro line and one-line numbered rules."""
    open_tag = "<{}>".format(tag)
    close_tag = "</{}>".format(tag)
    if not (block.startswith(open_tag) and block.endswith(close_tag)):
        raise AssertionError("malformed frozen {} block".format(tag))
    inner = block[len(open_tag):-len(close_tag)].strip("\n")
    lines = inner.splitlines()
    if not lines:
        raise AssertionError("empty frozen {} block".format(tag))
    intro = lines[0]
    if re.match(r"^\d+\.\s", intro):
        raise AssertionError("frozen {} block has no intro line".format(tag))
    rules = {}
    for line in lines[1:]:
        match = re.match(r"^(\d+)\.\s", line)
        if not match:
            raise AssertionError(
                "frozen {} block has a continuation line; the splitter "
                "expects one line per rule: {!r}".format(tag, line)
            )
        number = int(match.group(1))
        if number in rules:
            raise AssertionError(
                "duplicate rule {} in frozen {}".format(number, tag)
            )
        rules[number] = line
    return intro, rules


def _semantic_binding_block() -> str:
    """C's treatment: r0-v1 advisory-binding rules 1-3, verbatim only.

    Rules 4-5 are output-shape rules for the assessment sections, which do
    not exist in C.  Keeping them would change the assessment factor at the
    same time as the advisory-scope factor.
    """
    source = _extract_tagged_block(_load_r0_v1(), "ADVISORY_BINDING_RULES")
    intro, rules = _split_numbered_rules(source, "ADVISORY_BINDING_RULES")
    expected_numbers = SEMANTIC_BINDING_RULES + EXCLUDED_BINDING_RULES
    if tuple(sorted(rules)) != expected_numbers:
        raise AssertionError(
            "r0-v1 binding rules changed: got {}, expected {}".format(
                tuple(sorted(rules)), expected_numbers
            )
        )
    kept = [rules[number] for number in SEMANTIC_BINDING_RULES]
    block = "\n".join(
        ["<ADVISORY_BINDING_RULES>", intro] + kept
        + ["</ADVISORY_BINDING_RULES>"]
    )
    if "assessment" in block.lower():
        raise AssertionError(
            "semantic binding block leaked assessment instructions"
        )
    return block


# r0-v1's assessment format.  Exactly one lead-in sentence is adapted: the
# historical "B1 instructions" cross-reference names the rewritten r0
# baseline, which is NOT this experiment's control (A is the official VEX
# template).  The eight section definitions and the RESEARCH_RULES stay
# verbatim; only the stale cross-reference points at the current
# instructions instead of a baseline that is absent from arm D.
_ASSESSMENT_SOURCE = _extract_tagged_block(
    _load_r0_v1(), "RESEARCH_ASSESSMENT"
)
_ASSESSMENT_STALE_LEAD = (
    "This is the research treatment added to the plain baseline. "
    "All B1 instructions remain in force."
)
_ASSESSMENT_CURRENT_LEAD = (
    "This is the extended research assessment added to the current "
    "instructions. All preceding instructions remain in force."
)
if _ASSESSMENT_SOURCE.count(_ASSESSMENT_STALE_LEAD) != 1:
    raise AssertionError(
        "frozen assessment lead-in changed; expected exactly one stale "
        "'B1' cross-reference"
    )
ASSESSMENT_BLOCK = _ASSESSMENT_SOURCE.replace(
    _ASSESSMENT_STALE_LEAD, _ASSESSMENT_CURRENT_LEAD
)
ADVISORY_BINDING_RULES_BLOCK = _semantic_binding_block()

# E's tool treatment.  Content mirrors the established C1/Task 6
# ``<EVIDENCE_TOOLS>`` contract (tool families, Observation fields and
# completeness semantics).  The only alignment is the citation target:
# D's assessment has ``assessment.evidence_quality.references``, not
# ``claims[]``/``evidence[]``.  No case, product or fix identifiers.
IZYAN_TOOLS_BLOCK = """
<EVIDENCE_TOOLS>
An MCP tool server named "izyan" is connected to this session. It exposes
deterministic analysis tools over the exact source tree in your working
directory: advisory/fix research, dependency graph and module versions,
symbol/reference/caller search, source reading, argument tracing,
validation discovery, dynamic-dispatch markers, and optional build/test
execution. Use these tools alongside your normal file/search tools
whenever a fact is cheaper or more reliable to obtain that way.

Every tool call returns an Observation object:
  id, tool, fact, scope, completeness, tool_status, evidence_refs,
  limitations, scope_details, data.

Binding interpretation rules:
- tool_status "OK" with an EMPTY result is NOT a safety finding.
    completeness="COMPLETE" means "absent inside the closed scope named in
      scope/scope_details";
    completeness="PARTIAL"  means "not found in the checked part only";
    completeness="UNKNOWN"  means coverage could not be characterized.
- tool_status "ERROR" means the check failed (no coverage claim);
  "UNSUPPORTED" means the capability is not available in this session.
- Never treat a PARTIAL/UNKNOWN negative, or an absent tool result, as
  evidence that a code path is safe or unreachable.
- scope_details is authoritative: it lists the build context, packages,
  skipped packages and limits that bounded the check. Product-scope
  results say nothing about dependency-internal, dynamically dispatched
  or other-build-configuration behavior unless the scope says so.
- When you cite tool output in
  `assessment.evidence_quality.references`, use the Observation
  "evidence_refs" entries verbatim (they resolve to the recorded tool
  artifact).
</EVIDENCE_TOOLS>
""".strip()

# The harness receives one prompt string (eval.c1.runner.run_attempt's
# ``prompt`` argument).  This protocol synthesizes no system message; any
# adapter-injected system prompt must be captured from the runtime's raw
# export by Task 2.
PROTOCOL_SYSTEM_MESSAGES: tuple = ()


# --- arm construction ----------------------------------------------------------


def _validate_cve_id(cve_id: str) -> None:
    if not isinstance(cve_id, str) or not _CVE_RE.match(cve_id):
        raise ValueError(
            "cve_id must look like CVE-YYYY-NNNN; got {!r}".format(cve_id)
        )
    if "{" in cve_id or "}" in cve_id or "\n" in cve_id:
        raise ValueError("cve_id must not contain prompt syntax")


def advisory_block(advisory_text: str) -> str:
    """The frozen advisory rendered as data (no binding instructions)."""
    if not isinstance(advisory_text, str):
        raise TypeError("advisory_text must be a string")
    body = advisory_text.strip()
    if not body:
        raise ValueError("advisory_text must not be empty")
    if "</ADVISORY>" in body:
        raise ValueError("advisory_text must not contain the closing tag")
    return "\n".join([
        "<ADVISORY>",
        "The following frozen advisory record is provided as reference data:",
        "",
        body,
        "</ADVISORY>",
    ])


def treatment_blocks(advisory_text: str) -> Dict[str, str]:
    """All four treatment blocks, keyed by the manifest's treatment names."""
    return {
        "advisory_data": advisory_block(advisory_text),
        "semantic_advisory_binding": ADVISORY_BINDING_RULES_BLOCK,
        "extended_assessment": ASSESSMENT_BLOCK,
        "izyan_mcp_tools": IZYAN_TOOLS_BLOCK,
    }


def _append(base: str, block: str) -> str:
    """Append one treatment block with exactly two LF between sections."""
    return "{}\n\n{}".format(base, block.strip())


def build_arms(cve_id: str, advisory_text: str) -> Dict[str, str]:
    """Render the full prompt for every arm; returns ``{arm: prompt}``.

    A is the frozen official template with only ``{cve_id}`` substituted.
    Each later arm is the previous arm plus exactly one literal block, in
    the order declared by ``ARM_TREATMENTS``.
    """
    _validate_cve_id(cve_id)
    official = _load_official_template()
    blocks = treatment_blocks(advisory_text)

    arms = {"A": official.replace("{cve_id}", cve_id)}
    for arm in ARM_ORDER[1:]:
        previous = arms[ARM_ORDER[ARM_ORDER.index(arm) - 1]]
        arms[arm] = _append(previous, blocks[ARM_TREATMENTS[arm][-1]])

    assert_arm_contract(arms, cve_id, advisory_text)
    return arms


def request_messages(prompt: str) -> List[Dict[str, str]]:
    """Full request shape for one attempt: one user message, no system one."""
    return [{"role": "user", "content": prompt}]


def request_record(
    prompt: str, *, system_messages: Sequence[Mapping[str, Any]] = ()
) -> Dict[str, Any]:
    """Record the full request of one attempt, including runtime system text.

    This protocol contributes no system message, but the adapter may inject
    one.  Task 2 must pass whatever the adapter actually sent so the attempt
    artifact proves the complete request, not just the rendered arm prompt.
    """
    if not isinstance(prompt, str) or not prompt:
        raise ValueError("prompt must be a non-empty string")
    normalized = []
    for index, message in enumerate(system_messages):
        if not isinstance(message, Mapping):
            raise TypeError(
                "system_messages[{}] must be a mapping".format(index)
            )
        role = message.get("role")
        content = message.get("content")
        if role not in ("system", "developer"):
            raise ValueError(
                "system_messages[{}].role must be 'system' or 'developer'"
                .format(index)
            )
        if not isinstance(content, str) or not content:
            raise ValueError(
                "system_messages[{}].content must be a non-empty string"
                .format(index)
            )
        normalized.append({"role": role, "content": content})
    messages = normalized + [{"role": "user", "content": prompt}]
    return {
        "messages": messages,
        "system_message_count": len(normalized),
        "system_prompt_sha256": [
            sha256_text(message["content"]) for message in normalized
        ],
        "user_prompt_sha256": sha256_text(prompt),
        "full_request_sha256": sha256_text(canonical_json(messages)),
    }


# --- treatment-specific forbidden content --------------------------------------

_ASSESSMENT_SECTIONS = (
    "vulnerability_mechanism",
    "root_cause",
    "attack_scenario",
    "product_exposure",
    "alternative_paths",
    "evidence_quality",
    "residual_questions",
    "triage_recommendation",
)
_ASSESSMENT_TOKENS = ("assessment",) + _ASSESSMENT_SECTIONS
_BINDING_TOKENS = (
    "ADVISORY_BINDING_RULES",
    "Before any mechanism or root-cause claim",
)
_TOOL_TOKENS = (
    "EVIDENCE_TOOLS",
    "izyan",
    r"\bMCP\b",
    "tool_status",
    "completeness=",
    "Observation object",
)

# Ground-truth / prior-answer leakage.  The frozen assessment block says
# "do not authorize auto-close" (hyphenated); the artifact name is
# ``auto_close``, so the prohibition is not a leak.
_GROUND_TRUTH_PATTERNS = (
    ("USE_BASED_VERDICT", re.compile(r"\bUSE_BASED_VERDICT\b")),
    ("REVIEW_REQUIRED", re.compile(r"\bREVIEW_REQUIRED\b")),
    ("auto_close_rule", re.compile(r"\bauto_close\b")),
    ("GAP_DETECTED", re.compile(r"\bGAP_DETECTED\b")),
    ("CONFLICTED", re.compile(r"\bCONFLICTED\b")),
    ("ground_truth", re.compile(r"\bground[- ]?truth\b", re.IGNORECASE)),
    ("expected_answer", re.compile(
        r"\bexpected (?:answer|category|verdict|classification)\b",
        re.IGNORECASE,
    )),
    ("answer_key", re.compile(r"\banswer key\b", re.IGNORECASE)),
    ("correct_answer", re.compile(r"\bcorrect answer\b", re.IGNORECASE)),
    ("previous_model_output", re.compile(
        r"\bprevious (?:model )?(?:output|answer|run)\b", re.IGNORECASE
    )),
)

# Case-specific hints.  The sanctioned ``<CVE>`` and ``<ADVISORY>`` regions
# are removed before scanning; every other occurrence is a leak.
_CASE_HINT_PATTERNS = (
    ("case_cve_outside_inputs", re.compile(r"\bCVE-2023-44487\b")),
    ("case_task_id", re.compile(r"kubernetes-kubernetes-e196d24",
                                re.IGNORECASE)),
    ("case_commit", re.compile(r"\be196d24\b", re.IGNORECASE)),
    ("product_kubernetes", re.compile(r"\bk(?:ubernetes|8s)\b",
                                     re.IGNORECASE)),
    ("product_grpc", re.compile(r"\bgrpc\b", re.IGNORECASE)),
    ("google_grpc", re.compile(r"google\.golang\.org/grpc",
                               re.IGNORECASE)),
    ("http2_component", re.compile(r"\bx/net/http2\b", re.IGNORECASE)),
)

_SANCTIONED_REGION_RE = re.compile(
    r"<(CVE|ADVISORY)>.*?</\1>", re.IGNORECASE | re.DOTALL
)


def _strip_sanctioned_regions(text: str) -> str:
    """Blank the CVE id and advisory body before the leak scan."""
    return _SANCTIONED_REGION_RE.sub(lambda m: "<{}/>".format(m.group(1)),
                                     text)


def _treatment_hits(text: str, arm: str) -> List[str]:
    allowed = set(ARM_TREATMENTS[arm])
    hits = []
    if "extended_assessment" not in allowed:
        lowered = text.lower()
        for token in _ASSESSMENT_TOKENS:
            if token.lower() in lowered:
                hits.append("assessment:{}".format(token))
    if "semantic_advisory_binding" not in allowed:
        for token in _BINDING_TOKENS:
            if re.search(re.escape(token), text, re.IGNORECASE):
                hits.append("binding:{}".format(token))
    if "izyan_mcp_tools" not in allowed:
        for token in _TOOL_TOKENS:
            if re.search(token, text, re.IGNORECASE):
                hits.append("tools:{}".format(token))
    return hits


def find_prohibited(text: str, arm: Optional[str] = None) -> List[str]:
    """Human-readable leaks in a rendered arm (empty list means clean)."""
    if arm is not None and arm not in ARM_TREATMENTS:
        raise ValueError("unknown arm {!r}".format(arm))
    scrubbed = _strip_sanctioned_regions(text)
    hits = []
    for name, pattern in _GROUND_TRUTH_PATTERNS:
        if pattern.search(scrubbed):
            hits.append("ground_truth:{}".format(name))
    for name, pattern in _CASE_HINT_PATTERNS:
        if pattern.search(scrubbed):
            hits.append("case_hint:{}".format(name))
    if arm is not None:
        hits.extend(_treatment_hits(scrubbed, arm))
    return sorted(set(hits))


def assert_control_prompt(text: str, cve_id: str) -> None:
    """Arm A is the frozen control: exact bytes plus zero added treatments."""
    _validate_cve_id(cve_id)
    expected = _load_official_template().replace("{cve_id}", cve_id)
    if text != expected:
        raise AssertionError(
            "arm A is not the exact frozen VEX prompt with only {cve_id} "
            "substituted"
        )
    hits = find_prohibited(text, arm="A")
    if hits:
        raise AssertionError(
            "arm A carries prohibited content: {}".format(", ".join(hits))
        )


def assert_arm_contract(
    arms: Mapping[str, str], cve_id: str, advisory_text: str
) -> None:
    """Raise unless every adjacent pair differs by exactly one treatment."""
    if tuple(arms) != ARM_ORDER:
        raise AssertionError(
            "arm keys/order drifted: got {}, expected {}".format(
                tuple(arms), ARM_ORDER
            )
        )
    assert_control_prompt(arms["A"], cve_id)
    blocks = treatment_blocks(advisory_text)

    for previous, current in zip(ARM_ORDER, ARM_ORDER[1:]):
        treatment = ARM_TREATMENTS[current][-1]
        expected_suffix = "\n\n" + blocks[treatment].strip()
        if not arms[current].startswith(arms[previous]):
            raise AssertionError(
                "arm {} does not preserve arm {} as an exact prefix".format(
                    current, previous
                )
            )
        actual_suffix = arms[current][len(arms[previous]):]
        if actual_suffix != expected_suffix:
            raise AssertionError(
                "arm {} - arm {} is not exactly the declared treatment "
                "{!r}".format(current, previous, treatment)
            )

    for arm in ARM_ORDER:
        for treatment in ARM_TREATMENTS[arm]:
            count = arms[arm].count(blocks[treatment].strip())
            if count != 1:
                raise AssertionError(
                    "treatment {!r} appears {} times in arm {} (expected 1)"
                    .format(treatment, count, arm)
                )
        if "extended_assessment" in ARM_TREATMENTS[arm]:
            missing = [
                section for section in _ASSESSMENT_SECTIONS
                if "- `{}`:".format(section) not in arms[arm]
            ]
            if missing:
                raise AssertionError(
                    "arm {} is missing assessment sections: {}".format(
                        arm, missing
                    )
                )
        hits = find_prohibited(arms[arm], arm=arm)
        if hits:
            raise AssertionError(
                "arm {} carries prohibited content: {}".format(
                    arm, ", ".join(hits)
                )
            )


# --- manifest ------------------------------------------------------------------


def build_schedule() -> List[Dict[str, Any]]:
    """Preassigned sequential order: all five arms inside each repeat."""
    schedule = []
    index = 0
    for repeat in range(1, ATTEMPT_POLICY["repeats"] + 1):
        for arm in ARM_ORDER:
            index += 1
            schedule.append({
                "index": index,
                "arm": arm,
                "repeat": repeat,
                "attempt_key": "{}/{}/r{}".format(EXPERIMENT_ID, arm, repeat),
            })
    return schedule


def assert_arm_runtime_contract() -> tuple:
    """A-D effective configs are identical; E differs only by MCP wiring."""
    base = ARM_RUNTIME["A"]
    for arm in ("B", "C", "D"):
        if ARM_RUNTIME[arm] != base:
            raise AssertionError(
                "arm {} runtime differs from A outside the MCP treatment"
                .format(arm)
            )
    e = ARM_RUNTIME["E"]
    delta = tuple(sorted(set(base) | set(e)))
    changed = tuple(sorted(
        key for key in delta if base.get(key) != e.get(key)
    ))
    if changed != ARM_RUNTIME_DELTA:
        raise AssertionError(
            "E's runtime delta is {}, expected {}".format(
                changed, ARM_RUNTIME_DELTA
            )
        )
    if e["mcp"] is not True or base["mcp"] is not False:
        raise AssertionError("MCP flags drifted")
    return changed


def _relpath(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return str(resolved.relative_to(_REPO_ROOT))
    except ValueError:
        return str(resolved)


def _resolve_recorded_path(recorded: str) -> Path:
    path = Path(recorded)
    return path if path.is_absolute() else _REPO_ROOT / path


_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|"
    r"authorization|bearer)",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"(sk-[A-Za-z0-9]{8,}|ghp_[A-Za-z0-9]{8,}|Bearer\s+\S+)"
)


def _assert_no_secrets(obj: Any, *, where: str, path: str = "$") -> None:
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            if _SECRET_KEY_RE.search(str(key)):
                raise ValueError(
                    "{} must not contain credentials: {}.{}".format(
                        where, path, key
                    )
                )
            _assert_no_secrets(value, where=where,
                               path="{}.{}".format(path, key))
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            _assert_no_secrets(value, where=where,
                               path="{}[{}]".format(path, index))
    elif isinstance(obj, str):
        if _SECRET_VALUE_RE.search(obj):
            raise ValueError(
                "{} must not contain a credential-like value at {}".format(
                    where, path
                )
            )


def _validate_case(case: Mapping[str, Any]) -> None:
    required = (
        "task_id", "cve_id", "repo_url", "commit_sha", "language",
        "snapshot_path",
    )
    if not isinstance(case, Mapping):
        raise TypeError("case must be a mapping")
    missing = [key for key in required if key not in case]
    if missing:
        raise ValueError("case is missing fields: {}".format(missing))
    extra = set(case) - set(required) - {"snapshot_sha256"}
    if extra:
        raise ValueError("case has unknown fields: {}".format(sorted(extra)))
    for key in required:
        value = case[key]
        if not isinstance(value, str) or not value.strip():
            raise ValueError("case.{} must be a non-empty string".format(key))
    if not _CVE_RE.match(case["cve_id"]):
        raise ValueError("case.cve_id is not a CVE id")
    if not _COMMIT_RE.match(case["commit_sha"]):
        raise ValueError("case.commit_sha must be 7-40 lowercase hex chars")
    snapshot_sha = case.get("snapshot_sha256")
    if snapshot_sha is not None:
        if not isinstance(snapshot_sha, str) or not _SHA256_RE.match(
            snapshot_sha
        ):
            raise ValueError("case.snapshot_sha256 must be 64 lowercase hex")
    _assert_no_secrets(case, where="case")


def _validate_runtime(runtime: Mapping[str, Any]) -> None:
    if not isinstance(runtime, Mapping):
        raise TypeError("runtime must be a mapping")
    allowed = {
        "model", "endpoint", "image", "parameters", "native_tools",
        "permissions",
    }
    extra = set(runtime) - allowed
    if extra:
        raise ValueError("runtime has unknown fields: {}".format(sorted(extra)))
    missing = allowed - set(runtime)
    if missing:
        raise ValueError("runtime is missing fields: {}".format(sorted(missing)))
    _assert_no_secrets(runtime, where="runtime")

    model = runtime["model"]
    if not isinstance(model, Mapping):
        raise TypeError("runtime.model must be a mapping")
    model_extra = set(model) - {
        "id", "alias", "provider", "provider_model_id", "revision",
    }
    if model_extra:
        raise ValueError(
            "runtime.model has unknown fields: {}".format(sorted(model_extra))
        )
    blob = " ".join(
        str(model.get(key) or "")
        for key in ("id", "alias", "provider_model_id")
    )
    if MODEL_ID not in blob and MODEL_ALIAS not in blob:
        raise ValueError(
            "runtime.model must identify {} (or alias {}); got {!r}".format(
                MODEL_ID, MODEL_ALIAS, model.get("id")
            )
        )
    provider = str(model.get("provider") or "")
    if not provider.lower().startswith(PROVIDER):
        raise ValueError(
            "runtime.model.provider must be {}; got {!r}".format(
                PROVIDER, provider
            )
        )

    endpoint = runtime["endpoint"]
    if not isinstance(endpoint, Mapping):
        raise TypeError("runtime.endpoint must be a mapping")
    endpoint_extra = set(endpoint) - {
        "base_url", "provider_endpoint", "transport",
    }
    if endpoint_extra:
        raise ValueError(
            "runtime.endpoint has unknown fields: {}".format(
                sorted(endpoint_extra)
            )
        )

    image = runtime["image"]
    if not isinstance(image, Mapping):
        raise TypeError("runtime.image must be a mapping")
    image_extra = set(image) - {"tag", "digest", "same_digest_all_arms"}
    if image_extra:
        raise ValueError(
            "runtime.image has unknown fields: {}".format(sorted(image_extra))
        )
    if not isinstance(image.get("tag"), str) or not image["tag"].strip():
        raise ValueError("runtime.image.tag must be a non-empty string")
    if image.get("same_digest_all_arms") is not True:
        raise ValueError(
            "runtime.image.same_digest_all_arms must be True: one digest is "
            "shared by every arm"
        )
    digest = image.get("digest")
    if digest is not None:
        if not isinstance(digest, str) or not _IMAGE_DIGEST_RE.match(digest):
            raise ValueError(
                "runtime.image.digest must be 'sha256:<64 hex>' or None"
            )

    parameters = runtime["parameters"]
    if not isinstance(parameters, Mapping):
        raise TypeError("runtime.parameters must be a mapping")
    tools = runtime["native_tools"]
    if not isinstance(tools, list) or not tools:
        raise ValueError("runtime.native_tools must be a non-empty list")
    if any(not isinstance(tool, str) or not tool for tool in tools):
        raise ValueError("runtime.native_tools entries must be strings")
    permissions = runtime["permissions"]
    if not isinstance(permissions, Mapping):
        raise TypeError("runtime.permissions must be a mapping")
    if "mcp" in permissions:
        raise ValueError(
            "MCP availability is the per-arm E treatment, not a shared "
            "runtime permission"
        )


def _assert_advisory_covers_cve(parsed: Any, cve_id: str) -> None:
    if not isinstance(parsed, Mapping):
        raise ValueError("frozen advisory must be a JSON object")
    identifiers = []
    for key in ("id", "aliases", "related"):
        value = parsed.get(key)
        if isinstance(value, str):
            identifiers.append(value)
        elif isinstance(value, list):
            identifiers.extend(
                item for item in value if isinstance(item, str)
            )
    if cve_id not in identifiers:
        raise ValueError(
            "advisory does not name {} in id/aliases/related".format(cve_id)
        )


def _validate_frozen_at(value: str) -> None:
    if not _UTC_RE.match(value):
        raise ValueError(
            "frozen_at_utc must look like YYYY-MM-DDTHH:MM:SSZ"
        )


def manifest_sha256(manifest: Mapping[str, Any]) -> str:
    """Self-hash over the canonical manifest without its own hash field."""
    body = {
        key: value for key, value in manifest.items()
        if key != "manifest_sha256"
    }
    return sha256_text(canonical_json(body))


def seal_manifest(manifest: Mapping[str, Any]) -> Dict[str, Any]:
    sealed = dict(manifest)
    sealed["manifest_sha256"] = manifest_sha256(sealed)
    return sealed


def build_manifest(
    *,
    case: Mapping[str, Any],
    advisory_path: Path,
    runtime: Mapping[str, Any],
    frozen_at_utc: Optional[str] = None,
    experiment_id: str = EXPERIMENT_ID,
) -> Dict[str, Any]:
    """Build and seal the frozen Task 1 manifest.

    Unknown runtime facts (image digest, endpoint, snapshot content hash)
    stay ``None`` with an explicit limitation; they are never fabricated.
    Task 2 preflight must resolve them and refuse to run on a mismatch.
    """
    case = dict(case)
    _validate_case(case)
    runtime = dict(runtime)
    _validate_runtime(runtime)
    if not isinstance(experiment_id, str) or not experiment_id.strip():
        raise ValueError("experiment_id must be a non-empty string")
    timestamp = frozen_at_utc or time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
    )
    _validate_frozen_at(timestamp)

    advisory_path = Path(advisory_path)
    if not advisory_path.is_file():
        raise ValueError(
            "frozen advisory not found: {}".format(advisory_path)
        )
    advisory_text = advisory_path.read_text(encoding="utf-8")
    try:
        parsed_advisory = json.loads(advisory_text)
    except ValueError as exc:
        raise ValueError(
            "frozen advisory must be valid JSON: {}".format(exc)
        )
    _assert_advisory_covers_cve(parsed_advisory, case["cve_id"])

    arms = build_arms(case["cve_id"], advisory_text)
    blocks = treatment_blocks(advisory_text)

    official_text = _OFFICIAL_PROMPT_FILE.read_text(encoding="utf-8")
    r0_text = _R0_V1_PROMPT_FILE.read_text(encoding="utf-8")
    if sha256_text(official_text) != FROZEN_OFFICIAL_SHA256:
        raise AssertionError("official template changed during manifest build")
    if sha256_text(r0_text) != FROZEN_R0_V1_SHA256:
        raise AssertionError("r0-v1 changed during manifest build")

    sources = {
        "official_vex_template": {
            "path": _relpath(_OFFICIAL_PROMPT_FILE),
            "sha256": sha256_text(official_text),
            "sha256_stripped": sha256_text(official_text.strip()),
            "frozen_sha256": FROZEN_OFFICIAL_SHA256,
            "bytes": len(official_text.encode("utf-8")),
        },
        "r0_v1_prompt": {
            "path": _relpath(_R0_V1_PROMPT_FILE),
            "sha256": sha256_text(r0_text),
            "frozen_sha256": FROZEN_R0_V1_SHA256,
            "bytes": len(r0_text.encode("utf-8")),
        },
        "advisory": {
            "path": _relpath(advisory_path),
            "sha256": sha256_text(advisory_text),
            "canonical_json_sha256": sha256_text(
                canonical_json(parsed_advisory)
            ),
            "frozen_sha256": (
                FROZEN_ADVISORY_SHA256
                if advisory_path.resolve() == _ADVISORY_FILE.resolve()
                else None
            ),
            "is_frozen_experiment_source": (
                advisory_path.resolve() == _ADVISORY_FILE.resolve()
            ),
            "bytes": len(advisory_text.encode("utf-8")),
        },
    }
    if sources["advisory"]["is_frozen_experiment_source"]:
        if sources["advisory"]["sha256"] != FROZEN_ADVISORY_SHA256:
            raise AssertionError("frozen advisory hash drifted")

    block_sources = {
        "advisory_data": (
            "<ADVISORY> envelope + frozen advisory JSON verbatim; "
            "reference data only, no binding rules"
        ),
        "semantic_advisory_binding": (
            "eval/agent7/prompts/r0-v1.txt <ADVISORY_BINDING_RULES> "
            "rules 1-3 verbatim; rules 4-5 excluded because they prescribe "
            "assessment sections that arm C does not have"
        ),
        "extended_assessment": (
            "eval/agent7/prompts/r0-v1.txt <RESEARCH_ASSESSMENT> with one "
            "lead-in replacement (stale 'B1' cross-reference -> current "
            "instructions); the eight section definitions and "
            "RESEARCH_RULES are verbatim"
        ),
        "izyan_mcp_tools": (
            "established C1/Task 6 <EVIDENCE_TOOLS> contract, citation "
            "target aligned to assessment.evidence_quality.references"
        ),
    }
    treatment_records = {}
    for name, block in blocks.items():
        treatment_records[name] = {
            "sha256": sha256_text(block),
            "bytes": len(block.encode("utf-8")),
            "source": block_sources[name],
        }

    prompts = {}
    prohibited = {}
    for arm in ARM_ORDER:
        prompt = arms[arm]
        prompts[arm] = {
            "role": ARM_ROLES[arm],
            "treatments": list(ARM_TREATMENTS[arm]),
            "agent": ARM_RUNTIME[arm]["agent"],
            "mcp": ARM_RUNTIME[arm]["mcp"],
            "sha256": sha256_text(prompt),
            "sha256_12": prompt_hash(prompt),
            "bytes": len(prompt.encode("utf-8")),
            "lines": prompt.count("\n") + 1,
        }
        prohibited[arm] = find_prohibited(prompt, arm=arm)
        if prohibited[arm]:
            raise AssertionError(
                "arm {} carries prohibited content: {}".format(
                    arm, ", ".join(prohibited[arm])
                )
            )

    assert_arm_runtime_contract()
    schedule = build_schedule()
    limitations = [
        "Single-case diagnostic (Kubernetes e196d24 / CVE-2023-44487); it "
        "localizes a prompt-treatment effect and does not establish general "
        "parity.",
        "Arm A is the frozen official VEX prompt with only {cve_id} "
        "substituted; no ground truth, expected category, gRPC hint or "
        "prior model output is supplied.",
        "C carries only the semantic advisory-binding rules (r0-v1 rules "
        "1-3); the eight-section assessment format is added only in D.",
        "No system message is synthesized by this protocol; Task 2 must "
        "capture any adapter-injected system message verbatim in the "
        "attempt artifacts.",
        "A-E share the legacy C1 benchmark runtime (opencode-c1-nomcp for "
        "A-D, opencode-c1 for E; same image and launch pipeline). That "
        "runtime keeps the legacy writable workspace, network access and "
        "--dangerously-skip-permissions. It is NOT the E6 sandbox and must "
        "not be described as E6-safe; E6 is not weakened.",
    ]
    if runtime["image"].get("digest") is None:
        limitations.append(
            "runtime.image.digest is None: Task 2 preflight must probe one "
            "digest and use it for every arm; a null is never treated as a "
            "value."
        )
    if runtime["endpoint"].get("base_url") is None:
        limitations.append(
            "runtime.endpoint.base_url is None (unexposed); it must stay "
            "identical across arms and is never fabricated."
        )
    if runtime["model"].get("revision") is None:
        limitations.append(
            "runtime.model.revision is None (unexposed by the provider); "
            "Task 2 records the observed revision if the provider exposes it."
        )
    if not case.get("snapshot_sha256"):
        limitations.append(
            "case.snapshot_sha256 is None: Task 2 preflight must verify the "
            "snapshot content hash and refuse a different snapshot."
        )

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "experiment_id": experiment_id,
        "frozen_at_utc": timestamp,
        "goal": (
            "Localize the first prompt/input change that loses correct "
            "first-layer VEX research on one saved case."
        ),
        "case": case,
        "sources": sources,
        "treatment_blocks": treatment_records,
        "prompts": prompts,
        "request_capture": {
            "protocol_system_messages": list(PROTOCOL_SYSTEM_MESSAGES),
            "user_messages_per_attempt": 1,
            "message_roles": ["user"],
            "full_prompt_sha256": {
                arm: prompts[arm]["sha256"] for arm in ARM_ORDER
            },
            "recorder": (
                "protocol.request_record(prompt, "
                "system_messages=<adapter-injected messages>)"
            ),
            "note": (
                "The harness receives one prompt string per attempt; no "
                "system message is synthesized here. Any adapter-injected "
                "system prompt must be captured from the runtime raw export. "
                "An export with no system message is recorded as "
                "absent_from_export_not_proof, never as proof that the "
                "runtime sent none; the invoked tool surface is captured "
                "from the same export."
            ),
        },
        "runtime": runtime,
        "runtime_sha256": sha256_text(canonical_json(runtime)),
        "attempt_policy": dict(ATTEMPT_POLICY),
        "schedule": schedule,
        "schedule_sha256": sha256_text(canonical_json(schedule)),
        "equality_contract": {
            "shared_across_all_arms": [
                "case.task_id",
                "case.cve_id",
                "case.repo_url",
                "case.commit_sha",
                "case.language",
                "case.snapshot_path",
                "runtime.model",
                "runtime.endpoint",
                "runtime.image.tag",
                "runtime.image.digest",
                "runtime.parameters",
                "runtime.native_tools",
                "runtime.permissions",
                "attempt_policy.timeout_seconds",
                "attempt_policy.parallel",
                "attempt_policy.retries",
                "attempt_policy.cache_admission",
            ],
            "arm_delta": {"E": list(ARM_RUNTIME_DELTA)},
            "same_image_digest_all_arms": True,
            "runtime_image_suffix": RUNTIME_IMAGE_SUFFIX,
            "runtime_pipeline": RUNTIME_PIPELINE,
            "required_arm_equality": (
                "A, B, C and D effective configs are identical; E differs "
                "only by the MCP treatment (agent=opencode-c1, mcp=true) on "
                "the same C1 image and legacy launch pipeline "
                "(opencode-c1-nomcp for A-D)."
            ),
        },
        "validation": {
            "control_exact": True,
            "adjacent_deltas_exact": True,
            "c_has_only_semantic_binding_rules": True,
            "prohibited_hits": prohibited,
        },
        "limitations": limitations,
    }
    sealed = seal_manifest(manifest)
    verify_manifest(sealed)
    return sealed


def verify_manifest(manifest: Mapping[str, Any]) -> bool:
    """Re-derive hashes and prompts from the pinned sources; raise on drift."""
    if not isinstance(manifest, Mapping):
        raise TypeError("manifest must be a mapping")
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise AssertionError(
            "unexpected manifest schema: {!r}".format(manifest.get("schema"))
        )
    expected_hash = manifest.get("manifest_sha256")
    at_rest_hash = manifest_sha256(manifest)
    if not expected_hash or expected_hash != at_rest_hash:
        raise AssertionError(
            "manifest self-hash mismatch: {} != {}".format(
                expected_hash, at_rest_hash
            )
        )

    case = manifest.get("case")
    if not isinstance(case, Mapping):
        raise AssertionError("manifest has no case mapping")
    _validate_case(case)
    runtime = manifest.get("runtime")
    if not isinstance(runtime, Mapping):
        raise AssertionError("manifest has no runtime mapping")
    _validate_runtime(runtime)
    if manifest.get("runtime_sha256") != sha256_text(canonical_json(runtime)):
        raise AssertionError("runtime hash mismatch")
    if manifest.get("attempt_policy") != ATTEMPT_POLICY:
        raise AssertionError("attempt policy drifted from the frozen values")
    assert_arm_runtime_contract()

    schedule = build_schedule()
    if manifest.get("schedule") != schedule:
        raise AssertionError("schedule is not the frozen repeat-major order")
    if manifest.get("schedule_sha256") != sha256_text(
        canonical_json(schedule)
    ):
        raise AssertionError("schedule hash mismatch")

    sources = manifest.get("sources")
    if not isinstance(sources, Mapping):
        raise AssertionError("manifest has no sources mapping")
    for name, source_path, frozen_hash in (
        ("official_vex_template", _OFFICIAL_PROMPT_FILE,
         FROZEN_OFFICIAL_SHA256),
        ("r0_v1_prompt", _R0_V1_PROMPT_FILE, FROZEN_R0_V1_SHA256),
    ):
        record = sources.get(name)
        if not isinstance(record, Mapping):
            raise AssertionError("manifest source {!r} is missing".format(name))
        actual = sha256_text(source_path.read_text(encoding="utf-8"))
        if record.get("sha256") != actual:
            raise AssertionError(
                "pinned source {!r} hash drifted".format(name)
            )
        if record.get("frozen_sha256") != frozen_hash:
            raise AssertionError(
                "pinned source {!r} does not carry its frozen hash"
                .format(name)
            )
    official_record = sources["official_vex_template"]
    if official_record.get("sha256_stripped") != FROZEN_OFFICIAL_SHA256:
        raise AssertionError(
            "official source does not satisfy the Task 5 stripped-hash "
            "convention"
        )

    advisory_record = sources.get("advisory", {})
    advisory_path = _resolve_recorded_path(advisory_record.get("path", ""))
    if not advisory_path.is_file():
        raise AssertionError(
            "pinned advisory is missing: {}".format(advisory_path)
        )
    advisory_text = advisory_path.read_text(encoding="utf-8")
    if sha256_text(advisory_text) != advisory_record.get("sha256"):
        raise AssertionError("pinned advisory hash drifted")
    try:
        parsed_advisory = json.loads(advisory_text)
    except ValueError as exc:
        raise AssertionError("pinned advisory is not JSON: {}".format(exc))
    _assert_advisory_covers_cve(parsed_advisory, case["cve_id"])

    arms = build_arms(case["cve_id"], advisory_text)
    prompts = manifest.get("prompts", {})
    if tuple(prompts) != ARM_ORDER:
        raise AssertionError("manifest prompt arms are not A-E")
    for arm in ARM_ORDER:
        record = prompts[arm]
        if record.get("sha256") != sha256_text(arms[arm]):
            raise AssertionError(
                "arm {} prompt hash does not match the pinned sources"
                .format(arm)
            )
        if record.get("sha256_12") != prompt_hash(arms[arm]):
            raise AssertionError(
                "arm {} short prompt hash does not match".format(arm)
            )
        if record.get("treatments") != list(ARM_TREATMENTS[arm]):
            raise AssertionError(
                "arm {} treatment list drifted".format(arm)
            )
        if record.get("agent") != ARM_RUNTIME[arm]["agent"]:
            raise AssertionError("arm {} agent drifted".format(arm))
        if record.get("mcp") is not ARM_RUNTIME[arm]["mcp"]:
            raise AssertionError("arm {} MCP flag drifted".format(arm))
        if find_prohibited(arms[arm], arm=arm):
            raise AssertionError(
                "arm {} is not clean after re-derivation".format(arm)
            )
    return True


def write_manifest(path: Path, manifest: Mapping[str, Any]) -> Path:
    """Freeze once; an existing different manifest is never overwritten."""
    path = Path(path)
    candidate = dict(manifest)
    if "manifest_sha256" in candidate:
        verify_manifest(candidate)
    sealed = seal_manifest(candidate)
    verify_manifest(sealed)
    body = json.dumps(
        sealed, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing == sealed:
            return path
        raise FileExistsError(
            "refusing to overwrite a different frozen manifest: {}".format(
                path
            )
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(body, encoding="utf-8")
    os.replace(temporary, path)
    return path


# --- CLI -----------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Render the first-layer ablation arms and freeze their manifest. "
            "No model, Docker or network call is made."
        )
    )
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--case", required=True,
        help="JSON object with task_id/cve_id/repo_url/commit_sha/language/"
             "snapshot_path and optional snapshot_sha256",
    )
    parser.add_argument(
        "--advisory", required=True,
        help="frozen advisory JSON file",
    )
    parser.add_argument(
        "--runtime", required=True,
        help="JSON object with model/endpoint/image/parameters/native_tools/"
             "permissions; must not contain credentials",
    )
    parser.add_argument(
        "--frozen-at", default=None,
        help="UTC timestamp YYYY-MM-DDTHH:MM:SSZ (default: now)",
    )
    parser.add_argument(
        "--experiment-id", default=EXPERIMENT_ID,
    )
    args = parser.parse_args(argv)

    case = json.loads(Path(args.case).read_text(encoding="utf-8"))
    runtime = json.loads(Path(args.runtime).read_text(encoding="utf-8"))
    advisory_path = Path(args.advisory)
    advisory_text = advisory_path.read_text(encoding="utf-8")
    arms = build_arms(case["cve_id"], advisory_text)
    manifest = build_manifest(
        case=case,
        advisory_path=advisory_path,
        runtime=runtime,
        frozen_at_utc=args.frozen_at,
        experiment_id=args.experiment_id,
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_manifest(output_dir / "manifest.json", manifest)
    for arm in ARM_ORDER:
        (output_dir / "arm-{}.txt".format(arm)).write_text(
            arms[arm], encoding="utf-8"
        )
    print(json.dumps({
        "output_dir": str(output_dir),
        "manifest_sha256": manifest["manifest_sha256"],
        "prompt_sha256_12": {
            arm: manifest["prompts"][arm]["sha256_12"]
            for arm in ARM_ORDER
        },
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
