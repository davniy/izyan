"""C1 experiment protocol: shared assessment/reporting prompt blocks.

Normative sources:
- spec:  docs/dev/specs/2026-10-08-task4-agent-evidence-tools-v2.md (sections 4, 7, 8)
- plan:  docs/dev/plans/2026-10-08-task4-c1-implementation-plan.md (sections 1.4, 1.5, 3)

This module is the single source of truth for the two prompt additions:

1. ASSESSMENT_REPORT_BLOCK — appended identically to the B1' control
   prompt and the C1 prompt. It extends the official output contract with
   a structured ``assessment`` object and requires a counterexample pass
   before any safe (non-vulnerable) estimate. It adds NO extra security
   guidance beyond what frozen B1 already had — it only adds reporting
   requirements (plan section 1.5).

2. EVIDENCE_TOOLS_BLOCK — appended only to the C1 prompt. It declares the
   ``izyan`` MCP tool server, the Observation response contract and the
   binding interpretation rules for scope/completeness. It mirrors the MCP
   server instructions emitted by ``izyan-evidence-tools`` at initialize
   time (internal/evidencetools/mcp.go); the wording is declarative tool
   documentation, not case-specific hints.

``build_prompt`` composes OFFICIAL_TEMPLATE + optional blocks. The
official template text is kept verbatim (sha256 c0a5c8458b77...) so the
frozen B1 prompt remains an exact prefix of both derived prompts; the
only deltas are the appended reporting block (B1') and reporting+tools
blocks (C1).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

PROMPT_HASH_LEN = 12

# --- frozen official template -------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_OFFICIAL_PROMPT_FILE = (
    _REPO_ROOT / "eval" / "vexbench-prompts" / "official-vuln-c0a5c8458b77.txt"
)


def _load_official_template() -> str:
    """Load the frozen B1 template verbatim from the repo (hash-pinned file)."""
    return _OFFICIAL_PROMPT_FILE.read_text(encoding="utf-8").strip()


# --- block 1: shared structured reporting (B1' and C1) ------------------------
#
# Constraints honored:
# - single JSON object on stdout keeps ``category``/``reasoning`` top-level
#   (official result_parser ignores extra fields);
# - no stronger security instruction than B1 — only reporting discipline;
# - counterexample pass is required CONTENT (what was checked / what stayed
#   unknown), not a boolean flag;
# - the agent must NOT self-declare controller metadata (versions, costs,
#   task ids) — those are stamped by the controller (plan section 1.4).

ASSESSMENT_REPORT_BLOCK = """
<ASSESSMENT_REPORT>
In addition to "category" and "reasoning", the same single JSON object MUST
contain an "assessment" field with your structured analysis:

{
  "category": "<one of the 12 category names, exact snake_case>",
  "reasoning": "<evidence-based explanation>",
  "assessment": {
    "root_causes": ["<root cause hypothesis you evaluated>"],
    "mandatory_conditions": ["<condition that MUST hold for exploitation>"],
    "claims": [
      {
        "statement": "<factual claim about presence / reachability / mitigation>",
        "verdict": "TRUE | FALSE | UNKNOWN",
        "evidence_refs": ["<evidence reference backing this claim>"]
      }
    ],
    "evidence": ["<all evidence references you rely on>"],
    "limitations": ["<what your investigation could not cover>"],
    "unresolved_questions": ["<question that stayed open>"],
    "counterexample_review": {
      "checked": ["<concrete alternative interpretation / attack path / caller you actively tried to disprove your verdict with>"],
      "still_unknown": ["<counterexample you could not rule out>"]
    },
    "verdict_estimate": "NOT_AFFECTED | NO_EXPLOIT_PATH_FOUND | EXPLOITABLE | INCONCLUSIVE"
  }
}

Rules:
- "category"/"reasoning" at top level stay EXACTLY as specified in
  <OUTPUT_FORMAT>: official category name, evidence-grounded reasoning.
- verdict_estimate must agree with category:
    "vulnerable"                  -> "EXPLOITABLE"
    "uncertain"                   -> "INCONCLUSIVE"
    any other (safe) category     -> "NOT_AFFECTED" or "NO_EXPLOIT_PATH_FOUND"
- Before choosing a safe category or estimate, perform the counterexample
  pass: actively look for at least one concrete way your conclusion could
  be wrong (alternative caller, indirect/dependency-internal path,
  configuration that enables the surface, build-tag variant). Record what
  you checked in counterexample_review.checked and what stayed open in
  counterexample_review.still_unknown. Do not write "done" or leave these
  lists empty without a concrete reason.
- Evidence references cite things a reviewer can resolve: file paths with
  line numbers ("file:pkg/http/server.go:142"), tool evidence ids returned
  by tools ("ev:..."), or advisory URLs ("url:https://...").
- Do NOT include task ids, snapshot hashes, model/tool versions, token
  counts or timing inside "assessment" — those are recorded by the harness.
- If you genuinely cannot reach a conclusion, keep "category": "uncertain"
  with "verdict_estimate": "INCONCLUSIVE" and explain why in
  unresolved_questions. Do not emit a safe category as a hedge.
</ASSESSMENT_REPORT>
""".strip()


# --- block 2: C1 evidence-tools contract (C1 only) -----------------------------
#
# Mirrors the binding interpretation rules of the MCP server instructions.
# It declares capabilities and semantics only; it must stay free of any
# CVE-, file- or benchmark-case-specific guidance (spec section 4).

EVIDENCE_TOOLS_BLOCK = """
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
- When you cite tool output in claims[].evidence_refs or evidence[], use
  the Observation "evidence_refs" entries verbatim (they resolve to the
  recorded tool artifact).
</EVIDENCE_TOOLS>
""".strip()


# --- prompt variants -----------------------------------------------------------

PROMPT_B1_PRIME = "vuln_assess"  # B1' control: official + assessment block
PROMPT_C1 = "vuln_c1"            # C1: official + assessment block + tools block


def build_prompt(variant: str) -> str:
    """Render a derived prompt template.

    ``variant`` is PROMPT_B1_PRIME (shared reporting block only) or
    PROMPT_C1 (reporting block + evidence-tools declaration). The frozen
    official template is always the verbatim prefix.
    """
    base = _load_official_template()
    if variant == PROMPT_B1_PRIME:
        return f"{base}\n\n{ASSESSMENT_REPORT_BLOCK}\n"
    if variant == PROMPT_C1:
        return f"{base}\n\n{ASSESSMENT_REPORT_BLOCK}\n\n{EVIDENCE_TOOLS_BLOCK}\n"
    raise ValueError(
        f"unknown prompt variant {variant!r}; expected "
        f"{PROMPT_B1_PRIME!r} or {PROMPT_C1!r}"
    )


def prompt_hash(text: str) -> str:
    """Harness-compatible short fingerprint (evaluate.common._prompt_hash)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:PROMPT_HASH_LEN]


_CVE_TAG_RE = re.compile(r"<CVE>\s*([A-Za-z]+-\d[\w.-]*)\s*</CVE>")


def extract_cve_id(prompt_text: str) -> str | None:
    """Recover the CVE id rendered into the official ``<CVE>`` template tag.

    The harness prompt contract (evaluate.prompts.VULNERABILITY_ANALYSIS_PROMPT)
    wraps the id in ``<CVE>...</CVE>``; C1 needs it to configure the tool
    server session (``--cve`` flag).
    """
    m = _CVE_TAG_RE.search(prompt_text)
    return m.group(1) if m else None


def write_frozen_prompts(out_dir: Path) -> dict[str, str]:
    """Materialize derived prompts to ``<variant>-<hash>.txt`` files.

    Returns {variant: filename}. Used to freeze prompt versions under
    eval/vexbench-prompts/ and to detect drift between this module and the
    files copied into the external harness's evaluate/prompts.py.
    """
    out: dict[str, str] = {}
    for variant in (PROMPT_B1_PRIME, PROMPT_C1):
        text = build_prompt(variant)
        name = f"{variant}-{prompt_hash(text)}.txt"
        (out_dir / name).write_text(text, encoding="utf-8")
        out[variant] = name
    return out


if __name__ == "__main__":
    import sys

    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else _REPO_ROOT / "eval" / "vexbench-prompts"
    for variant, name in write_frozen_prompts(dest).items():
        print(f"{variant}: {name}")
