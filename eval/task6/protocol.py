"""Task 6 prompt construction — byte-exact P2/T2 generation (plan §7).

Normative sources:
- spec:  docs/dev/specs/2026-10-09-task6-structured-evidence-experiment.md
         (§2 arm equality, §3 AgentAssessment contract, §4 validator)
- plan:  docs/dev/plans/2026-10-09-task6-structured-evidence-
         implementation-plan.md (§7)

The two prompt variants share ONE research methodology and ONE output
contract; the only treatment difference is the appended tool contract
block:

    vuln_safety_v2        (P2, plain)  = OFFICIAL + "\\n\\n" + SAFETY_RULES
                                         + "\\n\\n" + STRUCTURED_ASSESSMENT + "\\n"
    vuln_safety_v2_tools  (T2, tools)  = P2       + "\\n\\n" + EVIDENCE_TOOLS + "\\n"

so the frozen official template is an unchanged byte prefix of P2, the
Task-5 ``<SAFETY_RULES>`` block is reused verbatim, and T2 extends P2 by
exactly two LF bytes plus the task6-local ``<EVIDENCE_TOOLS>`` contract
block (``EVIDENCE_TOOLS_BLOCK_TASK6`` — the C1 binding-rules text
byte-for-byte except the evidence-ref field names, which are aligned to
``agent-assessment/2``), terminated by the file's own trailing LF.

Unlike Task 5 (category-only output) Task 6 adds a mandatory
``<STRUCTURED_ASSESSMENT>`` block: the agent must emit the
``agent-assessment/2`` object (mechanisms / negative_claims /
unresolved / reasoning) with machine-checkable ``evidence_refs`` — the
whole point of the experiment (spec §3).

The appended blocks contain NO case/product/fix identifiers and NO new
placeholders: ``{cve_id}`` survives only inside the official prefix and
is rendered by the harness exactly as before.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from eval.task5 import protocol as _t5  # noqa: E402

PROMPT_HASH_LEN = 12

_REPO_ROOT = Path(__file__).resolve().parents[2]
_OFFICIAL_PROMPT_FILE = (
    _REPO_ROOT / "eval" / "vexbench-prompts" / "official-vuln-c0a5c8458b77.txt"
)

# Reused verbatim from Task 5/C1 (single convention, never a second copy):
_load_official_template = _t5._load_official_template
FROZEN_OFFICIAL_SHA256 = _t5.FROZEN_OFFICIAL_SHA256
SAFETY_RULES_BLOCK = _t5.SAFETY_RULES_BLOCK
prompt_hash = _t5.prompt_hash
find_prohibited = _t5.find_prohibited
scan_prompts = _t5.scan_prompts
config_delta_only_mcp = _t5.config_delta_only_mcp


# --- block: mandatory structured assessment (P2 and T2) ---------------------
#
# The literal <STRUCTURED_ASSESSMENT> block (spec §3 / plan §7). It turns
# the Task-5 root cause — answers carrying only {category, reasoning} —
# into a machine-checkable claim→subject/scope→evidence binding.
# General rules only — no case names, product hints or fix ids.

STRUCTURED_ASSESSMENT_BLOCK = """
<STRUCTURED_ASSESSMENT>
Your ENTIRE response MUST be exactly one JSON object and nothing else:
the first character is "{" and the last is "}". No markdown table, no
headings, no bullet lists, no prose before or after, no comments. A bare
object is preferred; a single ```json fenced block containing only the
object is tolerated but never required. All strings must be valid JSON
(escape newlines as \\n and inner double quotes as \\") - if the output
is not one syntactically valid JSON object it cannot be scored at all.

In addition to "category" and "reasoning", that single JSON object MUST
contain an "assessment" field with your structured analysis:

{
  "category": "<one of the 12 category names, exact snake_case>",
  "reasoning": "<evidence-based explanation>",
  "assessment": {
    "mechanisms": [
      {
        "subject": "<affected module, package or symbol this manifestation covers>",
        "scope": "<build tags, platform, call context and mechanism boundary you actually verified>",
        "limitations": ["<what this manifestation check could not cover>"]
      }
    ],
    "negative_claims": [
      {
        "predicate": "<one atomic negative assertion: e.g. absent / unreachable / fixed-version>",
        "subject": "<module, package or symbol the claim is about>",
        "scope": "<the scope the claim is restricted to: build tags, platform, call context, considered mechanism>",
        "evidence_refs": ["<evidence reference supporting THIS claim>"],
        "limitations": ["<what this claim does not establish>"]
      }
    ],
    "unresolved": ["<unexplored alternative path, tool error or unresolved condition>"],
    "reasoning": "<human-readable explanation of the assessment - not proof>"
  }
}

Rules:
- "category" and "reasoning" at top level stay EXACTLY as specified in
  <OUTPUT_FORMAT>: official category name, evidence-grounded reasoning.
- Split claims into atomic predicates: one negative assertion per entry,
  each with its own subject, scope and evidence. Never bundle a global
  conclusion into a single vague claim.
- evidence_refs bind each claim to checkable evidence, in exactly these
  forms:
    "file:<path>[:<line>[-<line>]]"    - a location you verified in this
        tree. After "file:" write ONLY the path and optional line(s) -
        no package names, versions or commentary. INVALID:
        "file:go.sum:github.com/x v1 entries" (free text after the
        path). VALID: "file:go.sum:12" or "file:go.sum".
    "src:<path>#L<line>@<snapshot-hash>" - a tool-reported source position;
        append the snapshot hash printed by get_product_snapshot
    "sha256:<64 lowercase hex>"        - a payload digest emitted by a tool
    "ev:OBS-NNNN"                      - an observation id emitted by a tool
    "url:https://..."                  - a public advisory or fix document
  Cite only refs that exist. "src:", "sha256:" and "ev:" refs resolve to
  recorded tool output - if no evidence tools are connected, use "file:"
  and "url:" refs. Never invent observation ids, hashes or paths.
- For a safe category (any of the first ten in the precedence list),
  include at least one negative_claim with non-empty evidence_refs that
  states WHY the CVE cannot manifest - the falsifier you checked. A safe
  verdict resting on no checkable negative claim is not a verified answer.
- Record every unexplored alternative path, failed or partial check in
  "unresolved". A safe category with a non-empty "unresolved" list is a
  defect - choose "uncertain" instead.
- "assessment.reasoning" is context for a human reviewer, not proof: the
  words COMPLETE or "safe" and your own confidence are not evidence of
  coverage.
- Do NOT include task ids, snapshot hashes (except inside evidence_refs),
  model or tool versions, token counts or timings inside "assessment" -
  those are recorded by the harness.
- If you genuinely cannot reach a conclusion, keep "category": "uncertain"
  and explain the open conditions in "unresolved". Do not emit a safe
  category as a hedge.
- Reminder: emit exactly ONE JSON object as your whole response - no
  markdown table, no headings, no prose outside the object.
</STRUCTURED_ASSESSMENT>
""".strip()


# --- block: task6-local evidence-tools contract (T2 only) ----------------------
#
# Byte-for-byte the C1 <EVIDENCE_TOOLS> binding-rules block EXCEPT the
# evidence-ref citation line, which is aligned to the agent-assessment/2
# field names (assessment.negative_claims[].evidence_refs — the schema v1
# names claims[]/evidence[] do not exist in this experiment's contract).
# Task6-local by design: eval.c1.protocol must stay verbatim for C1.
# General rules only — no case names, product hints or fix ids.

EVIDENCE_TOOLS_BLOCK_TASK6 = """
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
  assessment.negative_claims[].evidence_refs, use the Observation
  "evidence_refs" entries verbatim (they resolve to the recorded tool
  artifact).
</EVIDENCE_TOOLS>
""".strip()


# --- prompt variants -----------------------------------------------------------

PROMPT_P2 = "vuln_safety_v2"        # P2: official + safety + assessment, no MCP
PROMPT_T2 = "vuln_safety_v2_tools"  # T2: exact P2 bytes + tools contract block

PROMPT_FILENAMES = {
    PROMPT_P2: "vuln_safety_v2.txt",
    PROMPT_T2: "vuln_safety_v2_tools.txt",
}


def build_prompt(variant: str) -> str:
    """Render a Task 6 prompt template (bytes-exact contract per plan §7).

    P2 = frozen official template (unchanged prefix) + "\\n\\n" +
    ``<SAFETY_RULES>`` + "\\n\\n" + ``<STRUCTURED_ASSESSMENT>`` + "\\n".
    T2 = P2's exact bytes + two LF + the task6-local
    ``<EVIDENCE_TOOLS>`` block + "\\n". Anything else is rejected.
    """
    base = _load_official_template()
    if variant == PROMPT_P2:
        return (
            f"{base}\n\n{SAFETY_RULES_BLOCK}\n\n"
            f"{STRUCTURED_ASSESSMENT_BLOCK}\n"
        )
    if variant == PROMPT_T2:
        return f"{build_prompt(PROMPT_P2)}\n\n{EVIDENCE_TOOLS_BLOCK_TASK6}\n"
    raise ValueError(
        f"unknown prompt variant {variant!r}; expected "
        f"{PROMPT_P2!r} or {PROMPT_T2!r}"
    )


# --- byte-contract assertions --------------------------------------------------


def assert_prompt_contract(p2: str, t2: str) -> None:
    """Enforce the plan §7 byte contract; raise AssertionError on drift."""
    base = _load_official_template()
    assert p2.startswith(base), "P2 does not start with the frozen official template"
    # The official prompt FILE is an unchanged byte prefix of P2
    # (it ends with a single LF; our appended "\n" completes the blank
    # separator line).
    assert p2.startswith(
        _OFFICIAL_PROMPT_FILE.read_text(encoding="utf-8")
    ), "official file bytes are not an unchanged prefix of P2"
    assert t2.startswith(p2), "T2 does not start with the exact P2 bytes"
    assert t2 == f"{p2}\n\n{EVIDENCE_TOOLS_BLOCK_TASK6}\n", (
        "T2 - P2 is not exactly two LF + the task6-local "
        "<EVIDENCE_TOOLS> block"
    )
    assert p2.count("{cve_id}") == 1 and t2.count("{cve_id}") == 1, (
        "{cve_id} placeholder must survive exactly once (official prefix)"
    )
    for bad in scan_prompts({PROMPT_P2: p2, PROMPT_T2: t2}).items():
        assert not bad[1], f"{bad[0]} carries prohibited identifiers: {bad[1]}"


def unified_p2_t2_diff(p2: str, t2: str) -> str:
    """The published P2/T2 unified diff (what the treatment adds)."""
    return "".join(
        difflib.unified_diff(
            p2.splitlines(keepends=True),
            t2.splitlines(keepends=True),
            fromfile="vuln_safety_v2.txt",
            tofile="vuln_safety_v2_tools.txt",
        )
    )


# --- artifact emission ---------------------------------------------------------


def write_prompts(
    out_dir: Path,
    *,
    harness_dir: Optional[Path] = None,
) -> dict:
    """Materialize the two prompt files plus hashes.json and p2-t2.diff.

    When ``harness_dir`` is given, the harness registry is read and the
    emitted bytes must equal ``PROMPTS[variant]`` byte-for-byte (drift
    check between repo-generated files and the applied harness patch).
    Returns the hashes.json document.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    p2 = build_prompt(PROMPT_P2)
    t2 = build_prompt(PROMPT_T2)
    assert_prompt_contract(p2, t2)

    (out_dir / PROMPT_FILENAMES[PROMPT_P2]).write_text(p2, encoding="utf-8")
    (out_dir / PROMPT_FILENAMES[PROMPT_T2]).write_text(t2, encoding="utf-8")

    diff_text = unified_p2_t2_diff(p2, t2)
    (out_dir / "p2-t2.diff").write_text(diff_text, encoding="utf-8")

    doc = {
        "schema": "task6-prompts/1",
        "official_prefix": {
            "file": "eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt",
            "sha256_12": FROZEN_OFFICIAL_SHA256[:PROMPT_HASH_LEN],
            "sha256": FROZEN_OFFICIAL_SHA256,
        },
        "blocks": {
            "safety_rules": "eval.task5.protocol.SAFETY_RULES_BLOCK (verbatim)",
            "structured_assessment":
                "eval.task6.protocol.STRUCTURED_ASSESSMENT_BLOCK (new)",
            "evidence_tools":
                "eval.task6.protocol.EVIDENCE_TOOLS_BLOCK_TASK6 "
                "(task6-local copy of the C1 binding-rules block; "
                "evidence-ref field names aligned to "
                "agent-assessment/2)",
        },
        "prompts": {
            PROMPT_P2: {
                "file": PROMPT_FILENAMES[PROMPT_P2],
                "sha256_12": prompt_hash(p2),
                "sha256": hashlib.sha256(p2.encode("utf-8")).hexdigest(),
                "bytes": len(p2.encode("utf-8")),
            },
            PROMPT_T2: {
                "file": PROMPT_FILENAMES[PROMPT_T2],
                "sha256_12": prompt_hash(t2),
                "sha256": hashlib.sha256(t2.encode("utf-8")).hexdigest(),
                "bytes": len(t2.encode("utf-8")),
            },
        },
        "diff_file": "p2-t2.diff",
        "t2_minus_p2": "two LF bytes + task6-local <EVIDENCE_TOOLS> block + LF",
        "assertions": {
            "p2_prefix_is_official_file_bytes": True,
            "t2_minus_p2_is_exact_tool_block": True,
            "prohibited_identifiers": "none",
        },
        "harness_registry": None,
    }

    if harness_dir is not None:
        src = str(Path(harness_dir) / "src")
        if src not in sys.path:
            sys.path.insert(0, src)
        from evaluate.prompts import PROMPTS  # noqa: E402

        registry = {}
        for variant, text in ((PROMPT_P2, p2), (PROMPT_T2, t2)):
            reg = PROMPTS.get(variant)
            registry[variant] = {
                "registered": reg is not None,
                "bytes_equal": reg == text,
            }
            if reg != text:
                raise AssertionError(
                    f"harness PROMPTS[{variant!r}] does not match the "
                    f"generated file bytes — the Task 6 patch is stale"
                )
        doc["harness_registry"] = registry

    (out_dir / "hashes.json").write_text(
        json.dumps(doc, indent=2) + "\n", encoding="utf-8"
    )
    return doc


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="eval.task6.protocol",
        description=__doc__.split("\n")[0],
    )
    ap.add_argument(
        "--out", required=True,
        help="prompt output dir (eval/task6/prompts)")
    ap.add_argument(
        "--harness-dir", default=None,
        help="verify the emitted bytes equal harness PROMPTS entries")
    args = ap.parse_args(argv)

    doc = write_prompts(
        Path(args.out),
        harness_dir=Path(args.harness_dir) if args.harness_dir else None,
    )
    for variant, info in doc["prompts"].items():
        print(f"{variant}: {info['file']} sha256_12={info['sha256_12']} "
              f"({info['bytes']} bytes)")
    print(f"diff -> {Path(args.out) / 'p2-t2.diff'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
