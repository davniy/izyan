"""Task 5 prompt construction — byte-exact P1/T1 generation (plan §4).

Normative sources:
- spec:  docs/dev/specs/2026-10-09-task5-prompt-tools-gate-comparison-v2.md
         (§3.3 arm equality, §4 tuned safety prompt rules, §4.1 output
         contract, §7 prohibited case-specific content)
- plan:  docs/dev/plans/2026-10-09-task5-implementation-plan.md (§4)

The two prompt variants share ONE research methodology and ONE output
contract; the only treatment difference is the appended tool API block:

    vuln_safety_v1        (P1, plain)  = OFFICIAL + "\\n\\n" + SAFETY_RULES + "\\n"
    vuln_safety_v1_tools  (T1, tools)  = P1     + "\\n\\n" + EVIDENCE_TOOLS + "\\n"

so the frozen official template is an unchanged byte prefix of P1
(the file already ends with a single LF, so ``OFFICIAL + "\\n"`` puts a
blank line before ``<SAFETY_RULES>``) and T1 extends P1 by exactly two
LF bytes plus the literal ``<EVIDENCE_TOOLS>`` block (terminated by the
file's own trailing LF, as in every prompts_data file).

The appended blocks contain NO case/product/fix identifiers and NO new
placeholders: ``{cve_id}`` survives only inside the official prefix and
is rendered by the harness exactly as in P0 (``.replace("{cve_id}", ...)``).
Unlike Task 4 (``vuln_assess``/``vuln_c1``) there is deliberately NO
structured-assessment block: category-only output keeps the official
scoring contract and leaves ``assessment_schema=absent`` as artifact
availability (plan §7).
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Iterable, Optional, Sequence

PROMPT_HASH_LEN = 12

_REPO_ROOT = Path(__file__).resolve().parents[2]
_OFFICIAL_PROMPT_FILE = (
    _REPO_ROOT / "eval" / "vexbench-prompts" / "official-vuln-c0a5c8458b77.txt"
)

# Frozen sha256 of the official template bytes (stripped), pinned by the
# filename and by the Task 4 manifest — asserted, never recomputed blindly.
FROZEN_OFFICIAL_SHA256 = (
    "c0a5c8458b77015d57b82eefca563d01c870ea027562381715c8ab9d70ffabda"
)


def _load_official_template() -> str:
    """Frozen official ``vuln`` template verbatim (stripped like C1 does)."""
    text = _OFFICIAL_PROMPT_FILE.read_text(encoding="utf-8").strip()
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if digest != FROZEN_OFFICIAL_SHA256:
        raise AssertionError(
            f"frozen official template drifted: sha256 {digest} != "
            f"{FROZEN_OFFICIAL_SHA256} — never re-derive the prefix"
        )
    return text


# --- block 1: shared tuned safety rules (P1 and T1) --------------------------
#
# The literal <SAFETY_RULES> block from the plan, verbatim. General
# principles only — no case names, no product hints, no fix ids
# (spec §4 prohibition list).

SAFETY_RULES_BLOCK = """
<SAFETY_RULES>
1. Separate local observations from your final conclusion. "no matches",
   "not imported", "fix found", "default=false", or "OK/COMPLETE" from one
   query does not prove that the CVE is not exploitable.
2. Check alternative manifestations of the defect. Advisory packages,
   fix diffs and affected symbols may not exhaust runtime manifestations.
   Check relevant versions, transitive implementations, generated runtime
   code and dependency-internal calls.
3. A negative conclusion requires a countercheck. Before a safe answer,
   state the necessary exploitation condition, scope, alternatives checked,
   supporting facts and remaining limitations. If a material alternative
   remains unchecked, choose "uncertain".
4. Do not turn failures into absence. A tool error, timeout, PARTIAL result,
   failed build, missing toolchain or unverified deployment fact leaves the
   relevant condition open.
5. Exploitability is not one reachability fact. Absence of a direct
   first-party import does not exclude a transitive path; a single
   reachability observation is not a global exploitability conclusion.
6. Return the single structured benchmark JSON with its official category
   and concrete reasoning, including scope and limitations. Do not invent
   evidence IDs. "uncertain" is an abstention, not a safe conclusion.
</SAFETY_RULES>
""".strip()


# --- block 2: T1-only evidence tools API note --------------------------------
#
# The literal <EVIDENCE_TOOLS> block from the plan, verbatim. It is a
# SHORT capability description — deliberately narrower than the Task 4
# <EVIDENCE_TOOLS> contract block (which carried binding interpretation
# rules for a different output protocol). Task 5 keeps the safety rules
# in <SAFETY_RULES> shared between both arms; this block only documents
# that the 31 existing tools exist and how their result fields read.

EVIDENCE_TOOLS_BLOCK = """
<EVIDENCE_TOOLS>
The connected izyan MCP server exposes the existing 31 snapshot evidence
tools: advisory/fix, dependency/module, source/symbol/caller, dataflow/
validation, dynamic-dispatch and optional build/test observations.
Results contain fact, scope, completeness, tool_status, evidence_refs,
limitations, scope_details and data. OK concerns this call only; COMPLETE
concerns only its named scope. Apply the shared safety rules to all results.
Use normal coding-agent tools as well: MCP tools are additive.
</EVIDENCE_TOOLS>
""".strip()


# --- prompt variants -----------------------------------------------------------

PROMPT_P1 = "vuln_safety_v1"        # P1: official + safety rules, no MCP
PROMPT_T1 = "vuln_safety_v1_tools"  # T1: exact P1 bytes + tools API block

PROMPT_FILENAMES = {
    PROMPT_P1: "vuln_safety_v1.txt",
    PROMPT_T1: "vuln_safety_v1_tools.txt",
}


def build_prompt(variant: str) -> str:
    """Render a Task 5 prompt template (bytes-exact contract per plan §4).

    P1 = frozen official template (unchanged prefix) + "\\n\\n" +
    ``<SAFETY_RULES>`` + "\\n".  T1 = P1's exact bytes + two LF + the
    literal ``<EVIDENCE_TOOLS>`` block + "\\n". Anything else is rejected.
    """
    base = _load_official_template()
    if variant == PROMPT_P1:
        return f"{base}\n\n{SAFETY_RULES_BLOCK}\n"
    if variant == PROMPT_T1:
        return f"{build_prompt(PROMPT_P1)}\n\n{EVIDENCE_TOOLS_BLOCK}\n"
    raise ValueError(
        f"unknown prompt variant {variant!r}; expected "
        f"{PROMPT_P1!r} or {PROMPT_T1!r}"
    )


def prompt_hash(text: str) -> str:
    """Harness-compatible short fingerprint (evaluate.common._prompt_hash)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:PROMPT_HASH_LEN]


# --- prohibited-identifier scan ------------------------------------------------
#
# Spec §4: the prompt must not carry known VEX-Bench case names, product
# hints or fix ids. Two scopes:
# - ``block`` rules apply to the appended blocks only (a literal CVE/GHSA
#   id there would be a case hint; the official EXAMPLE already contains a
#   GHSA id, so the whole file is never scanned for it);
# - ``full`` rules apply to the whole rendered template (a benchmark
#   task-id or a concrete affected-product identifier must not appear
#   anywhere, including inside the frozen prefix — if it did, the freeze
#   itself is invalid and we fail loudly).

_PROHIBITED_BLOCK_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("cve_id", re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)),
    ("ghsa_id", re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}",
                           re.IGNORECASE)),
    ("go_advisory_id", re.compile(r"GO-\d{4}-\d{4,}")),
]

_PROHIBITED_FULL_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("task_id", re.compile(
        r"\b[a-z0-9_.-]+-[a-z0-9_.-]+-[0-9a-f]{7}-CVE-\d", re.IGNORECASE)),
    ("product_grpc", re.compile(r"\bgrpc\b", re.IGNORECASE)),
    ("product_kubernetes", re.compile(r"\bk(?:ubernetes|8s)\b",
                                     re.IGNORECASE)),
    ("product_rancher", re.compile(r"\brancher\b", re.IGNORECASE)),
    ("generated_pb_go", re.compile(r"(?:generated\.pb\.go|\.pb\.go\b)",
                                   re.IGNORECASE)),
    ("fix_reference", re.compile(
        r"(?:fix[-_ ]?(?:commit|pr|patch|id)\b|pull/\d+|#\d{4,}\b)",
        re.IGNORECASE)),
]


def find_prohibited(
    text: str, *, extra: Optional[Iterable[str]] = None,
) -> list[str]:
    """Human-readable violations of the prohibited-identifier policy.

    ``extra`` entries are case-insensitive literal needles (used to scan
    the rendered prompt against the actual benchmark task ids). Returns a
    sorted list of ``"<rule>: <match>"`` strings — empty when clean.
    """
    violations: set[str] = set()
    for name, rx in _PROHIBITED_FULL_PATTERNS:
        for m in rx.finditer(text):
            violations.add(f"{name}: {m.group(0)!r}")
    for needle in extra or ():
        for m in re.finditer(re.escape(needle), text, re.IGNORECASE):
            violations.add(f"literal: {m.group(0)!r}")
    return sorted(violations)


def scan_prompts(
    prompts: Optional[dict[str, str]] = None,
    *, extra: Optional[Iterable[str]] = None,
) -> dict[str, list[str]]:
    """Scan every Task 5 prompt: full-text rules over the whole template,
    block rules over the appended delta only. ``extra`` needles are matched
    everywhere (they are benchmark-specific literals)."""
    if prompts is None:
        prompts = {v: build_prompt(v) for v in PROMPT_FILENAMES}
    base = _load_official_template()
    out: dict[str, list[str]] = {}
    for variant, text in prompts.items():
        hits = set(find_prohibited(text, extra=extra))
        # Block-scoped rules: applied to whatever was appended past the
        # frozen official prefix.
        delta = text[len(base):] if text.startswith(base) else text
        for name, rx in _PROHIBITED_BLOCK_PATTERNS:
            for m in rx.finditer(delta):
                hits.add(f"{name}: {m.group(0)!r}")
        out[variant] = sorted(hits)
    return out


# --- byte-contract assertions --------------------------------------------------


def assert_prompt_contract(p1: str, t1: str) -> None:
    """Enforce the plan §4 byte contract; raise AssertionError on drift."""
    base = _load_official_template()
    assert p1.startswith(base), "P1 does not start with the frozen official template"
    # The official prompt FILE is an unchanged byte prefix of P1
    # (it ends with a single LF; our appended "\n" completes the blank
    # separator line).
    assert p1.startswith(
        _OFFICIAL_PROMPT_FILE.read_text(encoding="utf-8")
    ), "official file bytes are not an unchanged prefix of P1"
    assert t1.startswith(p1), "T1 does not start with the exact P1 bytes"
    assert t1 == f"{p1}\n\n{EVIDENCE_TOOLS_BLOCK}\n", (
        "T1 - P1 is not exactly two LF + the literal <EVIDENCE_TOOLS> block"
    )
    assert p1.count("{cve_id}") == 1 and t1.count("{cve_id}") == 1, (
        "{cve_id} placeholder must survive exactly once (official prefix)"
    )
    for bad in scan_prompts({PROMPT_P1: p1, PROMPT_T1: t1}).items():
        assert not bad[1], f"{bad[0]} carries prohibited identifiers: {bad[1]}"


def unified_p1_t1_diff(p1: str, t1: str) -> str:
    """The published P1/T1 unified diff (what the treatment adds)."""
    return "".join(
        difflib.unified_diff(
            p1.splitlines(keepends=True),
            t1.splitlines(keepends=True),
            fromfile="vuln_safety_v1.txt",
            tofile="vuln_safety_v1_tools.txt",
        )
    )


def config_delta_only_mcp(b1p_config: dict, c1_config: dict) -> bool:
    """True iff two synthesized opencode configs differ ONLY at top-level
    ``mcp`` (plan §4: config equality after removing only top-level mcp).
    Used on the per-attempt artifact configs (opencode-config.b1p.json vs
    opencode-config.c1.json)."""
    a = {k: v for k, v in b1p_config.items() if k != "mcp"}
    b = {k: v for k, v in c1_config.items() if k != "mcp"}
    return a == b and "mcp" in c1_config and "mcp" not in b1p_config


# --- artifact emission ---------------------------------------------------------


def write_prompts(
    out_dir: Path,
    *,
    harness_dir: Optional[Path] = None,
) -> dict:
    """Materialize the two prompt files plus hashes.json and p1-t1.diff.

    When ``harness_dir`` is given, the harness registry is read and the
    emitted bytes must equal ``PROMPTS[variant]`` byte-for-byte (drift
    check between repo-generated files and the applied harness patch).
    Returns the hashes.json document.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    p1 = build_prompt(PROMPT_P1)
    t1 = build_prompt(PROMPT_T1)
    assert_prompt_contract(p1, t1)

    (out_dir / PROMPT_FILENAMES[PROMPT_P1]).write_text(p1, encoding="utf-8")
    (out_dir / PROMPT_FILENAMES[PROMPT_T1]).write_text(t1, encoding="utf-8")

    diff_text = unified_p1_t1_diff(p1, t1)
    (out_dir / "p1-t1.diff").write_text(diff_text, encoding="utf-8")

    doc = {
        "schema": "task5-prompts/1",
        "official_prefix": {
            "file": "eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt",
            "sha256_12": FROZEN_OFFICIAL_SHA256[:PROMPT_HASH_LEN],
            "sha256": FROZEN_OFFICIAL_SHA256,
        },
        "prompts": {
            PROMPT_P1: {
                "file": PROMPT_FILENAMES[PROMPT_P1],
                "sha256_12": prompt_hash(p1),
                "sha256": hashlib.sha256(p1.encode("utf-8")).hexdigest(),
                "bytes": len(p1.encode("utf-8")),
            },
            PROMPT_T1: {
                "file": PROMPT_FILENAMES[PROMPT_T1],
                "sha256_12": prompt_hash(t1),
                "sha256": hashlib.sha256(t1.encode("utf-8")).hexdigest(),
                "bytes": len(t1.encode("utf-8")),
            },
        },
        "diff_file": "p1-t1.diff",
        "t1_minus_p1": f"two LF bytes + literal <EVIDENCE_TOOLS> block + LF",
        "assertions": {
            "p1_prefix_is_official_file_bytes": True,
            "t1_minus_p1_is_exact_tool_block": True,
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
        for variant, text in ((PROMPT_P1, p1), (PROMPT_T1, t1)):
            reg = PROMPTS.get(variant)
            registry[variant] = {
                "registered": reg is not None,
                "bytes_equal": reg == text,
            }
            if reg != text:
                raise AssertionError(
                    f"harness PROMPTS[{variant!r}] does not match the "
                    f"generated file bytes — the Task 5 patch is stale"
                )
        doc["harness_registry"] = registry

    (out_dir / "hashes.json").write_text(
        json.dumps(doc, indent=2) + "\n", encoding="utf-8"
    )
    return doc


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="eval.task5.protocol",
        description=__doc__.split("\n")[0],
    )
    ap.add_argument(
        "--out", required=True,
        help="prompt output dir (eval/task5/prompts)")
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
    print(f"diff -> {Path(args.out) / 'p1-t1.diff'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
