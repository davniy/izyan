"""First-layer VEX parity ablation (single-case diagnostic).

The experiment holds one Kubernetes snapshot (``e196d24``), one CVE
(``CVE-2023-44487``), one model/provider and one attempt policy fixed while
it varies ONE prompt treatment at a time:

- ``A`` — the frozen official VEX prompt, only ``{cve_id}`` substituted;
- ``B`` — A plus the frozen advisory as reference data;
- ``C`` — B plus the semantic advisory-binding rules (no assessment);
- ``D`` — C plus the eight-section research assessment format;
- ``E`` — D plus the izyan evidence-tools description.

``protocol.py`` owns the byte-level prompt contract, the adjacent-arm delta
assertions, the prohibited-content scan and the frozen manifest builder.
The runner/report modules (Tasks 2-3) consume the same protocol; nothing in
this package calls a model, Docker or the izyan MCP server.

This is a diagnostic, not a benchmark claim: one case localizes a treatment
effect, it does not establish general parity.
"""

__all__ = ()
