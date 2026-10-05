#!/usr/bin/env python3
"""Generate a local eval corpus from a private human-triage export.

The export and everything that identifies its origin (field codes,
component names, release refs, env var names) live outside the repo.
This script only knows a generic item shape:

    [ { "unit": {<object>}, "attributes":
        [{"attribute": {"code": "<code>"}, "value": <any>}, ...] } ]

All specifics come from a mapping config (see
eval/reviewed-map.example.json):

    REVIEWED_MAP=<config.json> REVIEWED_RAW=<export.json> \
        python3 eval/gen_reviewed_corpus.py [--out eval/corpus-reviewed.json]

The generated corpus file is gitignored: it embeds the human rationale
text. Advisory docs fetched from OSV land in eval/advisories/reviewed/
and are public data.
"""
import argparse
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADV_DIR = os.path.join(ROOT, "eval", "advisories", "reviewed")

SAFE_EXPECT = ["NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND", "INCONCLUSIVE"]


def attr(item, code):
    for a in item.get("attributes") or []:
        if a.get("attribute", {}).get("code") == code:
            return a.get("value")


def txt(v):
    if v is None:
        return ""
    if isinstance(v, list):
        return ",".join(
            x.get("name", x.get("code", "?")) if isinstance(x, dict) else str(x)
            for x in v
        )
    if isinstance(v, dict):
        return v.get("name") or v.get("code") or str(v)
    return str(v)


def pick_ids(idstr):
    """Order vuln-id candidates: GHSA > GO-* > CVE > other."""
    ids = [x.strip() for x in idstr.split(",") if x.strip()]
    return sorted(
        ids,
        key=lambda x: (
            0 if x.startswith("GHSA")
            else 1 if x.startswith("GO-")
            else 2 if x.startswith("CVE")
            else 3,
            x,
        ),
    )


def fetch_osv(vid):
    path = os.path.join(ADV_DIR, f"{vid}.json")
    if os.path.exists(path):
        return path
    try:
        with urllib.request.urlopen(
            f"https://api.osv.dev/v1/vulns/{vid}", timeout=15
        ) as r:
            data = r.read()
        json.loads(data)
    except Exception:
        return None
    with open(path, "wb") as f:
        f.write(data)
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=os.path.join(ROOT, "eval", "corpus-reviewed.json"))
    args = ap.parse_args()
    cfg = json.load(open(os.environ["REVIEWED_MAP"]))
    raw_path = os.environ["REVIEWED_RAW"]
    fields = cfg["fields"]
    components = cfg["components"]
    skip_pkgs = set(cfg.get("skip_packages", []))
    pv_re = re.compile(cfg.get("product_version_regex", r"([\d]+\.[\d.]+(?:-[a-zA-Z0-9.]+)?)\s*$"))

    os.makedirs(ADV_DIR, exist_ok=True)
    items = json.load(open(raw_path))
    cases, skipped = [], []
    for it in items:
        u = it["unit"]
        comp = txt(attr(it, fields["component"]))
        pkg = txt(attr(it, fields["package"]))
        if comp not in components or pkg in skip_pkgs:
            continue
        m = pv_re.search(u.get(cfg.get("product_version_field", "summary"), ""))
        pv = m.group(1) if m else "?"
        comp_cfg = components[comp]
        if pv in comp_cfg.get("refs", {}):
            ref = comp_cfg["refs"][pv]
        elif "default" in comp_cfg:
            ref = comp_cfg["default"]
        else:
            skipped.append((u["code"], comp, pv))
            continue
        chosen, vfile = None, None
        for cand in pick_ids(txt(attr(it, fields["vuln_ids"]))):
            f = fetch_osv(cand)
            if f:
                chosen, vfile = cand, f
                break
        if not chosen:
            skipped.append((u["code"], comp, pv, "no OSV doc"))
            continue
        just = txt(attr(it, fields["rationale"])).strip()
        case = {
            "id": "rev-" + u["code"].split("-")[-1],
            "vuln": chosen,
            "vuln_file": os.path.relpath(vfile, os.path.join(ROOT, "eval")),
            "repo": comp_cfg["repo"],
            "ref": ref,
            "expect": SAFE_EXPECT,
            "_note": (
                f"{u['code']} | {comp} {pv} | pkg {pkg} "
                f"{txt(attr(it, fields['package_version']))} | human: {just[:300]}"
            ),
        }
        # Per-component deployment context for batch runs — same fields the
        # analyzer accepts on the CLI (perimeter, trusted peers, manifests).
        case.update(comp_cfg.get("eval_overrides", {}))
        cases.append(case)
    json.dump({"cases": cases}, open(args.out, "w"), ensure_ascii=False, indent=2)
    print(f"cases: {len(cases)} -> {args.out}")
    for s in skipped:
        print("SKIP", s)


if __name__ == "__main__":
    sys.exit(main())
