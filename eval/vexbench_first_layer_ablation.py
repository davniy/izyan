#!/usr/bin/env python3
"""First-layer VEX parity ablation — Task 2 entrypoint.

Two commands, both fail-closed:

- ``preflight`` verifies (or freezes) the Task 1 manifest, probes the one
  local image digest and the snapshot identity, checks the secret runtime
  channel, compares the effective configs (A-D identical, E only the MCP
  treatment) and writes ``preflight.json``.  It makes no model call.
- ``run`` repeats the same preflight, then executes the 15 preassigned
  attempts sequentially in repeat-major order.  Every attempt is
  immutable; an existing attempt directory aborts the run.

Credentials are never arguments: only the path of the harness's secret
env file is passed, and only its key names are recorded.

Exit codes: 0 success, 2 controller/infrastructure refusal.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

WORKTREE = Path(__file__).resolve().parents[1]
if str(WORKTREE) not in sys.path:
    sys.path.insert(0, str(WORKTREE))

from eval.first_layer_ablation import runner  # noqa: E402

DEFAULT_HARNESS = Path("/tmp/vexbench-agent-ctl")
DEFAULT_RESULTS = WORKTREE / "results" / "first-layer-ablation"


def _read_json(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("{} must contain a JSON object".format(path))
    return payload


def _common_kwargs(args: argparse.Namespace) -> Dict[str, Any]:
    harness_dir = Path(args.harness_dir)
    # The launcher resolves env/opencode/* relative to the harness checkout.
    # Defaults follow --harness-dir so the validated file is the file the
    # adapter will actually mount / pass to --env-file.
    secret_env = (
        Path(args.secret_env)
        if args.secret_env
        else harness_dir / "env" / "opencode" / "opencode.env"
    )
    secret_config = (
        Path(args.secret_config)
        if args.secret_config
        else harness_dir / "env" / "opencode" / "opencode.json"
    )
    return {
        "results_root": Path(args.results_root),
        "manifest_path": Path(args.manifest) if args.manifest else None,
        "case": _read_json(args.case),
        "runtime": _read_json(args.runtime),
        "advisory_path": Path(args.advisory) if args.advisory else None,
        "secret_env_path": secret_env,
        "secret_config_path": secret_config,
        "harness_dir": harness_dir,
    }


def cmd_preflight(args: argparse.Namespace) -> int:
    if not args.manifest and not (args.case and args.runtime and args.advisory):
        print(
            "preflight: pass --manifest, or --case/--runtime/--advisory to "
            "freeze a new manifest",
            file=sys.stderr,
        )
        return 2
    report = runner.preflight(
        frozen_at_utc=args.frozen_at, **_common_kwargs(args)
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if not args.manifest and not (args.case and args.runtime and args.advisory):
        print(
            "run: pass --manifest, or --case/--runtime/--advisory so the "
            "preflight can freeze one before the first answer",
            file=sys.stderr,
        )
        return 2
    summary = runner.run_experiment(
        frozen_at_utc=args.frozen_at, **_common_kwargs(args)
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary.get("outcome") == "complete" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the frozen first-layer VEX ablation (A-E x 3 repeats) "
            "through the existing OpenCode runtime. No model call happens "
            "during preflight."
        )
    )
    parser.add_argument(
        "--results-root",
        default=str(DEFAULT_RESULTS),
        help="experiment root; the manifest lives in "
             "<root>/<experiment_id>/",
    )
    parser.add_argument(
        "--harness-dir", default=str(DEFAULT_HARNESS),
        help="external harness checkout (adapters and secret env file)",
    )
    parser.add_argument(
        "--secret-env", default=None,
        help="secret runtime env file (default: "
             "<harness-dir>/env/opencode/opencode.env); values are never "
             "read into artifacts",
    )
    parser.add_argument(
        "--secret-config", default=None,
        help="provider config the launcher mounts (default: "
             "<harness-dir>/env/opencode/opencode.json); must match the "
             "adapter's resolved config path",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler in (("preflight", cmd_preflight), ("run", cmd_run)):
        command = sub.add_parser(name)
        command.add_argument(
            "--manifest", default=None,
            help="frozen Task 1 manifest.json; omit to freeze a new one",
        )
        command.add_argument("--case", default=None, help="case JSON file")
        command.add_argument(
            "--runtime", default=None, help="runtime JSON file"
        )
        command.add_argument(
            "--advisory", default=None, help="frozen advisory JSON file"
        )
        command.add_argument(
            "--frozen-at", default=None,
            help="manifest timestamp YYYY-MM-DDTHH:MM:SSZ",
        )
        command.set_defaults(func=handler)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except runner.AblationError as exc:
        print(json.dumps(exc.as_dict(), indent=2, sort_keys=True),
              file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(
            json.dumps(
                {"error": "invalid_input", "message": str(exc)},
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
