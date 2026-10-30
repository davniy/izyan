"""Synthetic subprocess boundary tests; never launches Go, models or private inputs."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_census
import regression_guard
import runner

FAKE = '''#!/usr/bin/env python3
import json, os, pathlib, sys, shutil, hashlib
args = sys.argv[1:]
def arg(flag): return args[args.index(flag)+1]
if args[:2] == ['eval', 'research-replay']:
    out = pathlib.Path(arg('--out'))
    out.mkdir()
    shutil.copytree(arg('--run'), out / 'original')
    (out / 'historical-replay.json').write_text(json.dumps({'historical_only': True, 'current_admission': False}))
    sys.exit(0)
assert args[0] == 'research'
assert '--deterministic-only' not in args and '--decision-ready' not in args
out = pathlib.Path(arg('--output-dir'))
out.mkdir(parents=True)
snap = {'path': arg('--snapshot'), 'external_commit_sha': arg('--external-commit-sha') if '--external-commit-sha' in args else None}
adv = {'requested_id': arg('--cve'), 'source_path': arg('--advisory-file')}
snap['content_hash'] = hashlib.sha256(b''.join(p.read_bytes() for p in sorted(pathlib.Path(arg('--snapshot')).rglob('*')) if p.is_file())).hexdigest()
adv['raw_sha256'] = hashlib.sha256(pathlib.Path(arg('--advisory-file')).read_bytes()).hexdigest()
adv['canonical_sha256'] = os.environ.get('FAKE_CANONICAL', adv['raw_sha256'])
options = {key: arg('--' + key.replace('_', '-')) for key in ('goos', 'goarch', 'build_tags', 'analysis_go') if '--' + key.replace('_', '-') in args}
if 'build_tags' in options: options['build_tags'] = [args[i + 1] for i, value in enumerate(args) if value == '--build-tags']
snap.update({key: options[key] for key in ('goos', 'goarch', 'build_tags') if key in options})
if options.get('analysis_go'): snap['go_version'] = 'go version go' + options['analysis_go'].removeprefix('go') + ' darwin/arm64'
if os.environ.get('FAKE_BUILD_MISMATCH'): snap['goarch'] = 'wrong'
report = {'schema': 'research-report/5', 'run': {'run_id': out.parent.name},
          'input': {'snapshot': snap, 'advisory': adv},
          'decision': {'verdict': os.environ.get('FAKE_VERDICT', 'INCONCLUSIVE'), 'coverage': 'PARTIAL', 'evidence_refs': ['obs:o1']},
          'disposition': {'class': 'REVIEW_REQUIRED', 'auto_close': False}}
manifest = {'run_id': out.parent.name, 'snapshot': dict(snap), 'advisory': dict(adv)}
manifest['options'] = options
if snap['external_commit_sha'] is None: manifest['snapshot']['external_commit_sha'] = ''
if os.environ.get('FAKE_FOREIGN') == 'run': manifest['run_id'] = 'foreign'
if os.environ.get('FAKE_FOREIGN') == 'input':
    manifest['advisory']['requested_id'] = 'FOREIGN'
    report['input']['advisory']['requested_id'] = 'FOREIGN'
if os.environ.get('FAKE_ARTIFACT'):
    report['schema'] = 'research-report/3'
    manifest['decision_ready'] = {'termination': 'PLANNER_FAILURE', 'ready': False, 'turns': []}
    artifact = {'proposed_disposition': 'HOLD_UNKNOWN', 'branches': [{'id': 'B-UNKNOWN', 'status': 'NOT_DECISION_READY'}], 'human_action': {}, 'shared_facts': []}
    (out / 'decision-artifact.json').write_text(json.dumps(artifact))
(out / 'report.json').write_text(json.dumps(report))
(out / 'run-manifest.json').write_text(json.dumps(manifest))
(out / 'observations.jsonl').write_text(json.dumps({'id': 'o1'}) + '\\n')
sys.exit(int(os.environ.get('FAKE_EXIT', '0')))
'''


def inputs(tmp_path):
    binary = tmp_path / 'fake-izyan'
    binary.write_text(FAKE)
    binary.chmod(0o755)
    snap = tmp_path / 'snapshot'
    snap.mkdir()
    adv = tmp_path / 'advisory.json'
    adv.write_text('{}')
    saved = tmp_path / 'saved'
    saved.mkdir()
    manifest = {'run_id': 'original', 'snapshot': {'path': str(snap), 'external_commit_sha': 'pinned', 'content_hash': hashlib.sha256(b'').hexdigest()},
                'advisory': {'requested_id': 'CVE-REQUESTED', 'resolved_id': 'GO-RESOLVED', 'source_path': str(adv),
                             'raw_sha256': hashlib.sha256(b'{}').hexdigest(), 'canonical_sha256': hashlib.sha256(b'{}').hexdigest()}}
    (saved / 'run-manifest.json').write_text(json.dumps(manifest))
    row = {'case': 'case-01', 'baseline_dir': str(saved), 'verdict': 'INCONCLUSIVE', 'coverage': 'PARTIAL'}
    baseline = tmp_path / 'r6-corporate-baseline.json'
    baseline.write_text(json.dumps({'rows': [row]}))
    return binary, baseline, row


def test_census_uses_current_command(tmp_path):
    binary, baseline, _ = inputs(tmp_path)
    rc, path = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    assert rc == 0
    comparison = json.loads(path.read_text())
    assert comparison['results'][0]['fresh'] == ['INCONCLUSIVE', 'PARTIAL']
    regression_guard.current_guard(path, baseline)


def test_census_rejects_stale_report_after_failure(tmp_path, monkeypatch):
    binary, baseline, _ = inputs(tmp_path)
    rc, first = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    assert rc == 0
    # Even a report emitted by the failed attempt must not be consumed.
    monkeypatch.setenv('FAKE_EXIT', '1')
    rc, second = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    result = json.loads(second.read_text())['results'][0]
    assert first.parent != second.parent
    assert rc == 2 and result['fresh'] is None and result['status'] == 'TECHNICAL_FAILURE'
    with pytest.raises(SystemExit):
        regression_guard.current_guard(second, baseline)


@pytest.mark.parametrize('foreign', ['run', 'input'])
def test_census_rejects_foreign_manifest(tmp_path, monkeypatch, foreign):
    binary, baseline, _ = inputs(tmp_path)
    monkeypatch.setenv('FAKE_FOREIGN', foreign)
    rc, path = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    assert rc == 2
    assert json.loads(path.read_text())['results'][0]['fresh'] is None


def test_census_preserves_baseline(tmp_path, monkeypatch):
    binary, baseline, row = inputs(tmp_path)
    saved = Path(row['baseline_dir']) / 'run-manifest.json'
    before = baseline.read_bytes(), saved.read_bytes()
    monkeypatch.setenv('FAKE_VERDICT', 'EXPLOITABLE')
    rc, _ = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    assert rc == 1  # label drift, not command failure
    assert before == (baseline.read_bytes(), saved.read_bytes())


def test_census_cli_subprocess_smoke(tmp_path):
    binary, baseline, _ = inputs(tmp_path)
    pointer = tmp_path / 'current.txt'
    cmd = [sys.executable, str(Path(run_census.__file__)), '--corpus', str(tmp_path),
           '--output-dir', str(tmp_path / 'outputs'), '--izyan-bin', str(binary),
           '--comparison-pointer', str(pointer)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    path = Path(pointer.read_text().strip())
    assert path.is_file()
    proc = subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ, FAKE_EXIT='7'))
    assert proc.returncode == 2 and not pointer.exists()
    assert path.is_file()  # old artifact is retained but never selected


@pytest.mark.parametrize('version', [2, 3, 4, 5])
def test_guard_explicit_schema_adapters(version):
    report = {'schema': f'research-report/{version}', 'decision': {'verdict': 'INCONCLUSIVE'}}
    assert runner.report_decision(report)['verdict'] == 'INCONCLUSIVE'
    if version == 5:
        report['decision_artifact'] = {}
        with pytest.raises(ValueError):
            runner.report_decision(report)


def test_guard_rejects_foreign_comparison(tmp_path):
    binary, baseline, _ = inputs(tmp_path)
    _, path = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    comp = json.loads(path.read_text())
    comp['results'][0]['run_dir'] = str(tmp_path / 'foreign')
    path.write_text(json.dumps(comp))
    with pytest.raises(SystemExit):
        regression_guard.current_guard(path, baseline)


def test_guard_keeps_immutable_safety_labels(tmp_path, monkeypatch):
    binary, baseline, _ = inputs(tmp_path)
    monkeypatch.setenv('FAKE_VERDICT', 'NOT_AFFECTED')
    _, path = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    safety = tmp_path / 'safety.json'
    safety.write_text(json.dumps({'rows': [{'case': 'case-01', 'expected_class': 'exploitable'}]}))
    with pytest.raises(SystemExit):
        regression_guard.current_guard(path, baseline, safety)


def test_guard_rejects_hidden_changed_rows(tmp_path, monkeypatch):
    binary, baseline, _ = inputs(tmp_path)
    monkeypatch.setenv('FAKE_VERDICT', 'EXPLOITABLE')
    _, path = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    comp = json.loads(path.read_text())
    comp['changed'] = []
    path.write_text(json.dumps(comp))
    with pytest.raises(SystemExit):
        regression_guard.current_guard(path, baseline)


def test_parse_run_never_reads_failed_command_report(tmp_path):
    (tmp_path / 'report.json').write_text('not even JSON')
    rec = runner.parse_run('case-01', {}, tmp_path, ['research'], [], 1, 0, False, [])
    assert rec['category'] == 'error' and rec['status'] == 'ERROR'


@pytest.mark.parametrize('material', ['snapshot', 'raw_advisory', 'canonical_advisory'])
def test_census_rejects_material_drift_at_same_path(tmp_path, monkeypatch, material):
    binary, baseline, row = inputs(tmp_path)
    snap, adv, _ = run_census.case_args(row)
    before = baseline.read_bytes()
    if material == 'snapshot':
        (Path(snap['path']) / 'changed.go').write_text('package changed')
    elif material == 'raw_advisory':
        Path(adv['source_path']).write_text('{"changed": true}')
    else:
        monkeypatch.setenv('FAKE_CANONICAL', 'foreign-canonical-pin')
    rc, path = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    result = json.loads(path.read_text())['results'][0]
    assert rc == 2 and result['fresh'] is None
    assert 'pin mismatch' in result['error']
    assert baseline.read_bytes() == before


@pytest.mark.parametrize('mismatch', [False, True])
def test_census_preserves_effective_build_and_toolchain(tmp_path, monkeypatch, mismatch):
    binary, baseline, row = inputs(tmp_path)
    saved = Path(row['baseline_dir']) / 'run-manifest.json'
    source = json.loads(saved.read_text())
    source['options'] = {'goos': 'linux', 'goarch': 'amd64', 'build_tags': ['feature', 'custom'], 'analysis_go': '1.25.0'}
    saved.write_text(json.dumps(source))
    if mismatch:
        monkeypatch.setenv('FAKE_BUILD_MISMATCH', '1')
    rc, path = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    assert rc == (2 if mismatch else 0)
    if not mismatch:
        regression_guard.current_guard(path, baseline)


def test_optional_commit_real_go_encoding_is_absent_only():
    report = {'run': {'run_id': 'r'}, 'input': {'snapshot': {'external_commit_sha': None}}}
    manifest = {'run_id': 'r', 'snapshot': {'external_commit_sha': ''}}
    runner.validate_run_identity(report, manifest, [])
    with pytest.raises(ValueError):
        runner.validate_run_identity(report, manifest, ['--external-commit-sha', 'required'])
    manifest['snapshot']['external_commit_sha'] = 'foreign'
    with pytest.raises(ValueError):
        runner.validate_run_identity(report, manifest, [])


def test_census_preserves_recorded_host_effective_build(tmp_path):
    binary, baseline, row = inputs(tmp_path)
    retained = Path(row['baseline_dir'])
    (retained / 'report.json').write_text(json.dumps({'input': {'snapshot': {
        'goos': 'linux', 'goarch': 'arm64', 'build_tags': ['retained'],
        'go_version': 'go version go1.25.0 linux/arm64'}}}))
    rc, path = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    assert rc == 0
    regression_guard.current_guard(path, baseline)
    result = json.loads(path.read_text())['results'][0]
    report = json.loads((Path(result['run_dir']) / 'report.json').read_text())
    assert report['input']['snapshot']['goos'] == 'linux'
    assert report['input']['snapshot']['go_version'].split()[2] == 'go1.25.0'


def test_retained_toolchain_fallback_is_technical_failure():
    report = {'input': {'snapshot': {'go_version': 'go version go1.26.1 darwin/arm64'}}}
    manifest = {'options': {'analysis_go': '1.25.0'}}
    with pytest.raises(ValueError, match='toolchain mismatch'):
        run_census.validate_retained_inputs(report, manifest, {}, {}, {'analysis_go': '1.25.0'})


def test_guard_rechecks_retained_digest_pins(tmp_path):
    binary, baseline, _ = inputs(tmp_path)
    _, path = run_census.census(baseline, tmp_path / 'outputs', str(binary))
    row = json.loads(path.read_text())['results'][0]
    output = Path(row['run_dir'])
    for name in ('report.json', 'run-manifest.json'):
        data = json.loads((output / name).read_text())
        section = data['input']['snapshot'] if name == 'report.json' else data['snapshot']
        section['content_hash'] = 'same-foreign-pin-in-both-outputs'
        (output / name).write_text(json.dumps(data))
    with pytest.raises(SystemExit):
        regression_guard.current_guard(path, baseline)
