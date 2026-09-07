"""Assemble valid partial reports from one explicitly identified producer run."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from scripts.code_analysis import channel_status, evidence_contract, provenance
from scripts.code_analysis.hosted import build, load, write
from scripts.code_analysis.monitoring import canonicalize, build_snapshot
from scripts.code_analysis.snapshot import build_analysis_snapshot


def assemble(artifacts: Path, output: Path, identity: dict, producer_repository: str,
             run_id: str, source: Path, config_root: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    normalized = output / 'normalized'
    subprocess.run([sys.executable, '-m', 'scripts.code_analysis.normalizer', '--input-dir',
                    str(artifacts), '--output-dir', str(normalized)], check=True)
    raw = load(normalized / 'unified-findings.json')
    manifest = load(config_root / 'required-channels.json')
    repository, sha = identity['source_repository'], identity['head_sha']
    contract = evidence_contract.build(manifest, artifacts, repository, sha, [run_id])
    status = channel_status.build(manifest, artifacts, raw, contract, repository, sha)
    from scripts.code_analysis.hosted import now
    current = canonicalize(raw, repository, {'commit_sha': sha, 'branch': identity['branch'],
                            'workflow_run_id': run_id, 'generated_at': now()}, manifest)
    proof = provenance.build(artifacts, sha, [run_id])
    snapshot = build_analysis_snapshot(build_snapshot(current, status, proof, allow_partial=True),
                                      load(config_root / 'proposal-tool-catalog.json'), artifacts)
    # Persist the strict gate result unchanged; hosted validity permits missing evidence.
    write(output / 'snapshot.json', snapshot)
    return build(snapshot, identity, output / 'report', producer_repository=producer_repository,
                 source=source)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--target', type=Path, required=True)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--run-id', required=True)
    p.add_argument('--producer-repository', required=True)
    a = p.parse_args()
    assemble(a.artifacts, a.output, load(a.target), a.producer_repository, a.run_id,
             a.source, Path('config/code-analysis'))


if __name__ == '__main__':
    main()
