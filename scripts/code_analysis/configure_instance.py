"""Create another repository's service configuration without changing the current instance."""
import argparse
import json
from pathlib import Path

from scripts.code_analysis.extensions import registry
from scripts.code_analysis.hosted import REPOSITORY, load


def configure(template: dict, source: str, analysis: str, publishing: str, branch: str, profile: dict) -> dict:
    if not all(REPOSITORY.fullmatch(value) for value in (source, analysis, publishing)) or not branch.strip():
        raise ValueError('Repository identifiers must be owner/repo; preferred branch is required')
    if publishing in {source, analysis} or analysis == source:
        raise ValueError('Source, analysis host and publishing repository must be separate')
    if not isinstance(profile, dict) or not profile:
        raise ValueError('Supply the new repository profile explicitly')
    required = {'python_root', 'python_requirements', 'javascript_root'}
    if not required.issubset(profile):
        raise ValueError('Profile requires python_root, python_requirements and javascript_root')
    from scripts.code_analysis.hosted import safe_file
    if any(not isinstance(profile[key], str) or not safe_file(profile[key]) for key in required):
        raise ValueError('Profile roots/manifests must be safe repository-relative paths')
    result = {**template, 'source_repository': source, 'analysis_repository': analysis,
              'publishing_repository': publishing, 'preferred_branch': branch, 'profile': profile,
              'scanner_extensions': [], 'launch_endpoint': None}
    registry(result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', required=True)
    p.add_argument('--analysis-host', required=True)
    p.add_argument('--publishing-repository', required=True)
    p.add_argument('--preferred-branch', required=True)
    p.add_argument('--profile', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    config = configure(load(Path('config/code-analysis/service.json')), a.source, a.analysis_host,
                       a.publishing_repository, a.preferred_branch, load(a.profile))
    # Never replace an existing instance accidentally.
    with a.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(config, indent=2) + '\n')
    print('Created configuration. Review scanner applicability, vendor setup and profile paths, then generate workflows.')


if __name__ == '__main__':
    main()
