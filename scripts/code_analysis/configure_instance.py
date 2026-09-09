"""Create another repository's service configuration without changing the current instance."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

from scripts.code_analysis.extensions import registry
from scripts.code_analysis.hosted import REPOSITORY, load


def configure(template: dict, source: str, analysis: str, publishing: str, branch: str, profile: dict) -> dict:
    if not all(REPOSITORY.fullmatch(value) for value in (source, analysis, publishing)) or not branch.strip():
        raise ValueError('Repository identifiers must be owner/repo; preferred branch is required')
    if len({source.lower(), analysis.lower(), publishing.lower()}) != 3:
        raise ValueError('Source, analysis host and publishing repository must be separate')
    if not isinstance(profile, dict) or not profile:
        raise ValueError('Supply the new repository profile explicitly')
    required = set() if profile.get('mode') == 'portable' else {'python_root', 'python_requirements', 'javascript_root'}
    if profile.get('mode', 'legacy') not in {'portable', 'legacy'}:
        raise ValueError('Unknown repository profile mode')
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


def bundle(config: dict, destination: Path, endpoint: str, dashboard_url: str, client_id: str, worker_name: str) -> None:
    """Write a coordinated configuration overlay, never mutate the current instance."""
    import re
    from scripts.code_analysis.generate_source_workflow import generate
    from scripts.code_analysis.hosted import write
    worker, dashboard = urlsplit(endpoint), urlsplit(dashboard_url)
    if (worker.scheme != 'https' or not worker.hostname or worker.path not in ('', '/') or worker.query or worker.fragment
            or worker.username or worker.password or dashboard.scheme != 'https' or not dashboard.hostname
            or dashboard.username or dashboard.password or dashboard.query or dashboard.fragment):
        raise ValueError('Supply an HTTPS Worker origin and dashboard URL without credentials')
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', worker_name) or not client_id.strip():
        raise ValueError('Worker name and GitHub App client ID are required')
    config = {**config, 'launch_endpoint': endpoint.rstrip('/')}
    workflow = generate(config)
    root = Path(__file__).resolve().parents[2]
    launcher = load(root / 'analysis-launcher/wrangler.jsonc')
    launcher['name'] = worker_name
    launcher['vars'] = {'SOURCE_REPOSITORY': config['source_repository'], 'ANALYSIS_REPOSITORY': config['analysis_repository'],
                        'DASHBOARD_ORIGIN': f'{dashboard.scheme}://{dashboard.netloc}', 'GITHUB_CLIENT_ID': client_id}
    destination.mkdir(parents=True, exist_ok=False)
    for repository in ('analysis', 'dashboard'):
        write(destination / repository / 'config/code-analysis/service.json', config)
    write(destination / 'launcher/wrangler.jsonc', launcher)
    target = destination / 'analysis/.github/workflows/11-source-analysis.yml'
    target.parent.mkdir(parents=True)
    target.write_text(workflow, encoding='utf-8')
    discovery = (root / '.github/workflows/10-analysis-discovery.yml').read_text(encoding='utf-8')
    (target.parent / '10-analysis-discovery.yml').write_text(discovery, encoding='utf-8')
    target = destination / 'dashboard/.github/workflows/pages.yml'
    target.parent.mkdir(parents=True)
    target.write_text((root / 'config/code-analysis/dashboard-pages.yml').read_text(), encoding='utf-8')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', required=True)
    p.add_argument('--analysis-host', required=True)
    p.add_argument('--publishing-repository', required=True)
    p.add_argument('--preferred-branch', required=True)
    p.add_argument('--profile', type=Path, required=True)
    output = p.add_mutually_exclusive_group(required=True)
    output.add_argument('--output', type=Path)
    output.add_argument('--bundle-directory', type=Path)
    p.add_argument('--launch-endpoint')
    p.add_argument('--dashboard-url')
    p.add_argument('--app-client-id')
    p.add_argument('--worker-name')
    a = p.parse_args()
    config = configure(load(Path('config/code-analysis/service.json')), a.source, a.analysis_host,
                       a.publishing_repository, a.preferred_branch, load(a.profile))
    if a.bundle_directory:
        if not all((a.launch_endpoint, a.dashboard_url, a.app_client_id, a.worker_name)):
            p.error('Bundles require --launch-endpoint, --dashboard-url, --app-client-id and --worker-name')
        bundle(config, a.bundle_directory, a.launch_endpoint, a.dashboard_url, a.app_client_id, a.worker_name)
        print('Created coordinated overlays for the analysis repository, dashboard repository and Cloudflare launcher. Install App access and credentials separately; no deployment was performed.')
        return
    # Never replace an existing instance accidentally.
    with a.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(config, indent=2) + '\n')
    print('Created configuration. Review scanner applicability, vendor setup and profile paths, then generate workflows.')


if __name__ == '__main__':
    main()
