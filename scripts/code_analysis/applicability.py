"""Trusted scanner selection from explicit configuration and the checked-out tree."""
from pathlib import Path

# A shared producer must be enabled or deferred as a unit: partial disabling must
# never silently discard observations produced by another channel in that job.
GROUPS = {
    'sonarqube-cloud': ['sonarqube-cloud'], 'python-ruff': ['ruff'],
    'python-bandit': ['bandit'], 'python-types': ['pyright'],
    'typescript-quality': ['eslint', 'typescript'], 'codeql': ['codeql'],
    'semgrep': ['semgrep'], 'snyk': ['snyk'], 'osv-scanner': ['osv'],
    'gitleaks': ['gitleaks'], 'trivy': ['trivy'], 'hadolint': ['hadolint'],
    'checkov': ['checkov'],
    'shipping-image-security': ['shipping-image-cves', 'sbom-license-provenance'],
    'workflow-security-posture': ['github-secret-protection-posture', 'github-actions-security'],
    'openssf-scorecard': ['openssf-scorecard'], 'complexity': ['radon', 'xenon'],
    'dead-code': ['vulture'], 'test-coverage': ['coverage'],
    'schemathesis-fuzz': ['schemathesis'], 'atheris-state-machine': ['atheris'],
    'coderabbit': ['coderabbit-ai-advisory'],
}
PYTHON_JOBS = {'python-ruff', 'python-bandit', 'python-types', 'complexity',
               'dead-code', 'test-coverage', 'schemathesis-fuzz', 'atheris-state-machine'}


def selection(config: dict, source: Path) -> tuple[list[str], dict, list[str]]:
    known = {channel for channels in GROUPS.values() for channel in channels}
    enabled = set(config.get('enabled_scanners', known))
    deferred = config.get('deferred_channels', {})
    if (enabled & set(deferred) or enabled | set(deferred) != known
            or any(not isinstance(reason, str) or not reason.strip() for reason in deferred.values())):
        raise ValueError('Every known scanner must be enabled or explicitly deferred with a reason')
    profile = config['profile']
    def present(relative: str) -> bool:
        path = (source / relative).resolve()
        if not path.is_relative_to(source.resolve()):
            raise ValueError('Profile path escapes selected source')
        return path.exists()
    python = present(profile['python_root'])
    javascript = present(profile['javascript_root'])
    languages = (['python'] if python else []) + (['javascript-typescript'] if javascript else [])
    absent = {}
    for job in PYTHON_JOBS:
        if not python:
            absent[job] = 'Selected source has no configured Python project: ' + profile['python_root']
    if not javascript:
        absent['typescript-quality'] = 'Selected source has no configured JavaScript project: ' + profile['javascript_root']
    if not languages:
        absent['codeql'] = 'Selected source has neither configured language project'
        absent['sonarqube-cloud'] = 'Selected source has neither configured language project'
        absent['snyk'] = 'Selected source has neither configured language project'
    if not present(profile['python_root'] + '/Dockerfile') or not present(profile['javascript_root'] + '/Dockerfile'):
        absent['shipping-image-security'] = 'Selected source lacks the configured pair of shipping Dockerfiles'
    if not present(profile['python_root'] + '/Dockerfile') and not present(profile['javascript_root'] + '/Dockerfile'):
        absent['hadolint'] = 'Selected source has no configured shipping Dockerfiles to lint'
    manifests = [profile['python_requirements'], profile.get('python_development_requirements'),
                 profile['javascript_root'] + '/package-lock.json']
    if not any(present(path) for path in manifests if path):
        absent['osv-scanner'] = 'Selected source has none of the configured dependency manifests'
    jobs, excluded = [], {}
    for job, channels in GROUPS.items():
        active = enabled.intersection(channels)
        if active and len(active) != len(channels):
            raise ValueError('Channels sharing producer ' + job + ' must be enabled or deferred together')
        if active and job not in absent:
            jobs.append(job)
        else:
            for channel in channels:
                excluded[channel] = {
                    'status': 'NOT_APPLICABLE' if active else 'DEFERRED',
                    'reason': absent[job] if active else deferred[channel],
                }
    workflow_directory = source / '.github/workflows'
    if ('github-actions-security' in enabled and
            (not present('.github/workflows') or not any(
                p.is_file() and p.suffix in {'.yml', '.yaml'} for p in workflow_directory.iterdir()))):
        # This producer also reads repository posture, which remains applicable.
        excluded['github-actions-security'] = {
            'status': 'NOT_APPLICABLE', 'reason': 'Selected source contains no GitHub Actions workflow definitions'}
    from scripts.code_analysis.extensions import registry
    for extension in registry(config):
        if extension.get('deferred_reason'):
            excluded[extension['channel']] = {'status': 'DEFERRED', 'reason': extension['deferred_reason']}
        else:
            jobs.append(extension['channel'])
    return jobs, excluded, languages


def apply(snapshot: dict, exclusions: dict) -> None:
    for channel in snapshot['analysis_channels']:
        if channel['channel'] in exclusions:
            if channel['observation_count']:
                raise ValueError('Excluded scanner unexpectedly produced observations')
            channel.update(exclusions[channel['channel']], findings=None)
