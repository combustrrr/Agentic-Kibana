"""Generate the isolated exact-source workflow from existing scanner definitions.

Legacy push/PR workflows remain compatible. This generated workflow has no SARIF
publication privileges, persisted checkout credentials, or source-inherited tooling.
"""
from pathlib import Path
import copy
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHECKOUT = 'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803'
UPLOAD = 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'
PYTHON = 'actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1'


def generate():
    inputs = {k: {'required': True, 'type': 'string'} for k in ('target', 'tooling_sha', 'request_id')}
    document = {'name': 'Exact Source Analysis', 'run-name': 'Source analysis ${{ inputs.request_id }}',
                'on': {'workflow_dispatch': {'inputs': inputs}}, 'permissions': {'contents': 'read'},
                'concurrency': {'group': 'source-${{ fromJSON(inputs.target).id }}', 'cancel-in-progress': True}, 'jobs': {}}
    jobs = document['jobs']
    jobs['identity'] = {'runs-on': 'ubuntu-latest', 'timeout-minutes': 5,
        'steps': [{'uses': CHECKOUT, 'with': {'persist-credentials': False}},
                  {'name': 'Validate trusted tooling and selected target',
                   'env': {'TARGET_JSON': '${{ inputs.target }}', 'TOOLING_SHA': '${{ inputs.tooling_sha }}'},
                   'run': 'python -m scripts.code_analysis.source_identity'}]}
    for number in (1, 2, 3, 4, 7):
        path = next((ROOT / '.github/workflows').glob(f'0{number}-*.yml'))
        old = yaml.safe_load(path.read_text(encoding='utf-8'))
        for name, original in old['jobs'].items():
            if name == 'dependency-review':
                # GitHub's host-PR gate is not an upstream-head scanner.
                continue
            job = copy.deepcopy(original)
            job['needs'] = ['identity']
            job['permissions'] = {'contents': 'read'}
            job.pop('if', None)
            job.setdefault('env', {})['SOURCE_REPOSITORY'] = '${{ fromJSON(inputs.target).source_repository }}'
            steps = []
            for step in job['steps']:
                uses = step.get('uses', '')
                if 'upload-sarif@' in uses or step.get('name') in {'Parse Results for Aggregation', 'Upload Normalized Findings'}:
                    continue
                if uses.startswith('actions/checkout@'):
                    options = step.setdefault('with', {})
                    options['persist-credentials'] = False
                    if options.get('path') == '.analysis-tooling':
                        options.update(repository='${{ github.repository }}', ref='${{ inputs.tooling_sha }}')
                        # Harnesses and service tooling always come from trusted revision.
                        options.pop('sparse-checkout', None)
                        options.pop('sparse-checkout-cone-mode', None)
                    else:
                        options.update(repository='${{ fromJSON(inputs.target).source_repository }}',
                                       ref='${{ fromJSON(inputs.target).head_sha }}')
                if uses.startswith('actions/upload-artifact@'):
                    step.setdefault('with', {})['retention-days'] = 7
                if 'github/codeql-action/analyze@' in uses:
                    step.setdefault('with', {})['upload'] = False
                # Gitleaks scanner-only operation: never runs the public PR commenting action.
                if uses.startswith('gitleaks/gitleaks-action@'):
                    step = {'name': 'Run pinned Gitleaks without PR mutation', 'run':
                        'docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:v8.24.2 detect --source=/repo --report-format=sarif --report-path=/repo/gitleaks-results.sarif --redact --exit-code=0'}
                if step.get('name') == 'Validate and normalize Gitleaks output':
                    step = {'name': 'Validate redacted Gitleaks output', 'run': 'jq -e \'(.runs | type) == "array"\' gitleaks-results.sarif > /dev/null'}
                if name == 'snyk':
                    if step.get('name') in {'Resolve Python dependency manifests for Snyk SCA'}:
                        step['run'] = 'python -I .analysis-tooling/scripts/code_analysis/snyk_metadata.py --source "$GITHUB_WORKSPACE" --destination "$RUNNER_TEMP/snyk-metadata"'
                    if step.get('name') in {'Scan open-source dependencies', 'Scan source code'}:
                        step.setdefault('env', {})['SNYK_TOKEN'] = '${{ secrets.SNYK_TOKEN }}'
                    if step.get('name') == 'Scan open-source dependencies':
                        step['run'] = 'set -o pipefail\npython -I .analysis-tooling/scripts/code_analysis/snyk_scan.py 2>&1 | tee snyk-open-source.log'
                text = yaml.safe_dump(step, sort_keys=False)
                text = text.replace('inputs.scan_sha || github.event.pull_request.head.sha || github.sha', 'fromJSON(inputs.target).head_sha')
                text = text.replace('inputs.scan_sha', 'fromJSON(inputs.target).head_sha')
                text = text.replace('inputs.scan_branch', 'fromJSON(inputs.target).branch')
                text = text.replace('inputs.ensure_sonar_browse', 'false')
                text = text.replace('env.SNYK_TOKEN != \'\'', "env.SNYK_CONFIGURED == 'true'")
                text = text.replace('env.SNYK_TOKEN == \'\'', "env.SNYK_CONFIGURED != 'true'")
                text = text.replace('--command=.snyk-venv/bin/python', '--command="$RUNNER_TEMP/snyk-metadata/inspect-python"')
                text = text.replace('repos/${GITHUB_REPOSITORY}', 'repos/${SOURCE_REPOSITORY}')
                step = yaml.safe_load(text)
                if step.get('name') == 'Ensure Browse for the verified Sonar API user':
                    step['if'] = "env.SONAR_API_TOKEN != ''"
                    step['continue-on-error'] = True
                if name == 'atheris-state-machine' and 'run' in step:
                    step['run'] = step['run'].replace('../tests/security_canary/', '../.analysis-tooling/tests/security_canary/')
                steps.append(step)
            if name == 'snyk':
                job['env'].pop('SNYK_TOKEN', None)
                job['env']['SNYK_CONFIGURED'] = "${{ secrets.SNYK_TOKEN != '' }}"
                steps.insert(1, {'uses': CHECKOUT, 'with': {'repository': '${{ github.repository }}',
                             'ref': '${{ inputs.tooling_sha }}', 'path': '.analysis-tooling', 'persist-credentials': False}})
            if name in {'test-coverage', 'typescript-quality'}:
                # The existing scanner configuration still supplies language-specific
                # lint rules, while project install/test commands come from the profile.
                has_tooling = any(s.get('with', {}).get('path') == '.analysis-tooling' for s in steps)
                if not has_tooling:
                    steps.insert(1, {'uses': CHECKOUT, 'with': {'repository': '${{ github.repository }}',
                                 'ref': '${{ inputs.tooling_sha }}', 'path': '.analysis-tooling', 'persist-credentials': False}})
                for s in steps:
                    task = {'Install dependencies': 'python-install', 'Run pytest with coverage': 'python-test',
                            'Install locked dependencies': 'javascript-install'}.get(s.get('name'))
                    if task:
                        s['run'] = f'PYTHONPATH="$GITHUB_WORKSPACE/.analysis-tooling" python -m scripts.code_analysis.run_profile {task} --source "$GITHUB_WORKSPACE"'
            if number == 7:
                steps.insert(1, {'uses': CHECKOUT, 'with': {'repository': '${{ github.repository }}',
                             'ref': '${{ inputs.tooling_sha }}', 'path': '.analysis-tooling', 'persist-credentials': False}})
            if name == 'openssf-scorecard':
                steps = [{'name': 'Install verified Scorecard 5.5.0', 'run':
                    'curl --fail --location --retry 3 https://github.com/ossf/scorecard/releases/download/v5.5.0/scorecard_5.5.0_linux_amd64.tar.gz -o scorecard.tar.gz\n'
                    'echo "83b90a05c1540ef1390db1cd5711e5fd04be9c1d8537fb84d39d02092d6a8dff  scorecard.tar.gz" | sha256sum --check\n'
                    'tar -xzf scorecard.tar.gz scorecard\n'},
                    {'name': 'Scan external repository at selected commit', 'id': 'scorecard', 'continue-on-error': True,
                     'env': {'GITHUB_AUTH_TOKEN': '${{ github.token }}', 'ENABLE_SARIF': 'true', 'SOURCE_SHA': '${{ fromJSON(inputs.target).head_sha }}'},
                     'run': './scorecard --repo="github.com/$SOURCE_REPOSITORY" --commit="$SOURCE_SHA" --format=sarif --show-details > openssf-scorecard.sarif'},
                    {'name': 'Retain Scorecard execution status', 'if': 'always()',
                     'env': {'OUTCOME': '${{ steps.scorecard.outcome }}'},
                     'run': 'status=OPERATIONAL_FAILURE\nif [[ "$OUTCOME" == success ]]; then status=COMPLETED; fi\njq -n --arg status "$status" \'{scanner_family:"OpenSSF Scorecard",status:$status,reason:"Repository checks against the selected source commit; unavailable individual checks remain in scanner evidence"}\' > scorecard-status.json'},
                    {'uses': UPLOAD, 'if': 'always()', 'with': {'name': 'openssf-scorecard', 'path': 'openssf-scorecard.sarif\nscorecard-status.json', 'retention-days': 7}}]
            job['steps'] = steps
            jobs[f'scanner-{number}-{name}'] = job
    jobs['report'] = {'needs': list(jobs), 'if': "${{ always() && needs.identity.result == 'success' }}",
        'runs-on': 'ubuntu-latest', 'timeout-minutes': 30, 'permissions': {'contents': 'read', 'actions': 'read'},
        'steps': [{'uses': CHECKOUT, 'with': {'ref': '${{ inputs.tooling_sha }}', 'persist-credentials': False}},
            {'uses': PYTHON, 'with': {'python-version': '3.11'}},
            {'name': 'Install trusted reporting dependencies', 'run': 'python -m pip install click==8.2.1 ruff==0.12.5'},
            {'uses': CHECKOUT, 'with': {'repository': '${{ fromJSON(inputs.target).source_repository }}',
                'ref': '${{ fromJSON(inputs.target).head_sha }}', 'path': '.source', 'persist-credentials': False}},
            {'name': 'Collect exact producer artifacts and assemble report',
             'env': {'GH_TOKEN': '${{ github.token }}', 'TARGET_JSON': '${{ inputs.target }}', 'TOOLING_SHA': '${{ inputs.tooling_sha }}'},
             'run': 'python -m scripts.code_analysis.source_identity --assemble'},
            {'uses': UPLOAD, 'with': {'name': 'hosted-report-${{ github.run_id }}-${{ github.run_attempt }}',
                'path': '.hosted/report/', 'if-no-files-found': 'error', 'retention-days': 7}}]}
    return '# Generated by scripts/code_analysis/generate_source_workflow.py; do not edit by hand.\n' + yaml.safe_dump(document, sort_keys=False, width=110)


if __name__ == '__main__':
    (ROOT / '.github/workflows/11-source-analysis.yml').write_text(generate(), encoding='utf-8')
