"""Generate the isolated exact-source workflow from existing scanner definitions.

Legacy push/PR workflows remain compatible. This generated workflow has no SARIF
publication privileges, persisted checkout credentials, or source-inherited tooling.
"""
from pathlib import Path
import copy
import json
import re
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHECKOUT = 'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803'
UPLOAD = 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'
PYTHON = 'actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1'


def generate(config=None):
    config = config or json.loads((ROOT / 'config/code-analysis/service.json').read_text())
    profile = config['profile']
    inputs = {k: {'required': True, 'type': 'string'} for k in ('target', 'tooling_sha', 'request_id')}
    document = {'name': 'Exact Source Analysis', 'run-name': 'Source analysis ${{ inputs.request_id }}',
                'on': {'workflow_dispatch': {'inputs': inputs}}, 'permissions': {'contents': 'read'},
                'concurrency': {'group': 'source-${{ fromJSON(inputs.target).id }}', 'cancel-in-progress': True}, 'jobs': {}}
    jobs = document['jobs']
    jobs['identity'] = {'runs-on': 'ubuntu-latest', 'timeout-minutes': 5,
        'outputs': {'jobs': '${{ steps.identity.outputs.jobs }}', 'languages': '${{ steps.identity.outputs.languages }}'},
        'steps': [{'uses': CHECKOUT, 'with': {'persist-credentials': False}},
                  {'uses': CHECKOUT, 'with': {'repository': '${{ fromJSON(inputs.target).source_repository }}',
                    'ref': '${{ fromJSON(inputs.target).head_sha }}', 'path': '.source', 'persist-credentials': False}},
                  {'name': 'Validate trusted tooling and selected target', 'id': 'identity',
                   'env': {'TARGET_JSON': '${{ inputs.target }}', 'TOOLING_SHA': '${{ inputs.tooling_sha }}'},
                   'run': 'python -m scripts.code_analysis.source_identity'}]}
    for number in (1, 2, 3, 4, 7):
        path = next((ROOT / '.github/workflows').glob(f'0{number}-*.yml'))
        old = yaml.safe_load(path.read_text(encoding='utf-8'))
        for name, original in old['jobs'].items():
            if profile.get('mode') == 'portable':
                from scripts.code_analysis.applicability import PORTABLE_JOBS
                if name not in PORTABLE_JOBS:
                    continue
            if name == 'dependency-review':
                # GitHub's host-PR gate is not an upstream-head scanner.
                continue
            job = copy.deepcopy(original)
            job['needs'] = ['identity']
            job['permissions'] = {'contents': 'read'}
            job.pop('if', None)
            job['if'] = "${{ contains(fromJSON(needs.identity.outputs.jobs), '" + name + "') }}"
            if name == 'codeql':
                job['strategy']['matrix']['language'] = '${{ fromJSON(needs.identity.outputs.languages) }}'
            job.setdefault('env', {})['SOURCE_REPOSITORY'] = '${{ fromJSON(inputs.target).source_repository }}'
            if name == 'atheris-state-machine':
                job['env'].update(ANALYSIS_BACKEND_ROOT='${{ github.workspace }}/' + profile['python_root'],
                                  ANALYSIS_SOURCE_SHA='${{ fromJSON(inputs.target).head_sha }}')
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
                if name == 'snyk' and step.get('name') == 'Record configured scan status':
                    step['run'] = step['run'].replace('jq -n', 'if [[ "$SCA_OUTCOME" != success || "$CODE_OUTCOME" != success ]] && grep -q "monthly limit" snyk-*.log; then\n  reason="Snyk execution incomplete; a quota warning was also emitted. Inspect the failing manifest or surface before attributing the failure to quota."\nfi\njq -n')
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
            if name == 'schemathesis-fuzz':
                steps = [s for s in steps if s.get('name') != 'Start FastAPI Backend in Background']
                for s in steps:
                    if s.get('name') == 'Install dependencies & Schemathesis':
                        s['run'] = 'PYTHONPATH="$GITHUB_WORKSPACE/.analysis-tooling" python -m scripts.code_analysis.run_profile python-install --source "$GITHUB_WORKSPACE"\npython -m pip install schemathesis==3.39.16 httpx==0.27.2'
                    elif s.get('name') == 'Run API Fuzzing (Schemathesis)':
                        s['run'] = 'PYTHONPATH="$GITHUB_WORKSPACE/.analysis-tooling" python -m scripts.code_analysis.run_profile api-fuzz --source "$GITHUB_WORKSPACE"'
                    elif s.get('name') == 'Upload Fuzzing Report':
                        s['with']['path'] = 'fuzzing-results.xml\nschema.json\nschemathesis-status.json'
            if name == 'typescript-quality':
                steps.extend([
                    {'name': 'Run repository JavaScript test profile', 'if': 'always()',
                     'run': 'PYTHONPATH="$GITHUB_WORKSPACE/.analysis-tooling" python -m scripts.code_analysis.run_profile javascript-test --source "$GITHUB_WORKSPACE"'},
                    {'uses': UPLOAD, 'if': 'always()', 'with': {'name': 'typescript-tests', 'path': 'typescript-test-status.json', 'retention-days': 7}}])
            if name == 'sonarqube-cloud':
                probe = next(s for s in steps if s.get('name') == 'Probe Sonar credentials without exposing secrets')
                steps.remove(probe)
                position = next(i for i, s in enumerate(steps) if s.get('id') == 'sonar-identity')
                probe.setdefault('env', {})['SCAN_BRANCH'] = '${{ steps.sonar-identity.outputs.sonar_branch }}'
                probe['id'] = 'sonar-access'
                probe['run'] += '\npython -c \'import json; p=json.load(open("sonar-access-probe.json")); print("native_export_ready="+str(p["credentials"].get("issue_api",{}).get("project_issues_http_status")==200 and p["credentials"].get("issue_api",{}).get("branch_issues_http_status") not in (401,403)).lower())\' >> "$GITHUB_OUTPUT"'
                probe['run'] += '\npython -c \'import json; p=json.load(open("sonar-access-probe.json")); print("access_failure="+p["credentials"].get("issue_api",{}).get("access_failure",""))\' >> "$GITHUB_OUTPUT"'
                steps.insert(position + 1, probe)
                for s in steps:
                    if s.get('id') in {'sonar-native', 'sonar-manual'}:
                        s['if'] += " && steps.sonar-access.outputs.native_export_ready == 'true'"
                    if s.get('name') == 'Record configured scan status':
                        s.setdefault('env', {})['EXPORT_READY'] = '${{ steps.sonar-access.outputs.native_export_ready }}'
                        s['env']['ACCESS_FAILURE'] = '${{ steps.sonar-access.outputs.access_failure }}'
                        s['run'] = s['run'].replace('jq -n', 'if [[ "$EXPORT_READY" != true ]]; then\n  reason="Sonar native issue API is unavailable to the configured credential; analysis awaits export access"\nfi\njq -n')
                        s['run'] = s['run'].replace('jq -n', 'if [[ "$ACCESS_FAILURE" == branch_entitlement ]]; then\n  reason="Sonar organization denies non-main-branch data access; enable branch entitlement. Token validity and Browse permission do not resolve this restriction."\nfi\njq -n')
            if name == 'openssf-scorecard':
                pin = json.loads((ROOT / '.ci/scorecard.json').read_text())
                version, digest = pin['version'], pin['sha256']
                if not re.fullmatch(r'\d+\.\d+\.\d+', version) or not re.fullmatch('[0-9a-f]{64}', digest) or pin['checksum_version'] != version:
                    raise ValueError('Scorecard update requires a matching verified release checksum')
                steps = [{'uses': CHECKOUT, 'with': {'ref': '${{ inputs.tooling_sha }}', 'persist-credentials': False}},
                    {'name': f'Install verified Scorecard {version}', 'run':
                    f'curl --fail --location --retry 3 https://github.com/ossf/scorecard/releases/download/v{version}/scorecard_{version}_linux_amd64.tar.gz -o scorecard.tar.gz\n'
                    f'echo "{digest}  scorecard.tar.gz" | sha256sum --check\n'
                    'tar -xzf scorecard.tar.gz scorecard\n'},
                    {'name': 'Scan external repository at selected commit', 'id': 'scorecard', 'continue-on-error': True,
                     'env': {'GITHUB_AUTH_TOKEN': '${{ github.token }}', 'ENABLE_SARIF': 'true', 'SOURCE_SHA': '${{ fromJSON(inputs.target).head_sha }}'},
                     'run': './scorecard --repo="github.com/$SOURCE_REPOSITORY" --commit="$SOURCE_SHA" --format=json --show-details > scorecard-native.json\npython -I scripts/code_analysis/scorecard_report.py'},
                    {'name': 'Retain Scorecard execution status', 'if': 'always()',
                     'env': {'OUTCOME': '${{ steps.scorecard.outcome }}'},
                     'run': 'if [[ "$OUTCOME" != success ]]; then\n  jq -n \'{scanner_family:"OpenSSF Scorecard",status:"OPERATIONAL_FAILURE",reason:"Native Scorecard execution or source identity validation failed"}\' > scorecard-status.json\nfi'},
                    {'uses': UPLOAD, 'if': 'always()', 'with': {'name': 'openssf-scorecard', 'path': 'openssf-scorecard.sarif\nscorecard-status.json\nscorecard-native.json', 'retention-days': 7}}]
            isolated = []
            for step in steps:
                if step.get('uses', '').startswith('actions/checkout@') and step.get('with', {}).get('path') == '.analysis-tooling':
                    isolated.append(step)
                    isolated.append({'name': 'Keep trusted tooling outside the source scan tree',
                                     'run': 'mv "$GITHUB_WORKSPACE/.analysis-tooling" "$RUNNER_TEMP/analysis-tooling"'})
                    continue
                if step.get('uses', '').startswith('github/codeql-action/init@'):
                    isolated.append({'name': 'Stage trusted CodeQL policy in Git metadata',
                                     'run': 'mkdir -p "$GITHUB_WORKSPACE/.git/code-analysis"\ncp "$RUNNER_TEMP/analysis-tooling/.github/codeql/codeql-config.yml" "$GITHUB_WORKSPACE/.git/code-analysis/codeql-config.yml"'})
                    step['with']['config-file'] = '.git/code-analysis/codeql-config.yml'
                if 'run' in step:
                    step['run'] = step['run'].replace('$GITHUB_WORKSPACE/.analysis-tooling', '$RUNNER_TEMP/analysis-tooling').replace('../.analysis-tooling', '$RUNNER_TEMP/analysis-tooling').replace('.analysis-tooling', '$RUNNER_TEMP/analysis-tooling')
                if 'with' in step:
                    step['with'] = {k: v.replace('.analysis-tooling', '${{ runner.temp }}/analysis-tooling') if isinstance(v, str) else v for k, v in step['with'].items()}
                isolated.append(step)
            if profile.get('mode') == 'portable' and name == 'semgrep':
                for step in isolated:
                    if 'run' in step and 'backend/ webui/src/' in step['run']:
                        step['run'] = 'semgrep --config=p/owasp-top-ten --config=p/secrets --json --output=semgrep-results.json .'
            job['steps'] = isolated
            if name == 'snyk':
                job['steps'].append({'name': 'Upload isolated resolver diagnostics', 'if': 'always()',
                                     'uses': UPLOAD, 'with': {'name': 'snyk-resolver-diagnostics',
                                     'path': '${{ runner.temp }}/snyk-resolver-error.json',
                                     'if-no-files-found': 'ignore', 'retention-days': 7}})
            jobs[f'scanner-{number}-{name}'] = job
    from scripts.code_analysis.extensions import registry
    for extension in registry(config):
        channel = extension['channel']
        steps = [{'uses': CHECKOUT, 'with': {'ref': '${{ inputs.tooling_sha }}', 'persist-credentials': False}},
                 {'uses': PYTHON, 'with': {'python-version': '3.11'}}]
        if extension['mode'] == 'source':
            steps.append({'uses': CHECKOUT, 'with': {'repository': '${{ fromJSON(inputs.target).source_repository }}',
                          'ref': '${{ fromJSON(inputs.target).head_sha }}', 'path': '.source', 'persist-credentials': False}})
        environment = {'TARGET_JSON': '${{ inputs.target }}', 'TOOLING_SHA': '${{ inputs.tooling_sha }}'}
        environment.update({key: '${{ secrets.' + value + ' }}' for key, value in extension.get('secrets', {}).items()})
        steps += [{'name': 'Run trusted scanner adapter', 'env': environment,
                   'run': 'python -m scripts.code_analysis.extension_runner ' + channel},
                  {'uses': UPLOAD, 'if': 'always()', 'with': {'name': channel,
                   'path': '.extension-output/' + channel + '.channel-evidence', 'retention-days': 7,
                   'if-no-files-found': 'error'}}]
        jobs[channel] = {'name': extension['name'], 'needs': ['identity'],
                         'if': "${{ contains(fromJSON(needs.identity.outputs.jobs), '" + channel + "') }}",
                         'runs-on': 'ubuntu-latest', 'timeout-minutes': extension.get('timeout_minutes', 15) + 5,
                         'permissions': {'contents': 'read'}, 'steps': steps}
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


def diagnostics():
    document = yaml.safe_load(generate())
    document['name'] = 'Scanner access diagnostics'
    document['run-name'] = 'Scanner diagnostics ${{ inputs.request_id }}'
    document['concurrency']['group'] = 'scanner-diagnostics'
    document['jobs'] = {key: value for key, value in document['jobs'].items()
                        if key in {'identity', 'scanner-3-snyk', 'scanner-1-sonarqube-cloud'}}
    return '# Generated scanner diagnostics; never publishes a target report.\n' + yaml.safe_dump(document, sort_keys=False, width=110)


if __name__ == '__main__':
    (ROOT / '.github/workflows/11-source-analysis.yml').write_text(generate(), encoding='utf-8')
    (ROOT / '.github/workflows/12-scanner-diagnostics.yml').write_text(diagnostics(), encoding='utf-8')
