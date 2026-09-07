"""Project native Scorecard checks into findings without inventing an overall score."""
import json
import os
from pathlib import Path


def convert(data: dict, repository: str, sha: str) -> tuple[dict, dict]:
    if data.get('repo', {}).get('name', '').removeprefix('github.com/').lower() != repository.lower() or data['repo'].get('commit') != sha:
        raise ValueError('Scorecard did not analyze the selected source identity')
    checks = data.get('checks')
    if not isinstance(checks, list) or not checks:
        raise ValueError('Scorecard returned no check evidence')
    results, unavailable, evidence = [], [], []
    for check in checks:
        score, name = check.get('score'), check['name']
        evidence.append({'name': name, 'score': score, 'reason': check.get('reason', ''), 'details': check.get('details', [])})
        if type(score) not in (int, float) or score < 0:
            unavailable.append(name)
        elif score < 10:
            results.append({'ruleId': name, 'level': 'note', 'message': {'text':
                f"Scorecard {name}: {score}/10. {check.get('reason', '')}"}})
    sarif = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'OpenSSF Scorecard'}}, 'results': results}]}
    status = {'scanner_family': 'OpenSSF Scorecard', 'status': 'CONFIGURED_PARTIAL' if unavailable else 'COMPLETED',
              'reason': 'Unavailable repository checks: ' + ', '.join(unavailable) if unavailable else 'All native repository checks returned usable evidence',
              'source_repository': repository, 'source_sha': sha, 'checks': evidence}
    return sarif, status


def main():
    sarif, status = convert(json.loads(Path('scorecard-native.json').read_text()), os.environ['SOURCE_REPOSITORY'], os.environ['SOURCE_SHA'])
    Path('openssf-scorecard.sarif').write_text(json.dumps(sarif), encoding='utf-8')
    Path('scorecard-status.json').write_text(json.dumps(status), encoding='utf-8')


if __name__ == '__main__':
    main()
