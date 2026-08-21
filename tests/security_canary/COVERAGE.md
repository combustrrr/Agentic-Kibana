# Canary Coverage — Expected Detections

> **Purpose**: This document defines what each canary file contains and which
> tools MUST detect it. It is the source of truth for the canary validation
> CI gate (workflow `06-canary-validation.yml`).

## Detection Matrix

| Canary File | Vulnerability Type | Concept | Expected Tools |
|---|---|---|---|
| `python/sql_injection.py` | SQL injection (f-string, concat, %) | `sql-injection` | CodeQL, Semgrep, Bandit |
| `python/hardcoded_secret.py` | Hardcoded API keys, passwords, JWT secrets | `hardcoded-secret` | Bandit, Gitleaks, Semgrep |
| `python/jwt_none_algorithm.py` | JWT "none" algorithm bypass | `jwt-none-alg` | Semgrep (custom rule) |
| `python/eval_exec.py` | eval(), exec(), shell=True with input | `code-injection` | Bandit, Semgrep |
| `python/pickle_deserialization.py` | pickle.loads(), yaml.load() | `unsafe-deserialization` | Bandit, Semgrep |
| `python/path_traversal.py` | Unsanitized file paths | `path-traversal` | CodeQL, Semgrep, Bandit |
| `python/prompt_injection.py` | LLM output in eval()/subprocess | `code-injection` | Semgrep (custom rule) |
| `typescript/xss_dangerously.tsx` | dangerouslySetInnerHTML | `xss` | ESLint, CodeQL |
| `Dockerfile.insecure` | Running as root, no tag | `dockerfile-root` | Hadolint, Checkov |
| `requirements-vulnerable.txt` | Known-vulnerable packages | `dependency-vuln` | OSV-Scanner, Snyk |

## Validation

Run `python scripts/code_analysis/validate_canary.py --findings-dir <normalized_dir>`
to verify all expected detections are met. The script exits with code 1
(failing CI) if any expected vulnerability is NOT detected by at least
`min_detections` of the `required_tools`.
