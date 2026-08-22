# Acknowledged Code-Analysis Coverage Gaps

> Last measured: 2026-08-22, fork run
> [32575538895](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32575538895)
> Result: 7/10 canary expectations; 202 normalized findings from eight tools

These are coverage gaps, not suppressed application findings. The canary validator
continues to fail so the gaps remain visible. None is accepted as “safe”; each needs a
better model or an additional deterministic rule before it can become covered.

| Canary concept | Observed evidence | Why the expectation remains unmet | Required next implementation |
|---|---|---|---|
| SQL injection | Bandit detects `B608`; CodeQL and Semgrep execute but do not identify the fixture as SQL injection. | The fixture calls generic `db.execute`/`conn.execute` objects without framework types that CodeQL recognizes as database sinks. The configured Semgrep packs do not model the assignment-to-generic-execute flow. | Add a narrowly scoped custom Semgrep SQL construction rule with false-positive tests, or an application-specific CodeQL query/model pack for the repository's database adapters. Keep two independent detections as the acceptance threshold. |
| Path traversal | CodeQL reports an unclosed file but no traversal; Semgrep reports the shell subprocess as command injection; Bandit has no applicable traversal result. | A bare function parameter is not a recognized HTTP/user-input source for CodeQL dataflow. The former matrix incorrectly expected Bandit B609/B604 to cover direct `open(user_path)`. | Replace/add a realistic FastAPI request-source fixture and validate CodeQL, or add a custom source/sink CodeQL model. Update the matrix only after measured evidence, not by lowering the threshold. |
| React XSS | CodeQL analyzes the TSX fixture but reports only unused functions. ESLint is not run with a React XSS rule. | `dangerouslySetInnerHTML` alone is not a proven source-to-sink flow for the selected CodeQL queries, and the web UI intentionally lacks `eslint-plugin-react`/`react/no-danger`. | Add a tracked `eslint-plugin-react` or `eslint-plugin-no-unsanitized` rule in an advisory canary config, or make the fixture carry a CodeQL-recognized untrusted source to the sink. Then normalize ESLint/CodeQL to the `xss` concept. |

## Not covered by this canary phase

The following shortlisted proposal items are separately tracked as partial or not
implemented in [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md): `tsc` normalization, Xenon
structured findings, Schemathesis normalization/validation, Atheris, CodeRabbit,
PR-Agent, CodeScene service deployment, DefectDojo integration, Snyk, and persistent
dashboard hosting. A 7/10 canary result does not claim those capabilities.
