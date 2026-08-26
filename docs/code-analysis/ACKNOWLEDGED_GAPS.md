# Historical Canary Coverage Gaps — Resolved for the Defined Fixture Set

> Last measured: 2026-08-22, fork run
> [32575538895](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32575538895)
> Result: 7/10 canary expectations; 202 normalized findings from eight tools

> **Current status:** This file preserves the diagnostic evidence from the 7/10 stage.
> It is not the current acceptance result. After project-specific detection and
> normalization improvements, fork run
> [`32938363577`](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32938363577)
> passed all **10/10 defined canary expectations** at commit `48a1db2`.

These were coverage gaps, not suppressed application findings. None was accepted as
safe. The table remains as the explanation of why the earlier run failed and what work
was required. The current validator remains fail-closed and must continue to pass as
rules and scanners change.

| Canary concept | Observed evidence | Why the expectation remains unmet | Required next implementation |
|---|---|---|---|
| SQL injection | Bandit detects `B608`; CodeQL and Semgrep execute but do not identify the fixture as SQL injection. | The fixture calls generic `db.execute`/`conn.execute` objects without framework types that CodeQL recognizes as database sinks. The configured Semgrep packs do not model the assignment-to-generic-execute flow. | Add a narrowly scoped custom Semgrep SQL construction rule with false-positive tests, or an application-specific CodeQL query/model pack for the repository's database adapters. Keep two independent detections as the acceptance threshold. |
| Path traversal | CodeQL reports an unclosed file but no traversal; Semgrep reports the shell subprocess as command injection; Bandit has no applicable traversal result. | A bare function parameter is not a recognized HTTP/user-input source for CodeQL dataflow. The former matrix incorrectly expected Bandit B609/B604 to cover direct `open(user_path)`. | Replace/add a realistic FastAPI request-source fixture and validate CodeQL, or add a custom source/sink CodeQL model. Update the matrix only after measured evidence, not by lowering the threshold. |
| React XSS | CodeQL analyzes the TSX fixture but reports only unused functions. ESLint is not run with a React XSS rule. | `dangerouslySetInnerHTML` alone is not a proven source-to-sink flow for the selected CodeQL queries, and the web UI intentionally lacks `eslint-plugin-react`/`react/no-danger`. | Add a tracked `eslint-plugin-react` or `eslint-plugin-no-unsanitized` rule in an advisory canary config, or make the fixture carry a CodeQL-recognized untrusted source to the sink. Then normalize ESLint/CodeQL to the `xss` concept. |

## Not covered by this canary phase

The 10/10 result applies only to the ten checked-in expectations. It does not validate
every scanner or establish a vulnerability-detection percentage. TypeScript and Xenon
structured ingestion, Snyk CI, and Schemathesis dynamic ingestion are tracked separately
in [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md). Atheris, CodeRabbit execution, PR-Agent,
CodeScene/SonarQube services, DefectDojo, and QA-VM deployment remain partial or deferred
as described in [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).
