# External code-analysis service implementation

This directory is the implementation boundary for the read-only developer diagnosis
service. It is not part of the Agentic SOC backend or web UI runtime.

The stable top-level Python files are intentional compatibility entry points for
GitHub Actions. Their architectural ownership is machine-readable
in `config/code-analysis/service-layout.json`:

- **ingestion adapters** parse scanner-native SARIF, JSON, text, coverage, and approved
  AI-review evidence;
- **domain** owns canonical identity, evidence correlation, and finding invariants;
- **application** verifies exact-commit evidence and assembles publishable snapshots;
- **presentation** builds the bounded read-only dashboard inside GitHub Actions;
- **infrastructure adapters** publish immutable GitHub Actions artifacts;
- **verification** enforces workflow policy, canaries, scale, and regressions.

New code must respect dependency direction:

```text
scanner/GitHub adapters -> application -> domain
presentation            -> application snapshot contract
infrastructure          -> application/publication ports
```

The domain must never import GitHub, nginx, Docker, the Agentic SOC application, or an
AI provider. AI observations enter only through an adapter and remain `AI_ADVISORY`.
Do not move compatibility entry points without changing and validating every workflow,
systemd unit, document, and regression contract in the same reviewed change.
