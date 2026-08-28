# External code-analysis service implementation

This directory is the implementation boundary for the read-only developer diagnosis
service. It is not part of the Agentic SOC backend or web UI runtime.

The stable top-level Python files are intentional compatibility entry points for
GitHub Actions and the QA-VM worker. Their architectural ownership is machine-readable
in `config/code-analysis/service-layout.json`:

- **ingestion adapters** parse scanner-native SARIF, JSON, text, coverage, and approved
  AI-review evidence;
- **domain** owns canonical identity, evidence correlation, and finding invariants;
- **application** verifies exact-commit evidence and assembles publishable snapshots;
- **presentation** builds and atomically publishes the bounded read-only dashboard;
- **infrastructure adapters** pull immutable Actions artifacts and serve them externally;

`local_service.py` is the developer control plane for the same boundary. It dispatches
the trusted exact-commit orchestrator, retrieves only an accepted dashboard artifact,
and serves Issue Wall on loopback. The root `web-of-scanners.ps1` wrapper is the Windows
entry point. Neither file is part of Agentic SOC startup or shipping runtime.
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
