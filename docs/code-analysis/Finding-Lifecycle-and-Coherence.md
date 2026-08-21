# Finding Lifecycle & Tool Coherence Architecture
## Kavach-AgenticSOC Code Intelligence System

> **Version:** 1.1 — Addressing Core Engineering Challenges

---

## Part 1 — The Duplicate Issue Problem

### 1.1 Why Naive Issue Creation Fails

Without careful design, running multiple analysis tools 3x per day creates this failure mode:

```
Day 1, Run 1:  SQL injection in es/client.py:L136   → Issue #101 created
Day 1, Run 2:  SQL injection in es/client.py:L136   → Issue #102 created  ← DUPLICATE
Day 2, Run 1:  SQL injection in es/client.py:L136   → Issue #103 created  ← DUPLICATE
...
Weeks later: 47 open issues, most duplicates, nobody trusts the tracker
```

The problem has two root causes:
- No **stable identity** for a finding across runs
- No **lifecycle state machine** — issues are created but never managed

### 1.2 Solution: Canonical Finding Fingerprints

Every finding must have a **stable, deterministic ID** (fingerprint) that:
- Stays the same across every scan run
- Is the same whether CodeQL or Semgrep finds it
- Changes only if the underlying code changes (file + line + concept)

```
Fingerprint = SHA256(
    file_path +
    start_line +
    concept        ← "sql-injection", not "python.sqli.001"
)[:16]
```

Key insight: **the rule ID from the tool is NOT used** in the fingerprint.
`CodeQL:python/sql-injection` and `Semgrep:custom/sql-injection-rule` at the
same file+line are the **same finding** — same fingerprint.

The `rule_concept` is normalized by the Finding Normalizer
(`scripts/code_analysis/normalizer.py`):

```python
CONCEPT_MAP = {
    # SQL injection — multiple tool IDs → same concept
    "python/sql-injection":                      "sql-injection",
    "python.sqlalchemy.security.sqlalchemy-execute-injection": "sql-injection",
    "kavach-sqlalchemy-raw-string-execute":      "sql-injection",
    "B608":                                      "sql-injection",  # Bandit
    "S608":                                      "sql-injection",  # Ruff

    # Hardcoded secrets
    "HardcodedPassword":                         "hardcoded-secret",
    "HardcodedSecret":                           "hardcoded-secret",
    "kavach-hardcoded-api-key":                  "hardcoded-secret",
    "B105":                                      "hardcoded-secret",

    # JWT
    "python/jwt-missing-verification":           "jwt-none-alg",
    "kavach-jwt-decode-no-algorithm":            "jwt-none-alg",

    # Prompt injection / Agent safety
    "kavach-llm-output-exec-injection":          "code-injection",
    "kavach-langgraph-unrestricted-tool-invocation": "agent-tool-injection",
}
```

This fingerprint is stored in the GitHub Issue body and in DefectDojo as the primary key.

### 1.3 Finding Lifecycle State Machine

A finding is NOT just "open" or "closed". It has a precise lifecycle:

```mermaid
stateDiagram-v2
    [*] --> Detect: First scan detects it
    Detect --> NEW: Fingerprint computed & GitHub Issue created
    note right of NEW: Labels: [new] [severity:high] [tool:codeql]
    
    NEW --> OPEN: Issue assigned to developer / team
    note right of OPEN: Labels: [open] -> [acknowledged]
    
    OPEN --> Rescan: Re-scan runs (every PR / daily)
    
    state "Does fingerprint appear in new scan?" as CheckScan
    Rescan --> CheckScan
    
    CheckScan --> PERSISTS: YES
    note left of PERSISTS: Update 'last seen' timestamp\nNo new issue!
    PERSISTS --> OPEN
    
    CheckScan --> ABSENT: NO
    note right of ABSENT: Could be fixed OR\nscan missed it
    
    ABSENT --> VERIFICATION: Run VERIFICATION SCAN\ntargeted at specific file + rule
    
    VERIFICATION --> SCAN_MISS: Reappears (Flaky scanner)
    SCAN_MISS --> OPEN
    
    VERIFICATION --> RESOLVED: Still absent\n(3 consecutive clean scans)
    
    RESOLVED --> VERIFIED_FIXED: Tests pass, CI clean\nIssue closed with resolution note
    VERIFIED_FIXED --> [*]
    
    OPEN --> FALSE_POSITIVE: AI Triage + Human confirm -> Suppressed
    OPEN --> ACCEPTED_RISK: Known intentional -> Documented + Deferred
    OPEN --> WONT_FIX: Out of scope -> Documented
```

### 1.4 Idempotent Issue Management

The issue workflow must be **fully idempotent**. Running it 100 times produces
exactly the same state as running it once.

```python
# scripts/code_analysis/finding_lifecycle.py (conceptual)
def process_finding(finding, github_client):
    fingerprint = finding.id  # SHA256[:16] stable ID

    # 1. Look for existing issue with this fingerprint
    existing = search_issues(
        label=f"fp:{fingerprint}",
        state="all"            # include closed issues
    )

    if not existing:
        # CASE A: Brand new finding — create issue
        create_issue(finding, fingerprint)

    elif existing.state == "open":
        # CASE B: Known issue, still open — just update "last seen" timestamp
        update_issue_comment(existing, f"Still detected — {today}")
        # DO NOT create a new issue

    elif existing.state == "closed":
        # CASE C: Was closed (assumed fixed) — but detected again
        if finding_severity >= HIGH:
            reopen_issue(existing, reason="Regression detected by scanner")
```

**GitHub Labels Design:**

```
# Stable fingerprint label (PRIMARY KEY — never changes)
fp:a3f8c2d1          # short fingerprint

# Lifecycle state (only one at a time)
state:new
state:open
state:acknowledged
state:in-progress
state:pending-verification
state:false-positive

# Severity (set by scanner, can escalate)
severity:critical
severity:high
severity:medium
severity:low

# Tool that first detected it
tool:codeql
tool:semgrep
tool:bandit

# Corroboration (set by normalizer if multiple tools agree)
corroborated         # 2+ tools found same fingerprint
```

### 1.5 Persistence Guarantee

> **A finding issue is NEVER closed just because a single scan did not report it.**

The closing rule is:
```
close_condition = (
    3 consecutive clean scans of the affected file
    AND targeted re-scan of the specific rule on the specific file
    AND all tests pass
)
```

This prevents false closures due to:
- Diff-aware scanners skipping unchanged files
- Tool flakiness / partial scan failures
- Scanner version changes affecting detection

---

## Part 2 — Tool Web Coherence

### 2.1 The Three Coherence Risks

| Risk | Definition | Consequence |
|------|-----------|-------------|
| **Overlap** | Multiple tools cover the same surface | Finding appears N times → alert fatigue |
| **Dead spots** | A surface no tool covers | Issues exist but are never detected |
| **Disconnection** | Tools don't share state | No "web" benefit |

### 2.2 Overlap Is By Design — But Must Be Deduplicated

Overlap is not a bug, it is **defense-in-depth**. CodeQL catching SQL injection AND
Semgrep catching SQL injection is intentional:
- CodeQL: semantic/data-flow — catches complex multi-step injection
- Semgrep: pattern — catches obvious string-concat injection fast

But the developer should see **one issue**, not two. The `FindingDeduplicator`
in `normalizer.py` groups findings by `dedup_key = file:line:concept` and picks
the highest-severity finding as canonical. Other detections become `evidence[]`
on the canonical finding, increasing confidence — not separate issues.

### 2.3 Dead Spots — Acknowledged Gaps

| Surface | Why Static Analysis Cannot Cover It | Mitigation |
|---------|-------------------------------------|------------|
| Race conditions | Requires runtime analysis | CodeRabbit AI review (heuristic) |
| Business logic flaws | Requires domain context | CodeRabbit AI + manual security review |
| Second-order injection | Requires data-flow across sessions | CodeQL extended queries |
| Timing attacks | Requires bytecode analysis | `hmac.compare_digest` patterns in Semgrep |
| Logic bugs | Requires specification | pytest coverage + Atheris Fuzzing |
| Runtime 500 Crashes | Requires dynamic execution | Schemathesis API Fuzzing |
| AI/Agent prompt injection | Requires runtime trace | Semgrep custom rules (patterns only) |

### 2.4 Tool Selection Coherence — Why Each Tool Is Kept

Every tool in the stack has a reason for existing alongside the others.

| Tool | Unique Contribution | If Removed |
|------|--------------------|------------|
| **CodeQL** | Semantic inter-procedural data-flow taint; multi-hop injection | Misses complex injection chains |
| **Semgrep** | Fast pattern rules; diff-aware; custom YAML rules | Loses prompt injection detection |
| **Bandit** | Python-specific: B-rules for eval/exec/pickle/subprocess | Loses Python-specific dangerous function detection |
| **Ruff** | Lightning-fast; covers 40+ rules including security (S-rules) | Losing existing tool; import/format coverage gone |
| **Pyright** | Fast static type analysis; native VS Code integration | Loses type mismatch detection |
| **ESLint + tsc** | TypeScript type system catches null-deref, missing checks | Frontend quality coverage gone |
| **OSV-Scanner** | Official Google CVE database for Python + npm | Lose dependency CVE baseline |
| **Gitleaks** | Scans full git history; finds secrets committed months ago | Lose historical secret detection |
| **Trivy** | Scans the actual built Docker image filesystem | Lose runtime image CVE detection |
| **Hadolint** | Dockerfile-specific rules (SHELL, CMD, USER, COPY) | Lose Dockerfile safety |
| **Checkov** | IaC scanner — docker-compose, GitHub Actions, Kubernetes | Lose GH Actions config scanning |
| **CodeScene** | Git-history behavioral analysis — coupling hotspots | Lose technical debt hotspot intelligence |
| **Radon + Xenon** | CI gate for cyclomatic complexity | Lose complexity enforcement in CI |
| **Vulture** | Static dead code detection | Lose static dead code detection |
| **Coverage.py** | Runtime dead-code evidence via test coverage | Lose runtime coverage gap visibility |

**Verdict: Zero tools are redundant.** Each covers a distinct concern.

### 2.5 Coverage Validation — The Canary Test Suite

The only way to know the web is coherent is to test it. We maintain a
**deliberately vulnerable test codebase** (`tests/security_canary/`) that contains
one known example of every vulnerability type we claim to detect. On every tool
upgrade or config change, the pipeline runs against this canary suite and must
catch all known vulnerabilities.

**Canary validation workflow** runs weekly and after any tool config change
(`06-canary-validation.yml`).
