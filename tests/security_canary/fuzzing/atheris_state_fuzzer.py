"""
Atheris Fuzzing Harness for Kavach-AgenticSOC State Machine
============================================================
Targets the core state transition logic in backend/app/engine/ and
backend/app/state.py. Uses coverage-guided fuzzing to find unhandled
exceptions, infinite loops, or invalid state transitions in the
case management and correlation pipeline.

Run locally:
  cd backend
  pip install atheris
  python ../tests/security_canary/fuzzing/atheris_state_fuzzer.py

CI: runs in the 07-api-fuzzing.yml workflow (weekly + on API changes).
"""

import sys
import atheris

# ─────────────────────────────────────────────────────────────
# Fuzzing targets — imports from the Kavach backend
# ─────────────────────────────────────────────────────────────

# Import the actual state machine logic under test
# (These imports require the backend package to be available)
try:
    from app.engine.case_manager import CaseManager, decide
    from app.models import Case, Verdict, AutoClosePolicy
    from app.constants import CaseStatus, CaseVerdict
    _BACKEND_AVAILABLE = True
except ImportError:
    _BACKEND_AVAILABLE = False


@dataclass
class FuzzCaseInput:
    """Fuzzer input parsed from raw bytes."""
    verdict: str
    confidence: float
    risk_score: float
    status: str


def _parse_fuzz_input(data: bytes) -> FuzzCaseInput | None:
    """
    Parse raw fuzzer bytes into a structured case decision input.
    Returns None if the bytes cannot be parsed (expected — not a crash).
    """
    if len(data) < 4:
        return None

    try:
        # Use the bytes to construct fuzzed parameters
        # Map bytes to enum values for verdict and status
        verdict_byte = data[0] % 3
        verdict_map = {0: "TRUE_POSITIVE", 1: "FALSE_POSITIVE", 2: "NEEDS_HUMAN"}
        verdict = verdict_map[verdict_byte]

        # Confidence: 0.0 to 1.0
        confidence = (data[1] / 255.0) if len(data) > 1 else 0.5

        # Risk score: 0.0 to 10.0
        risk_score = ((data[2] % 101) / 10.0) if len(data) > 2 else 5.0

        # Status: first letter determines status category
        status_map = {
            0: "NEW",
            1: "OPEN",
            2: "INVESTIGATING",
            3: "NEEDS_HUMAN",
            4: "RESOLVED",
            5: "CLOSED",
        }
        status = status_map[(data[3] % 6)]

        return FuzzCaseInput(
            verdict=verdict,
            confidence=confidence,
            risk_score=risk_score,
            status=status,
        )
    except (IndexError, ValueError):
        return None


def _construct_case(fuzz_input: FuzzCaseInput):
    """Build a Case object with fuzzed parameters."""
    from app.models import Case
    from app.constants import CaseStatus, CaseVerdict

    verdict_enum = {
        "TRUE_POSITIVE": CaseVerdict.TRUE_POSITIVE,
        "FALSE_POSITIVE": CaseVerdict.FALSE_POSITIVE,
        "NEEDS_HUMAN": CaseVerdict.NEEDS_HUMAN,
    }[fuzz_input.verdict]

    status_enum = {
        "NEW": CaseStatus.NEW,
        "OPEN": CaseStatus.OPEN,
        "INVESTIGATING": CaseStatus.INVESTIGATING,
        "NEEDS_HUMAN": CaseStatus.NEEDS_HUMAN,
        "RESOLVED": CaseStatus.RESOLVED,
        "CLOSED": CaseStatus.CLOSED,
    }[fuzz_input.status]

    # Construct a minimal Case with fuzzed fields
    case = Case(
        id=f"fuzz-case-{fuzz_input.verdict}",
        cluster_signature="fuzz-cluster",
        verdict=verdict_enum,
        confidence=fuzz_input.confidence,
        risk_score=fuzz_input.risk_score,
        status=status_enum,
        raw_rule_id="fuzz-rule",
        summary="Fuzzer-generated case",
    )
    return case


def _run_decide(fuzz_input: FuzzCaseInput):
    """
    Run the deterministic case_manager.decide() function with fuzzed input.
    This is the core decision function that should never crash.
    """
    if not _BACKEND_AVAILABLE:
        # Fallback: simulate the decision logic
        policy = AutoClosePolicy(
            enable_auto_close=True,
            min_confidence=0.8,
            max_risk_score=10.0,
        )
        return decide(fuzz_input.verdict, fuzz_input.confidence, fuzz_input.risk_score, policy)

    case = _construct_case(fuzz_input)
    policy = AutoClosePolicy(
        enable_auto_close=True,
        min_confidence=0.5,
        max_risk_score=10.0,
    )
    return decide(
        verdict=fuzz_input.verdict,
        confidence=fuzz_input.confidence,
        risk_score=fuzz_input.risk_score,
        policy=policy,
    )


def TestOneInput(data: bytes) -> None:
    """
    Atheris entry point. Called continuously with mutated data.
    Goal: find edge cases in the case decision state machine.
    """
    if len(data) < 4 or len(data) > 4096:
        return

    fuzz_input = _parse_fuzz_input(data)
    if fuzz_input is None:
        return  # Invalid input is expected, not a crash

    try:
        _run_decide(fuzz_input)
    except ValueError as e:
        # Expected validation errors are fine
        if "Fatal:" in str(e):
            raise  # This is a real crash that should not happen
    except (KeyError, TypeError) as e:
        # These are unexpected — indicate a crash in the state machine
        raise AssertionError(f"Unhandled state transition: {e}") from e


# ─────────────────────────────────────────────────────────────
# Standalone mode (run without atheris for basic testing)
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if "--no-atheris" in sys.argv:
        # Run a few test iterations without atheris
        import os
        for i in range(50):
            data = os.urandom(20)
            try:
                TestOneInput(data)
            except AssertionError as e:
                print(f"Fuzz input {i} found issue: {e}")
                sys.exit(1)
        print("All fuzz iterations passed (no atheris)")
        sys.exit(0)

    # Full atheris fuzzing
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
