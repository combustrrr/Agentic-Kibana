#!/usr/bin/env python3
"""
Canary Test Suite: Prompt Injection via LLM Output Execution
=============================================================
This file DELIBERATELY contains a pattern where LLM/agent output is
used in eval(), enabling prompt injection → arbitrary code execution.

It exists to validate that the scanner pipeline detects agent-specific
security risks that standard SAST tools miss.

Expected detections: Semgrep (custom rule: llm-output-used-as-code)
"""


# ── Pattern 1: LLM response used in eval() ──────────────────────────────────
def execute_llm_code(llm_response: str):
    """
    VULNERABLE: The LLM model's response is passed directly to eval().
    An attacker who can influence the LLM (via prompt injection in the
    ingested alert data) can execute arbitrary Python code.
    """
    # The model's output is trusted as executable code — this is the anti-pattern
    result = eval(llm_response)
    return result


# ── Pattern 2: LLM-generated tool name used in dynamic dispatch ─────────────
def dispatch_agent_tool(llm_output: str):
    """
    VULNERABLE: The LLM model chooses which tool to invoke by name,
    and the output is passed directly to a tool executor without
    checking against an allowlist.
    """
    # Unrestricted tool invocation — model output is used as tool name
    tool_name = llm_output  # No allowlist check!
    result = tool_executor.invoke({"tool": tool_name, "args": {}})
    return result


# ── Pattern 3: LLM response in subprocess ───────────────────────────────────
def run_llm_command(llm_decision: str):
    """
    VULNERABLE: LLM model output used in subprocess call.
    """
    import subprocess
    result = subprocess.run(llm_decision, shell=True, capture_output=True, text=True)
    return result.stdout


# ── SAFE versions (for contrast) ─────────────────────────────────────────────
SAFE_TOOL_ALLOWLIST = {"es_query", "enrich", "rag_retrieve"}


def execute_llm_code_safe(llm_response: str):
    """SAFE: LLM output is parsed as structured data, not code."""
    import json
    try:
        result = json.loads(llm_response)
        return result
    except json.JSONDecodeError:
        return None


def dispatch_agent_tool_safe(llm_output: str):
    """SAFE: tool name is validated against an allowlist before invocation."""
    import json
    parsed = json.loads(llm_output)
    tool_name = parsed.get("tool")
    if tool_name not in SAFE_TOOL_ALLOWLIST:
        raise ValueError(f"Tool '{tool_name}' not in allowlist")
    return tool_executor.invoke({"tool": tool_name, "args": parsed.get("args", {})})


tool_executor = type("MockExecutor", (), {"invoke": staticmethod(lambda x: x)})()
