#!/usr/bin/env python3
"""
Canary Test Suite: SQL Injection
=================================
This file DELIBERATELY contains vulnerable code patterns.
It exists to validate that the scanner pipeline detects SQL injection.

NEVER import or run this code in production.
Expected detections: CodeQL (python/sql-injection), Semgrep, Bandit (B608)
"""

# ── Pattern 1: f-string SQL injection (most obvious) ─────────────────────────
async def get_user_by_id_vulnerable(db, user_id: str):
    """VULNERABLE: f-string directly in query."""
    query = f"SELECT * FROM users WHERE id = {user_id}"   # noqa: S608  ← intentional
    return await db.execute(query)


# ── Pattern 2: String concatenation ──────────────────────────────────────────
def search_logs_vulnerable(conn, keyword: str):
    """VULNERABLE: string concatenation in SQL."""
    sql = "SELECT * FROM audit_logs WHERE message LIKE '%" + keyword + "%'"
    return conn.execute(sql)


# ── Pattern 3: % formatting ───────────────────────────────────────────────────
def get_alert_by_status_vulnerable(db, status: str):
    """VULNERABLE: % string formatting in SQL."""
    query = "SELECT * FROM alerts WHERE status = '%s'" % status
    return db.execute(query)


# ── SAFE versions (for contrast) ─────────────────────────────────────────────
async def get_user_by_id_safe(db, user_id: int):
    """SAFE: parameterized query."""
    return await db.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def search_logs_safe(conn, keyword: str):
    """SAFE: ORM query with bound parameters."""
    return conn.execute(
        "SELECT * FROM audit_logs WHERE message LIKE ?",
        (f"%{keyword}%",)
    )
