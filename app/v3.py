"""
AgentGuard v3.0.0 — Session Engine, Real HITL, Injection Detection,
                     Per-Tool Rate Limits, Intent Drift Tracking

HOW TO INTEGRATE:
1. Add DB migrations to init_db()
2. Add helpers below existing helpers
3. Add new Pydantic models
4. Register new endpoints
5. Modify run_enforcement() to accept session_id
6. Update requirements.txt (no new deps needed beyond existing)
"""

# ══════════════════════════════════════════════════════════════════════════════
# 1. DB MIGRATIONS — add to init_db()
# ══════════════════════════════════════════════════════════════════════════════

SESSION_MIGRATIONS = [
"""CREATE TABLE IF NOT EXISTS agent_sessions (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    intent          TEXT,
    intent_embedding_hash TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    tool_call_count INTEGER DEFAULT 0,
    deny_count      INTEGER DEFAULT 0,
    started_at      TIMESTAMPTZ DEFAULT NOW(),
    last_active_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    metadata        JSONB DEFAULT '{}'
)""",

"""CREATE INDEX IF NOT EXISTS sessions_agent_idx
   ON agent_sessions(agent_id, status)""",

"""CREATE INDEX IF NOT EXISTS sessions_tenant_idx
   ON agent_sessions(tenant_id, started_at DESC)""",

"""CREATE TABLE IF NOT EXISTS session_tool_calls (
    id         TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    tenant_id  TEXT NOT NULL,
    agent_id   TEXT NOT NULL,
    tool       TEXT NOT NULL,
    args_hash  TEXT,
    decision   TEXT NOT NULL,
    turn       INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
)""",

"""CREATE INDEX IF NOT EXISTS stc_session_idx
   ON session_tool_calls(session_id, turn)""",

"""CREATE TABLE IF NOT EXISTS hitl_approvals (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    session_id  TEXT,
    request_id  TEXT NOT NULL,
    tool        TEXT NOT NULL,
    args        JSONB,
    reason      TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',
    decision    TEXT,
    decided_by  TEXT,
    decided_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL,
    webhook_sent BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
)""",

"""CREATE INDEX IF NOT EXISTS hitl_tenant_idx
   ON hitl_approvals(tenant_id, status, created_at DESC)""",

"""CREATE INDEX IF NOT EXISTS hitl_session_idx
   ON hitl_approvals(session_id, status)""",

"""CREATE TABLE IF NOT EXISTS injection_events (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    agent_id   TEXT NOT NULL,
    session_id TEXT,
    source     TEXT NOT NULL,
    pattern    TEXT NOT NULL,
    content    TEXT,
    blocked    BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
)""",

"""CREATE INDEX IF NOT EXISTS injection_tenant_idx
   ON injection_events(tenant_id, created_at DESC)""",

"""CREATE TABLE IF NOT EXISTS tool_rate_limits (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    tool_pattern TEXT NOT NULL,
    max_calls   INTEGER NOT NULL,
    window_secs INTEGER NOT NULL DEFAULT 3600,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, agent_id, tool_pattern)
)""",
]


# ══════════════════════════════════════════════════════════════════════════════
# 2. NEW PYDANTIC MODELS
# ══════════════════════════════════════════════════════════════════════════════

from pydantic import BaseModel
from typing import Any, Optional

class SessionCreate(BaseModel):
    agent_id:    str
    user_id:     str
    intent:      str                    # "Summarize the Q3 report and email to team"
    ttl_seconds: int = 3600             # session expires after N seconds of inactivity
    metadata:    dict = {}

class SessionToolCall(BaseModel):
    """Extended ProtectRequest with session awareness."""
    tool:       str
    args:       dict[str, Any] = {}
    agent_id:   str
    user_id:    str
    session_id: str                     # REQUIRED for session-aware enforcement
    context:    Optional[str] = None
    # tool result to scan for injection (populated AFTER tool executes)
    tool_result: Optional[Any] = None
    timestamp:  Optional[int] = None
    nonce:      Optional[str] = None

class HITLDecision(BaseModel):
    decision:    str                    # "approve" | "reject"
    decided_by:  str                    # user_id or email of approver
    reason:      Optional[str] = None

class ToolRateLimit(BaseModel):
    agent_id:     str
    tool_pattern: str                   # "send_email" or "send_*" or "*"
    max_calls:    int
    window_secs:  int = 3600


# ══════════════════════════════════════════════════════════════════════════════
# 3. INJECTION DETECTION
# ══════════════════════════════════════════════════════════════════════════════

import re

# Patterns that indicate prompt injection attempts in tool results
INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "ignore_instructions"),
    (r"disregard\s+(all\s+)?(previous|prior|above|your)\s+", "disregard_instructions"),
    (r"you\s+are\s+now\s+(a|an)\s+", "persona_hijack"),
    (r"new\s+instructions?\s*:", "new_instructions"),
    (r"system\s*prompt\s*:", "system_prompt_leak"),
    (r"<\s*/?system\s*>", "system_tag_injection"),
    (r"<\s*/?instruction\s*>", "instruction_tag"),
    (r"\[INST\]|\[/INST\]", "llama_injection"),
    (r"###\s*instruction", "markdown_instruction"),
    (r"exfiltrate|extract\s+all\s+data|send\s+all\s+(files|data|keys)", "exfil_attempt"),
    (r"base64\s*decode|eval\s*\(|exec\s*\(", "code_injection"),
    (r"curl\s+http|wget\s+http|fetch\s*\(\s*['\"]http", "ssrf_injection"),
    (r"drop\s+table|delete\s+from|truncate\s+table", "sql_injection"),
    (r"sudo\s+|rm\s+-rf|chmod\s+777", "shell_injection"),
]

_INJECTION_RE = [(re.compile(pat, re.IGNORECASE), label) for pat, label in INJECTION_PATTERNS]

def scan_for_injection(content: Any, source: str = "tool_result") -> list[dict]:
    """
    Scan any content (tool result, args, context) for injection patterns.
    Returns list of findings — empty means clean.
    """
    if content is None:
        return []
    try:
        text = content if isinstance(content, str) else json.dumps(content, default=str)
    except Exception:
        return []

    findings = []
    for pattern, label in _INJECTION_RE:
        m = pattern.search(text)
        if m:
            findings.append({
                "pattern": label,
                "match":   text[max(0, m.start()-20):m.end()+20],
                "source":  source,
            })
    return findings

async def log_injection_event(tenant_id, agent_id, session_id, source, finding):
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO injection_events
               (id, tenant_id, agent_id, session_id, source, pattern, content, blocked)
               VALUES (gen_random_uuid()::text, $1, $2, $3, $4, $5, $6, TRUE)""",
            tenant_id, agent_id, session_id,
            source, finding["pattern"], finding["match"][:500]
        )
    log.warning("injection.detected", tenant_id=tenant_id, agent_id=agent_id,
                pattern=finding["pattern"], source=source)


# ══════════════════════════════════════════════════════════════════════════════
# 4. SESSION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

import json, hashlib, time, uuid, asyncio
import structlog
log = structlog.get_logger()

SESSION_TTL_DEFAULT = 3600

async def create_session(tenant_id: str, agent_id: str, user_id: str,
                          intent: str, ttl: int = SESSION_TTL_DEFAULT,
                          metadata: dict = {}) -> dict:
    session_id = f"sess_{uuid.uuid4().hex[:16]}"
    intent_hash = hashlib.sha256(intent.encode()).hexdigest()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO agent_sessions
               (id, tenant_id, agent_id, user_id, intent,
                intent_embedding_hash, expires_at, metadata)
               VALUES ($1,$2,$3,$4,$5,$6,NOW()+($7||' seconds')::INTERVAL,$8)""",
            session_id, tenant_id, agent_id, user_id, intent,
            intent_hash, str(ttl), json.dumps(metadata)
        )
    # Cache in Redis for fast reads
    if redis_conn:
        await redis_conn.setex(
            f"ag:sess:{session_id}",
            ttl,
            json.dumps({"tenant_id": tenant_id, "agent_id": agent_id,
                        "user_id": user_id, "intent": intent,
                        "tool_call_count": 0, "deny_count": 0})
        )
    return {"session_id": session_id, "intent": intent, "expires_in": ttl}

async def get_session(session_id: str, tenant_id: str) -> Optional[dict]:
    # Try Redis first
    if redis_conn:
        try:
            raw = await redis_conn.get(f"ag:sess:{session_id}")
            if raw:
                data = json.loads(raw)
                if data.get("tenant_id") == tenant_id:
                    return data
        except Exception:
            pass
    # Fallback to DB
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT * FROM agent_sessions
               WHERE id=$1 AND tenant_id=$2
               AND status='active' AND expires_at > NOW()""",
            session_id, tenant_id
        )
    if not row:
        return None
    return dict(row)

async def increment_session_counters(session_id: str, tenant_id: str,
                                      decision: str, tool: str, turn: int):
    deny_inc = 1 if decision == "deny" else 0
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE agent_sessions
               SET tool_call_count = tool_call_count + 1,
                   deny_count = deny_count + $1,
                   last_active_at = NOW()
               WHERE id=$2 AND tenant_id=$3""",
            deny_inc, session_id, tenant_id
        )
        await conn.execute(
            """INSERT INTO session_tool_calls
               (id, session_id, tenant_id, agent_id, tool, decision, turn)
               SELECT gen_random_uuid()::text, $1, tenant_id, agent_id, $2, $3, $4
               FROM agent_sessions WHERE id=$1""",
            session_id, tool, decision, turn
        )
    # Update Redis
    if redis_conn:
        try:
            raw = await redis_conn.get(f"ag:sess:{session_id}")
            if raw:
                data = json.loads(raw)
                data["tool_call_count"] = data.get("tool_call_count", 0) + 1
                data["deny_count"] = data.get("deny_count", 0) + deny_inc
                ttl = await redis_conn.ttl(f"ag:sess:{session_id}")
                await redis_conn.setex(f"ag:sess:{session_id}", max(ttl, 60), json.dumps(data))
        except Exception:
            pass

async def terminate_session(session_id: str, tenant_id: str, reason: str = "manual"):
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE agent_sessions SET status=$1 WHERE id=$2 AND tenant_id=$3",
            reason, session_id, tenant_id
        )
    if redis_conn:
        await redis_conn.delete(f"ag:sess:{session_id}")


# ══════════════════════════════════════════════════════════════════════════════
# 5. INTENT DRIFT DETECTION
# ══════════════════════════════════════════════════════════════════════════════

# Cache: session_id -> (intent_summary, last_checked_turn)
_intent_cache: dict = {}

async def check_intent_drift(session: dict, tool: str, args: dict,
                               turn: int) -> tuple[bool, str]:
    """
    Compare current action against session intent.
    Uses Claude to score drift — only called every 5 turns to keep cost low.
    Cached per session.
    """
    session_id = session.get("id") or session.get("session_id", "")
    intent     = session.get("intent", "")
    if not intent:
        return True, "no intent set"

    # Only check every 5 turns (not every call — too expensive)
    last_turn = _intent_cache.get(session_id, {}).get("last_turn", 0)
    if turn - last_turn < 5 and turn > 1:
        cached = _intent_cache.get(session_id, {})
        return cached.get("ok", True), cached.get("reason", "cached")

    # Get recent tool call history for context
    async with pool.acquire() as conn:
        recent = await conn.fetch(
            """SELECT tool, decision FROM session_tool_calls
               WHERE session_id=$1 ORDER BY turn DESC LIMIT 10""",
            session_id
        )
    history = ", ".join(f"{r['tool']}({r['decision']})" for r in recent)

    try:
        client = anthropic.AsyncAnthropic()
        msg = await asyncio.wait_for(
            client.messages.create(
                model="claude-haiku-4-5-20251001",  # cheap model for this check
                max_tokens=150,
                messages=[{"role": "user", "content":
                    f"Session intent: '{intent}'\n"
                    f"Recent tools: {history}\n"
                    f"Current action: {tool}({json.dumps(args, default=str)[:200]})\n"
                    f"Turn: {turn}\n"
                    f"Is this action consistent with the session intent? "
                    f"JSON only: {{\"consistent\":true,\"drift_score\":0.0,\"reason\":\"brief\"}}\n"
                    f"drift_score: 0.0=perfect match, 1.0=completely unrelated"
                }]
            ),
            timeout=6.0
        )
        raw = re.sub(r"^```(?:json)?\n?|\n?```$", "", msg.content[0].text.strip())
        result = json.loads(raw)
        drift  = float(result.get("drift_score", 0))
        ok     = drift < 0.75  # threshold — tune per deployment
        reason = result.get("reason", "")

        _intent_cache[session_id] = {
            "ok": ok, "reason": reason,
            "drift_score": drift, "last_turn": turn
        }
        return ok, f"drift={drift:.2f}: {reason}"
    except Exception as e:
        # Fail open on drift check — it's supplemental, not primary
        return True, f"drift check skipped ({type(e).__name__})"


# ══════════════════════════════════════════════════════════════════════════════
# 6. PER-TOOL RATE LIMITER (Redis-backed sliding window)
# ══════════════════════════════════════════════════════════════════════════════

async def check_tool_rate_limit(tenant_id: str, agent_id: str,
                                 tool: str, session_id: Optional[str] = None
                                 ) -> tuple[bool, str]:
    """
    Check per-tool rate limits configured via POST /rate-limits.
    Uses Redis sorted sets for sliding window.
    Falls back to DB count if Redis unavailable.
    """
    async with pool.acquire() as conn:
        limits = await conn.fetch(
            """SELECT tool_pattern, max_calls, window_secs
               FROM tool_rate_limits
               WHERE tenant_id=$1 AND agent_id=$2""",
            tenant_id, agent_id
        )

    for row in limits:
        pattern = row["tool_pattern"]
        if not _matches(tool, pattern):
            continue

        max_calls   = row["max_calls"]
        window_secs = row["window_secs"]
        now         = time.time()
        window_start = now - window_secs

        if redis_conn and await _redis_ok():
            key = f"ag:trl:{tenant_id}:{agent_id}:{pattern}"
            pipe = redis_conn.pipeline()
            # Sliding window: remove old entries, add current, count
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zadd(key, {str(uuid.uuid4()): now})
            pipe.zcard(key)
            pipe.expire(key, window_secs + 10)
            results = await pipe.execute()
            count = results[2]
        else:
            # Fallback: DB count
            async with pool.acquire() as conn:
                count = await conn.fetchval(
                    """SELECT COUNT(*) FROM session_tool_calls
                       WHERE agent_id=$1
                       AND tool ILIKE $2
                       AND created_at > NOW() - ($3||' seconds')::INTERVAL""",
                    agent_id,
                    pattern.replace("*", "%"),
                    str(window_secs)
                ) or 0

        if count > max_calls:
            return False, (
                f"Tool '{tool}' rate limit exceeded: "
                f"{count}/{max_calls} calls in {window_secs}s window"
            )

    return True, "ok"


# ══════════════════════════════════════════════════════════════════════════════
# 7. REAL HITL — ASYNC APPROVAL FLOW
# ══════════════════════════════════════════════════════════════════════════════

HITL_DEFAULT_TTL = 300  # 5 minutes to approve before auto-expire

async def create_hitl_request(tenant_id: str, agent_id: str, session_id: Optional[str],
                               request_id: str, tool: str, args: dict,
                               reason: str, ttl: int = HITL_DEFAULT_TTL) -> dict:
    hitl_id = f"hitl_{uuid.uuid4().hex[:16]}"
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO hitl_approvals
               (id, tenant_id, agent_id, session_id, request_id,
                tool, args, reason, expires_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW()+($9||' seconds')::INTERVAL)""",
            hitl_id, tenant_id, agent_id, session_id, request_id,
            tool, json.dumps(args), reason, str(ttl)
        )

    # Store in Redis so agent can poll cheaply
    if redis_conn:
        await redis_conn.setex(
            f"ag:hitl:{hitl_id}",
            ttl + 60,
            json.dumps({"status": "pending", "tool": tool})
        )

    # Fire webhook to notify humans
    await _fire_hitl_webhook(tenant_id, hitl_id, tool, args, reason)

    return {
        "hitl_id":      hitl_id,
        "status":       "pending",
        "poll_url":     f"/hitl/{hitl_id}",
        "expires_in":   ttl,
        "tool":         tool,
        "reason":       reason,
    }

async def _fire_hitl_webhook(tenant_id: str, hitl_id: str,
                              tool: str, args: dict, reason: str):
    """Send webhook to all tenant webhooks subscribed to 'hitl' events."""
    try:
        async with pool.acquire() as conn:
            hooks = await conn.fetch(
                "SELECT url, secret FROM webhooks WHERE tenant_id=$1 AND active=TRUE "
                "AND 'hitl'=ANY(events)",
                tenant_id
            )
        if not hooks:
            return

        payload = json.dumps({
            "event":    "hitl.pending",
            "hitl_id":  hitl_id,
            "tool":     tool,
            "args":     args,
            "reason":   reason,
            "approve_url": f"POST /hitl/{hitl_id}/decide {{\"decision\":\"approve\",\"decided_by\":\"...\"}}",
        }, default=str).encode()

        for hook in hooks:
            import hmac as _hmac
            sig = _hmac.new(hook["secret"].encode(), payload, hashlib.sha256).hexdigest()
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(hook["url"], content=payload, headers={
                        "Content-Type": "application/json",
                        "x-agentguard-signature": f"sha256={sig}",
                        "x-agentguard-event": "hitl.pending",
                    })
                # Mark sent
                async with pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE hitl_approvals SET webhook_sent=TRUE WHERE id=$1", hitl_id
                    )
            except Exception as e:
                log.warning("hitl.webhook_failed", hitl_id=hitl_id, error=str(e))
    except Exception as e:
        log.error("hitl.webhook_error", error=str(e))

async def get_hitl_status(hitl_id: str, tenant_id: str) -> Optional[dict]:
    # Fast path: Redis
    if redis_conn:
        try:
            raw = await redis_conn.get(f"ag:hitl:{hitl_id}")
            if raw:
                data = json.loads(raw)
                if data.get("status") != "pending":
                    return data
        except Exception:
            pass
    # DB
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM hitl_approvals WHERE id=$1 AND tenant_id=$2",
            hitl_id, tenant_id
        )
    return dict(row) if row else None

async def decide_hitl(hitl_id: str, tenant_id: str,
                       decision: str, decided_by: str, reason: Optional[str]) -> dict:
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be 'approve' or 'reject'")

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM hitl_approvals WHERE id=$1 AND tenant_id=$2 AND status='pending'",
            hitl_id, tenant_id
        )
        if not row:
            raise LookupError("HITL request not found or already decided")
        if row["expires_at"] < datetime.now(timezone.utc):
            raise TimeoutError("HITL request has expired")

        await conn.execute(
            """UPDATE hitl_approvals
               SET status='decided', decision=$1, decided_by=$2,
                   decided_at=NOW()
               WHERE id=$3""",
            decision, decided_by, hitl_id
        )

    result = {"hitl_id": hitl_id, "decision": decision,
              "decided_by": decided_by, "tool": row["tool"]}

    # Update Redis so agent poll gets instant result
    if redis_conn:
        await redis_conn.setex(
            f"ag:hitl:{hitl_id}", 300,
            json.dumps({**result, "status": "decided", "args": json.loads(row["args"] or "{}")})
        )

    log.info("hitl.decided", hitl_id=hitl_id, decision=decision, decided_by=decided_by)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# 8. UPDATED run_enforcement — session-aware version
#    Replace the existing run_enforcement() with this
# ══════════════════════════════════════════════════════════════════════════════

async def run_enforcement_v3(tool, args, agent, rules, patterns, context,
                              tenant_id=None, session=None, session_id=None):
    """
    Full enforcement pipeline v3:
    1. Tool policy check
    2. Redaction
    3. Args bounds check
    4. Prompt injection scan (args + context)
    5. Per-tool rate limit
    6. Semantic check
    7. Intent drift (session-aware)
    8. HITL trigger
    """
    if isinstance(rules, str):
        rules = json.loads(rules)

    # Step 1: Tool policy
    ok, reason = check_tool(tool, rules)
    if not ok:
        return False, reason, args, False, "blocked"

    # Step 2: Redact
    clean, redacted = redact(args, patterns)
    if not isinstance(clean, dict):
        clean = {}

    # Step 3: Args bounds
    ok, reason = check_args(clean, rules)
    if not ok:
        return False, reason, clean, redacted, "blocked"

    # Step 4: Injection scan on args + context
    for source, content in [("args", clean), ("context", context)]:
        findings = scan_for_injection(content, source)
        if findings:
            f = findings[0]
            if tenant_id:
                asyncio.ensure_future(
                    log_injection_event(tenant_id, agent["id"], session_id, source, f)
                )
            return False, f"Injection detected in {source}: {f['pattern']}", clean, redacted, "injection_blocked"

    # Step 5: Per-tool rate limit
    if tenant_id:
        rl_ok, rl_reason = await check_tool_rate_limit(
            tenant_id, agent["id"], tool, session_id
        )
        if not rl_ok:
            return False, rl_reason, clean, redacted, "rate_limited"

    # Step 6: Semantic check
    toks = _tokens(tool)
    if context is not None or any(t in SUSPICIOUS_VERBS for t in toks):
        sem_ok, sem_reason = await semantic_check(tool, clean, context, agent["policy"])
        if not sem_ok:
            return False, sem_reason, clean, redacted, "blocked_semantic"

    # Step 7: Intent drift (only when session exists)
    if session:
        turn = session.get("tool_call_count", 0) + 1
        drift_ok, drift_reason = await check_intent_drift(session, tool, clean, turn)
        if not drift_ok:
            return False, f"Intent drift detected: {drift_reason}", clean, redacted, "intent_drift"

    # Step 8: HITL
    hitl = rules.get("require_approval", [])
    if any(_matches(tool, p) for p in hitl):
        return False, "requires human approval", clean, redacted, "pending_approval"

    return True, "all checks passed", clean, redacted, "proceed"


# ══════════════════════════════════════════════════════════════════════════════
# 9. NEW ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

from fastapi import FastAPI, HTTPException, Header, Request, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
import anthropic, httpx
from datetime import datetime, timezone, timedelta

# ── Sessions ──────────────────────────────────────────────────────────────────

@app.post("/sessions")
async def start_session(body: SessionCreate, tenant=Depends(get_tenant)):
    """
    Start a session with an explicit intent statement.
    The intent anchors all subsequent tool calls — drift is flagged automatically.
    """
    async with pool.acquire() as conn:
        agent = await conn.fetchrow(
            "SELECT id FROM agents WHERE id=$1 AND tenant_id=$2 AND revoked=FALSE",
            body.agent_id, tenant["id"]
        )
    if not agent:
        raise HTTPException(404, "Agent not found or revoked")

    result = await create_session(
        tenant["id"], body.agent_id, body.user_id,
        body.intent, body.ttl_seconds, body.metadata
    )
    log.info("session.created", session_id=result["session_id"],
             agent_id=body.agent_id, intent=body.intent[:80])
    return result

@app.get("/sessions/{session_id}")
async def get_session_detail(session_id: str, tenant=Depends(get_tenant)):
    sess = await get_session(session_id, tenant["id"])
    if not sess:
        raise HTTPException(404, "Session not found or expired")
    # Enrich with tool call history
    async with pool.acquire() as conn:
        calls = await conn.fetch(
            """SELECT tool, decision, turn, created_at
               FROM session_tool_calls WHERE session_id=$1
               ORDER BY turn DESC LIMIT 50""",
            session_id
        )
    return {**sess, "recent_calls": [dict(c) for c in calls]}

@app.delete("/sessions/{session_id}")
async def end_session(session_id: str, tenant=Depends(get_tenant)):
    await terminate_session(session_id, tenant["id"], "terminated")
    return {"session_id": session_id, "status": "terminated"}

@app.get("/sessions")
async def list_sessions(tenant=Depends(get_tenant),
                         agent_id: Optional[str] = None,
                         status: str = "active",
                         limit: int = 50):
    where = "WHERE tenant_id=$1 AND status=$2"
    vals  = [tenant["id"], status]
    if agent_id:
        where += " AND agent_id=$3"; vals.append(agent_id)
    vals.append(min(limit, 200))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""SELECT id, agent_id, user_id, intent, status,
                       tool_call_count, deny_count, started_at, last_active_at
                FROM agent_sessions {where}
                ORDER BY last_active_at DESC LIMIT ${len(vals)}""",
            *vals
        )
    return [dict(r) for r in rows]

# ── Session-aware protect ─────────────────────────────────────────────────────

@app.post("/sessions/{session_id}/protect")
@limiter.limit("200/minute;30/second")
async def session_protect(session_id: str, req: SessionToolCall,
                           request: Request, bg: BackgroundTasks,
                           tenant=Depends(get_tenant),
                           x_agent_signature: Optional[str] = Header(None)):
    """
    Session-aware enforcement. Adds:
    - Intent drift detection
    - Per-tool rate limits
    - Injection scanning on tool results
    - Automatic session counter updates
    """
    start = time.monotonic()
    request_id = rid(request)
    body_bytes = await request.body()
    tid = tenant["id"]

    # Load session
    session = await get_session(session_id, tid)
    if not session:
        raise HTTPException(404, "Session not found or expired")

    # Load agent + policy
    agent, policy_row = await load_agent_and_policy(req.agent_id, tid)

    # Signature check
    ok, reason = await verify_request(agent, body_bytes, x_agent_signature,
                                       req.timestamp, req.nonce)
    if not ok:
        raise HTTPException(401, reason)

    # Scan tool_result for injection FIRST (if provided)
    if req.tool_result is not None:
        findings = scan_for_injection(req.tool_result, "tool_result")
        if findings:
            f = findings[0]
            bg.add_task(log_injection_event, tid, req.agent_id, session_id, "tool_result", f)
            ms = int((time.monotonic() - start) * 1000)
            await log_action(request_id, tid, req.agent_id, req.user_id,
                             req.tool, {}, "deny",
                             f"Injection in tool result: {f['pattern']}",
                             False, ms, [])
            return JSONResponse(status_code=403, content={
                "allowed": False,
                "action": "injection_blocked",
                "reason": f"Prompt injection detected in tool result: {f['pattern']}",
                "finding": f,
                "request_id": request_id,
            })

    rules    = policy_row["rules"]
    patterns = build_patterns(rules)

    turn = (session.get("tool_call_count") or 0) + 1
    session["id"] = session_id  # ensure id is accessible

    allowed, reason, clean, redacted, action = await run_enforcement_v3(
        req.tool, req.args, agent, rules, patterns, req.context,
        tenant_id=tid, session=session, session_id=session_id
    )

    decision = "allow" if allowed else ("pending" if action == "pending_approval" else "deny")
    ms = int((time.monotonic() - start) * 1000)

    # Log + update session counters
    await log_action(request_id, tid, req.agent_id, req.user_id,
                     req.tool, clean, decision, reason, redacted, ms, patterns)
    bg.add_task(increment_session_counters, session_id, tid, decision, req.tool, turn)
    LATENCY.labels(endpoint="session_protect").observe(ms / 1000)

    if not allowed:
        # HITL: create real approval request
        if action == "pending_approval":
            hitl = await create_hitl_request(
                tid, req.agent_id, session_id, request_id,
                req.tool, clean, reason
            )
            return JSONResponse(status_code=202, content={
                "allowed": False,
                "action": "pending_approval",
                "reason": reason,
                "hitl": hitl,
                "request_id": request_id,
            })

        # Check if session should be terminated (too many denies)
        new_deny_count = (session.get("deny_count") or 0) + 1
        if new_deny_count >= 5:
            bg.add_task(terminate_session, session_id, tid, "auto_terminated_high_deny")
            log.warning("session.auto_terminated", session_id=session_id,
                        deny_count=new_deny_count)

        return JSONResponse(status_code=403, content={
            "allowed": False,
            "action": action,
            "reason": reason,
            "session_id": session_id,
            "session_turn": turn,
            "request_id": request_id,
        })

    bg.add_task(check_anomalies, tid, req.agent_id, req.tool, bg)

    return {
        "allowed": True,
        "action": "proceed",
        "args": clean,
        "redacted": redacted,
        "duration_ms": ms,
        "policy": agent["policy"],
        "session_id": session_id,
        "session_turn": turn,
        "request_id": request_id,
    }

# ── HITL endpoints ────────────────────────────────────────────────────────────

@app.get("/hitl/{hitl_id}")
async def poll_hitl(hitl_id: str, tenant=Depends(get_tenant)):
    """
    Agent polls this to check if human approved/rejected.
    Fast path via Redis — sub-millisecond when approved.
    """
    result = await get_hitl_status(hitl_id, tenant["id"])
    if not result:
        raise HTTPException(404, "HITL request not found")

    status = result.get("status", "pending")
    if status == "pending":
        # Check expiry
        expires_at = result.get("expires_at")
        if expires_at:
            if isinstance(expires_at, str):
                exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            else:
                exp = expires_at
            if exp < datetime.now(timezone.utc):
                return {"status": "expired", "hitl_id": hitl_id}

    return {
        "hitl_id":     hitl_id,
        "status":      status,
        "decision":    result.get("decision"),
        "decided_by":  result.get("decided_by"),
        "decided_at":  result.get("decided_at"),
        "tool":        result.get("tool"),
        "expires_at":  result.get("expires_at"),
    }

@app.post("/hitl/{hitl_id}/decide")
async def decide_hitl_endpoint(hitl_id: str, body: HITLDecision,
                                tenant=Depends(get_tenant)):
    """
    Human approves or rejects a pending HITL action.
    Agent must poll GET /hitl/{id} to get the result and resume.
    """
    try:
        result = await decide_hitl(hitl_id, tenant["id"],
                                    body.decision, body.decided_by, body.reason)
        return result
    except LookupError as e:
        raise HTTPException(404, str(e))
    except TimeoutError as e:
        raise HTTPException(410, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.get("/hitl")
async def list_hitl(tenant=Depends(get_tenant),
                     status: Optional[str] = None,
                     agent_id: Optional[str] = None,
                     limit: int = 50):
    where = "WHERE tenant_id=$1"
    vals  = [tenant["id"]]
    if status:
        vals.append(status); where += f" AND status=${len(vals)}"
    if agent_id:
        vals.append(agent_id); where += f" AND agent_id=${len(vals)}"
    vals.append(min(limit, 200))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""SELECT id, agent_id, session_id, tool, reason, status,
                       decision, decided_by, decided_at, expires_at,
                       webhook_sent, created_at
                FROM hitl_approvals {where}
                ORDER BY created_at DESC LIMIT ${len(vals)}""",
            *vals
        )
    return [dict(r) for r in rows]

# ── Rate limits ───────────────────────────────────────────────────────────────

@app.post("/rate-limits")
async def set_tool_rate_limit(body: ToolRateLimit, tenant=Depends(get_tenant)):
    """
    Set per-tool rate limits for an agent.
    Example: send_email max 10 calls per hour.
    Supports wildcards: send_* matches all send_ tools.
    """
    async with pool.acquire() as conn:
        agent = await conn.fetchrow(
            "SELECT id FROM agents WHERE id=$1 AND tenant_id=$2",
            body.agent_id, tenant["id"]
        )
        if not agent:
            raise HTTPException(404, "Agent not found")
        await conn.execute(
            """INSERT INTO tool_rate_limits
               (tenant_id, agent_id, tool_pattern, max_calls, window_secs)
               VALUES ($1,$2,$3,$4,$5)
               ON CONFLICT (tenant_id, agent_id, tool_pattern)
               DO UPDATE SET max_calls=$4, window_secs=$5""",
            tenant["id"], body.agent_id, body.tool_pattern,
            body.max_calls, body.window_secs
        )
    return {
        "agent_id":     body.agent_id,
        "tool_pattern": body.tool_pattern,
        "max_calls":    body.max_calls,
        "window_secs":  body.window_secs,
        "window_label": f"{body.window_secs}s",
    }

@app.get("/rate-limits")
async def list_rate_limits(tenant=Depends(get_tenant),
                            agent_id: Optional[str] = None):
    where = "WHERE tenant_id=$1"
    vals  = [tenant["id"]]
    if agent_id:
        where += " AND agent_id=$2"; vals.append(agent_id)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT * FROM tool_rate_limits {where} ORDER BY created_at DESC",
            *vals
        )
    return [dict(r) for r in rows]

@app.delete("/rate-limits/{limit_id}")
async def delete_rate_limit(limit_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        res = await conn.execute(
            "DELETE FROM tool_rate_limits WHERE id=$1 AND tenant_id=$2",
            limit_id, tenant["id"]
        )
    if res == "DELETE 0":
        raise HTTPException(404, "Rate limit not found")
    return {"deleted": limit_id}

# ── Injection events ──────────────────────────────────────────────────────────

@app.get("/security/injections")
async def list_injections(tenant=Depends(get_tenant),
                           agent_id: Optional[str] = None,
                           days: int = 7,
                           limit: int = 100):
    where = "WHERE tenant_id=$1 AND created_at > NOW() - ($2||' days')::INTERVAL"
    vals  = [tenant["id"], str(days)]
    if agent_id:
        where += " AND agent_id=$3"; vals.append(agent_id)
    vals.append(min(limit, 500))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""SELECT * FROM injection_events {where}
                ORDER BY created_at DESC LIMIT ${len(vals)}""",
            *vals
        )
    return [dict(r) for r in rows]

@app.get("/security/injections/stats")
async def injection_stats(tenant=Depends(get_tenant), days: int = 30):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT COUNT(*) AS total,
                      COUNT(DISTINCT agent_id) AS agents_affected,
                      COUNT(DISTINCT session_id) AS sessions_affected,
                      MODE() WITHIN GROUP (ORDER BY pattern) AS top_pattern
               FROM injection_events
               WHERE tenant_id=$1
               AND created_at > NOW() - ($2||' days')::INTERVAL""",
            tenant["id"], str(days)
        )
        by_pattern = await conn.fetch(
            """SELECT pattern, COUNT(*) AS count
               FROM injection_events
               WHERE tenant_id=$1
               AND created_at > NOW() - ($2||' days')::INTERVAL
               GROUP BY pattern ORDER BY count DESC""",
            tenant["id"], str(days)
        )
    return {**dict(row), "by_pattern": [dict(r) for r in by_pattern]}

# ── Session analytics ─────────────────────────────────────────────────────────

@app.get("/sessions/{session_id}/drift")
async def session_drift_report(session_id: str, tenant=Depends(get_tenant)):
    """Show intent drift scores across a session's history."""
    async with pool.acquire() as conn:
        sess = await conn.fetchrow(
            "SELECT * FROM agent_sessions WHERE id=$1 AND tenant_id=$2",
            session_id, tenant["id"]
        )
        if not sess:
            raise HTTPException(404, "Session not found")
        calls = await conn.fetch(
            """SELECT tool, decision, turn, created_at
               FROM session_tool_calls
               WHERE session_id=$1 ORDER BY turn ASC""",
            session_id
        )
    cached = _intent_cache.get(session_id, {})
    return {
        "session_id":    session_id,
        "intent":        sess["intent"],
        "tool_calls":    len(calls),
        "deny_count":    sess["deny_count"],
        "last_drift_score": cached.get("drift_score"),
        "last_drift_reason": cached.get("reason"),
        "calls": [dict(c) for c in calls],
    }
