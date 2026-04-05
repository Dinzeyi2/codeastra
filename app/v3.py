"""
AgentGuard v3.0.0 — helpers only.
No @app decorators here. Routes are registered in main.py.
"""

import json, hashlib, time, uuid, asyncio, re
from typing import Any, Optional
from datetime import datetime, timezone

import anthropic
import httpx
import structlog

from pydantic import BaseModel

log = structlog.get_logger()

# ══════════════════════════════════════════════════════════════════════════════
# DB MIGRATIONS — called inside init_db() in main.py
# ══════════════════════════════════════════════════════════════════════════════

SESSION_MIGRATIONS = [
"""CREATE TABLE IF NOT EXISTS agent_sessions (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    agent_id             TEXT NOT NULL,
    user_id              TEXT NOT NULL,
    intent               TEXT,
    intent_embedding_hash TEXT,
    status               TEXT NOT NULL DEFAULT 'active',
    tool_call_count      INTEGER DEFAULT 0,
    deny_count           INTEGER DEFAULT 0,
    started_at           TIMESTAMPTZ DEFAULT NOW(),
    last_active_at       TIMESTAMPTZ DEFAULT NOW(),
    expires_at           TIMESTAMPTZ,
    metadata             JSONB DEFAULT '{}'
)""",
"""CREATE INDEX IF NOT EXISTS sessions_agent_idx ON agent_sessions(agent_id, status)""",
"""CREATE INDEX IF NOT EXISTS sessions_tenant_idx ON agent_sessions(tenant_id, started_at DESC)""",
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
"""CREATE INDEX IF NOT EXISTS stc_session_idx ON session_tool_calls(session_id, turn)""",
"""CREATE TABLE IF NOT EXISTS hitl_approvals (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    session_id   TEXT,
    request_id   TEXT NOT NULL,
    tool         TEXT NOT NULL,
    args         JSONB,
    reason       TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    decision     TEXT,
    decided_by   TEXT,
    decided_at   TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ NOT NULL,
    webhook_sent BOOLEAN DEFAULT FALSE,
    created_at   TIMESTAMPTZ DEFAULT NOW()
)""",
"""CREATE INDEX IF NOT EXISTS hitl_tenant_idx ON hitl_approvals(tenant_id, status, created_at DESC)""",
"""CREATE INDEX IF NOT EXISTS hitl_session_idx ON hitl_approvals(session_id, status)""",
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
"""CREATE INDEX IF NOT EXISTS injection_tenant_idx ON injection_events(tenant_id, created_at DESC)""",
"""CREATE TABLE IF NOT EXISTS tool_rate_limits (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    tool_pattern TEXT NOT NULL,
    max_calls    INTEGER NOT NULL,
    window_secs  INTEGER NOT NULL DEFAULT 3600,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, agent_id, tool_pattern)
)""",
]

# ══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS
# ══════════════════════════════════════════════════════════════════════════════

class SessionCreate(BaseModel):
    agent_id:    str
    user_id:     str
    intent:      str
    ttl_seconds: int = 3600
    metadata:    dict = {}

class SessionToolCall(BaseModel):
    tool:        str
    args:        dict[str, Any] = {}
    agent_id:    str
    user_id:     str
    session_id:  str
    context:     Optional[str] = None
    tool_result: Optional[Any] = None
    timestamp:   Optional[int] = None
    nonce:       Optional[str] = None

class HITLDecision(BaseModel):
    decision:   str
    decided_by: str
    reason:     Optional[str] = None

class ToolRateLimit(BaseModel):
    agent_id:     str
    tool_pattern: str
    max_calls:    int
    window_secs:  int = 3600

# ══════════════════════════════════════════════════════════════════════════════
# INJECTION DETECTION
# ══════════════════════════════════════════════════════════════════════════════

INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "ignore_instructions"),
    (r"disregard\s+(all\s+)?(previous|prior|above|your)\s+",      "disregard_instructions"),
    (r"you\s+are\s+now\s+(a|an)\s+",                              "persona_hijack"),
    (r"new\s+instructions?\s*:",                                   "new_instructions"),
    (r"system\s*prompt\s*:",                                       "system_prompt_leak"),
    (r"<\s*/?system\s*>",                                          "system_tag_injection"),
    (r"<\s*/?instruction\s*>",                                     "instruction_tag"),
    (r"\[INST\]|\[/INST\]",                                        "llama_injection"),
    (r"###\s*instruction",                                         "markdown_instruction"),
    (r"exfiltrate|extract\s+all\s+data|send\s+all\s+(files|data|keys)", "exfil_attempt"),
    (r"base64\s*decode|eval\s*\(|exec\s*\(",                       "code_injection"),
    (r"curl\s+http|wget\s+http|fetch\s*\(\s*['\"]http",           "ssrf_injection"),
    (r"drop\s+table|delete\s+from|truncate\s+table",              "sql_injection"),
    (r"sudo\s+|rm\s+-rf|chmod\s+777",                             "shell_injection"),
]

_INJECTION_RE = [(re.compile(pat, re.IGNORECASE), label) for pat, label in INJECTION_PATTERNS]

def scan_for_injection(content: Any, source: str = "tool_result") -> list[dict]:
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
    from app.main import pool
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO injection_events
               (id, tenant_id, agent_id, session_id, source, pattern, content, blocked)
               VALUES (gen_random_uuid()::text, $1, $2, $3, $4, $5, $6, TRUE)""",
            tenant_id, agent_id, session_id, source,
            finding["pattern"], finding["match"][:500]
        )
    log.warning("injection.detected", tenant_id=tenant_id, agent_id=agent_id,
                pattern=finding["pattern"], source=source)

# ══════════════════════════════════════════════════════════════════════════════
# SESSION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

SESSION_TTL_DEFAULT = 3600
_intent_cache: dict = {}

async def create_session(tenant_id, agent_id, user_id, intent,
                          ttl=SESSION_TTL_DEFAULT, metadata={}):
    from app.main import pool, redis_conn
    session_id  = f"sess_{uuid.uuid4().hex[:16]}"
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
    if redis_conn:
        await redis_conn.setex(
            f"ag:sess:{session_id}", ttl,
            json.dumps({"tenant_id": tenant_id, "agent_id": agent_id,
                        "user_id": user_id, "intent": intent,
                        "tool_call_count": 0, "deny_count": 0})
        )
    return {"session_id": session_id, "intent": intent, "expires_in": ttl}

async def get_session(session_id, tenant_id):
    from app.main import pool, redis_conn
    if redis_conn:
        try:
            raw = await redis_conn.get(f"ag:sess:{session_id}")
            if raw:
                data = json.loads(raw)
                if data.get("tenant_id") == tenant_id:
                    return data
        except Exception:
            pass
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT * FROM agent_sessions
               WHERE id=$1 AND tenant_id=$2
               AND status='active' AND expires_at > NOW()""",
            session_id, tenant_id
        )
    return dict(row) if row else None

async def increment_session_counters(session_id, tenant_id, decision, tool, turn):
    from app.main import pool, redis_conn
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
    if redis_conn:
        try:
            raw = await redis_conn.get(f"ag:sess:{session_id}")
            if raw:
                data = json.loads(raw)
                data["tool_call_count"] = data.get("tool_call_count", 0) + 1
                data["deny_count"]      = data.get("deny_count", 0) + deny_inc
                ttl = await redis_conn.ttl(f"ag:sess:{session_id}")
                await redis_conn.setex(f"ag:sess:{session_id}",
                                        max(ttl, 60), json.dumps(data))
        except Exception:
            pass

async def terminate_session(session_id, tenant_id, reason="manual"):
    from app.main import pool, redis_conn
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE agent_sessions SET status=$1 WHERE id=$2 AND tenant_id=$3",
            reason, session_id, tenant_id
        )
    if redis_conn:
        await redis_conn.delete(f"ag:sess:{session_id}")

# ══════════════════════════════════════════════════════════════════════════════
# INTENT DRIFT
# ══════════════════════════════════════════════════════════════════════════════

async def check_intent_drift(session, tool, args, turn):
    from app.main import pool
    session_id = session.get("id") or session.get("session_id", "")
    intent     = session.get("intent", "")
    if not intent:
        return True, "no intent set"
    last_turn = _intent_cache.get(session_id, {}).get("last_turn", 0)
    if turn - last_turn < 5 and turn > 1:
        cached = _intent_cache.get(session_id, {})
        return cached.get("ok", True), cached.get("reason", "cached")
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
                model="claude-haiku-4-5-20251001",
                max_tokens=150,
                messages=[{"role": "user", "content":
                    f"Session intent: '{intent}'\n"
                    f"Recent tools: {history}\n"
                    f"Current action: {tool}({json.dumps(args, default=str)[:200]})\n"
                    f"Turn: {turn}\n"
                    f"Is this consistent with the intent? "
                    f"JSON only: {{\"consistent\":true,\"drift_score\":0.0,\"reason\":\"brief\"}}\n"
                    f"drift_score: 0.0=perfect match, 1.0=completely unrelated"
                }]
            ),
            timeout=6.0
        )
        raw    = re.sub(r"^```(?:json)?\n?|\n?```$", "", msg.content[0].text.strip())
        result = json.loads(raw)
        drift  = float(result.get("drift_score", 0))
        ok     = drift < 0.75
        reason = result.get("reason", "")
        _intent_cache[session_id] = {"ok": ok, "reason": reason,
                                      "drift_score": drift, "last_turn": turn}
        return ok, f"drift={drift:.2f}: {reason}"
    except Exception as e:
        return True, f"drift check skipped ({type(e).__name__})"

# ══════════════════════════════════════════════════════════════════════════════
# PER-TOOL RATE LIMITER
# ══════════════════════════════════════════════════════════════════════════════

def _matches_pattern(tool, pattern):
    if pattern == "*": return True
    if pattern.endswith("*"): return tool.lower().startswith(pattern[:-1].lower())
    return tool.lower() == pattern.lower()

async def check_tool_rate_limit(tenant_id, agent_id, tool, session_id=None):
    from app.main import pool, redis_conn, _redis_ok
    async with pool.acquire() as conn:
        limits = await conn.fetch(
            """SELECT tool_pattern, max_calls, window_secs
               FROM tool_rate_limits WHERE tenant_id=$1 AND agent_id=$2""",
            tenant_id, agent_id
        )
    for row in limits:
        if not _matches_pattern(tool, row["tool_pattern"]):
            continue
        max_calls   = row["max_calls"]
        window_secs = row["window_secs"]
        now          = time.time()
        if redis_conn and await _redis_ok():
            key  = f"ag:trl:{tenant_id}:{agent_id}:{row['tool_pattern']}"
            pipe = redis_conn.pipeline()
            pipe.zremrangebyscore(key, 0, now - window_secs)
            pipe.zadd(key, {str(uuid.uuid4()): now})
            pipe.zcard(key)
            pipe.expire(key, window_secs + 10)
            results = await pipe.execute()
            count   = results[2]
        else:
            async with pool.acquire() as conn:
                count = await conn.fetchval(
                    """SELECT COUNT(*) FROM session_tool_calls
                       WHERE agent_id=$1 AND tool ILIKE $2
                       AND created_at > NOW() - ($3||' seconds')::INTERVAL""",
                    agent_id, row["tool_pattern"].replace("*", "%"), str(window_secs)
                ) or 0
        if count > max_calls:
            return False, (
                f"Tool '{tool}' rate limit exceeded: "
                f"{count}/{max_calls} calls in {window_secs}s"
            )
    return True, "ok"

# ══════════════════════════════════════════════════════════════════════════════
# HITL
# ══════════════════════════════════════════════════════════════════════════════

HITL_DEFAULT_TTL = 300

async def create_hitl_request(tenant_id, agent_id, session_id,
                               request_id, tool, args, reason, ttl=HITL_DEFAULT_TTL):
    from app.main import pool, redis_conn
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
    if redis_conn:
        await redis_conn.setex(
            f"ag:hitl:{hitl_id}", ttl + 60,
            json.dumps({"status": "pending", "tool": tool})
        )
    await _fire_hitl_webhook(tenant_id, hitl_id, tool, args, reason)
    return {
        "hitl_id":    hitl_id,
        "status":     "pending",
        "poll_url":   f"/hitl/{hitl_id}",
        "expires_in": ttl,
        "tool":       tool,
        "reason":     reason,
    }

async def _fire_hitl_webhook(tenant_id, hitl_id, tool, args, reason):
    from app.main import pool
    import hmac as _hmac
    try:
        async with pool.acquire() as conn:
            hooks = await conn.fetch(
                "SELECT url, secret FROM webhooks WHERE tenant_id=$1 "
                "AND active=TRUE AND 'hitl'=ANY(events)",
                tenant_id
            )
        if not hooks:
            return
        payload = json.dumps({
            "event":   "hitl.pending",
            "hitl_id": hitl_id,
            "tool":    tool,
            "args":    args,
            "reason":  reason,
        }, default=str).encode()
        for hook in hooks:
            sig = _hmac.new(hook["secret"].encode(), payload, __import__("hashlib").sha256).hexdigest()
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(hook["url"], content=payload, headers={
                        "Content-Type":            "application/json",
                        "x-agentguard-signature":  f"sha256={sig}",
                        "x-agentguard-event":      "hitl.pending",
                    })
                async with pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE hitl_approvals SET webhook_sent=TRUE WHERE id=$1", hitl_id
                    )
            except Exception as e:
                log.warning("hitl.webhook_failed", hitl_id=hitl_id, error=str(e))
    except Exception as e:
        log.error("hitl.webhook_error", error=str(e))

async def get_hitl_status(hitl_id, tenant_id):
    from app.main import pool, redis_conn
    if redis_conn:
        try:
            raw = await redis_conn.get(f"ag:hitl:{hitl_id}")
            if raw:
                data = json.loads(raw)
                if data.get("status") != "pending":
                    return data
        except Exception:
            pass
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM hitl_approvals WHERE id=$1 AND tenant_id=$2",
            hitl_id, tenant_id
        )
    return dict(row) if row else None

async def decide_hitl(hitl_id, tenant_id, decision, decided_by, reason):
    from app.main import pool, redis_conn
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
               SET status='decided', decision=$1, decided_by=$2, decided_at=NOW()
               WHERE id=$3""",
            decision, decided_by, hitl_id
        )
    result = {"hitl_id": hitl_id, "decision": decision,
              "decided_by": decided_by, "tool": row["tool"]}
    if redis_conn:
        await redis_conn.setex(
            f"ag:hitl:{hitl_id}", 300,
            json.dumps({**result, "status": "decided",
                        "args": json.loads(row["args"] or "{}")})
        )
    log.info("hitl.decided", hitl_id=hitl_id, decision=decision, decided_by=decided_by)
    return result

# ══════════════════════════════════════════════════════════════════════════════
# ENFORCEMENT PIPELINE v3
# ══════════════════════════════════════════════════════════════════════════════

async def run_enforcement_v3(tool, args, agent, rules, patterns, context,
                              tenant_id=None, session=None, session_id=None):
    # These come from main.py via import *
    from app.main import (check_tool, redact, check_args, _tokens,
                           SUSPICIOUS_VERBS, semantic_check, _matches)

    if isinstance(rules, str):
        rules = json.loads(rules)

    ok, reason = check_tool(tool, rules)
    if not ok:
        return False, reason, args, False, "blocked"

    clean, redacted = redact(args, patterns)
    if not isinstance(clean, dict):
        clean = {}

    ok, reason = check_args(clean, rules)
    if not ok:
        return False, reason, clean, redacted, "blocked"

    for source, content in [("args", clean), ("context", context)]:
        findings = scan_for_injection(content, source)
        if findings:
            f = findings[0]
            if tenant_id:
                asyncio.ensure_future(
                    log_injection_event(tenant_id, agent["id"], session_id, source, f)
                )
            return False, f"Injection detected in {source}: {f['pattern']}", clean, redacted, "injection_blocked"

    if tenant_id:
        rl_ok, rl_reason = await check_tool_rate_limit(tenant_id, agent["id"], tool, session_id)
        if not rl_ok:
            return False, rl_reason, clean, redacted, "rate_limited"

    toks = _tokens(tool)
    if context is not None or any(t in SUSPICIOUS_VERBS for t in toks):
        sem_ok, sem_reason = await semantic_check(tool, clean, context, agent["policy"])
        if not sem_ok:
            return False, sem_reason, clean, redacted, "blocked_semantic"

    if session:
        turn = session.get("tool_call_count", 0) + 1
        drift_ok, drift_reason = await check_intent_drift(session, tool, clean, turn)
        if not drift_ok:
            return False, f"Intent drift: {drift_reason}", clean, redacted, "intent_drift"

    hitl = rules.get("require_approval", [])
    if any(_matches(tool, p) for p in hitl):
        return False, "requires human approval", clean, redacted, "pending_approval"

    return True, "all checks passed", clean, redacted, "proceed"
