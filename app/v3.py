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

# ════════════════════════════════════════════════════════════════════════════
# INSTRUCTIONS
# ════════════════════════════════════════════════════════════════════════════
#
# FILE 1: app/v3.py
#   → Paste everything between the V3_PY_START and V3_PY_END markers
#     at the BOTTOM of your existing v3.py
#
# FILE 2: app/main.py
#   → 3 small changes marked with MAIN_CHANGE_1, MAIN_CHANGE_2, MAIN_CHANGE_3
#
# requirements.txt → add these 3 lines:
#   presidio-analyzer==2.2.354
#   presidio-anonymizer==2.2.354
#   spacy==3.7.4
#
# After first deploy, run once in Railway shell:
#   python -m spacy download en_core_web_sm
#
# ════════════════════════════════════════════════════════════════════════════


# ════════════════════════════════════════════════════════════════════════════
# V3_PY_START — paste at the bottom of app/v3.py
# ════════════════════════════════════════════════════════════════════════════

GUARDRAIL_MIGRATIONS = [
"""CREATE TABLE IF NOT EXISTS pii_token_store (
    token       TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    real_value  TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
)""",
"""CREATE INDEX IF NOT EXISTS pii_token_tenant_idx ON pii_token_store(tenant_id, expires_at)""",
"""CREATE TABLE IF NOT EXISTS topic_policies (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    direction   TEXT NOT NULL DEFAULT 'both',
    action      TEXT NOT NULL DEFAULT 'block',
    keywords    TEXT[] NOT NULL DEFAULT '{}',
    description TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, name)
)""",
"""CREATE TABLE IF NOT EXISTS guardrail_events (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id   TEXT NOT NULL,
    agent_id    TEXT,
    session_id  TEXT,
    direction   TEXT NOT NULL,
    layer       TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT,
    content     TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
)""",
"""CREATE INDEX IF NOT EXISTS guardrail_tenant_idx ON guardrail_events(tenant_id, created_at DESC)""",
"""CREATE TABLE IF NOT EXISTS grounding_sources (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id    TEXT NOT NULL,
    session_id   TEXT,
    agent_id     TEXT,
    content      TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    expires_at   TIMESTAMPTZ
)""",
"""CREATE INDEX IF NOT EXISTS grounding_session_idx ON grounding_sources(session_id, tenant_id)""",
]

# ── New Pydantic models ───────────────────────────────────────────────────────

class TopicPolicy(BaseModel):
    name:        str
    direction:   str = "both"
    action:      str = "block"
    keywords:    list[str] = []
    description: str = ""

class GroundingSource(BaseModel):
    content:     str
    session_id:  Optional[str] = None
    agent_id:    Optional[str] = None
    ttl_seconds: int = 3600

class ProxyRequestV31(BaseModel):
    agent_id:            str
    user_id:             str
    task_id:             Optional[str] = None
    session_id:          Optional[str] = None
    model:               str = "claude-sonnet-4-6"
    messages:            list[dict]
    system:              Optional[str] = None
    max_tokens:          int = 1024
    temperature:         float = 1.0
    provider:            str = "anthropic"
    tokenize_pii:        bool = True
    scan_output:         bool = True
    check_grounding:     bool = False
    grounding_threshold: float = 0.3
    dry_run:             bool = False

class OutputScanRequest(BaseModel):
    content:    str
    agent_id:   Optional[str] = None
    session_id: Optional[str] = None

# ── PII Tokenizer ─────────────────────────────────────────────────────────────

import secrets as _secrets

_presidio_analyzer   = None
_presidio_anonymizer = None

def _get_presidio():
    global _presidio_analyzer, _presidio_anonymizer
    if _presidio_analyzer is None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine
            _presidio_analyzer   = AnalyzerEngine()
            _presidio_anonymizer = AnonymizerEngine()
        except ImportError:
            pass
    return _presidio_analyzer, _presidio_anonymizer

PII_ENTITIES = [
    "PHONE_NUMBER","CREDIT_CARD","EMAIL_ADDRESS","US_SSN",
    "US_PASSPORT","US_DRIVER_LICENSE","IBAN_CODE","IP_ADDRESS",
    "PERSON","LOCATION",
]
TOKEN_PREFIX = "AG_TOKEN"
TOKEN_TTL    = 3600

async def tokenize_pii(text: str, tenant_id: str, ttl: int = TOKEN_TTL):
    analyzer, _ = _get_presidio()
    if not analyzer:
        return text, {}
    try:
        results = analyzer.analyze(text=text, entities=PII_ENTITIES, language="en")
        if not results:
            return text, {}
        token_map = {}
        tokenized = text
        for result in sorted(results, key=lambda r: r.start, reverse=True):
            real_value  = text[result.start:result.end]
            token       = f"{TOKEN_PREFIX}_{_secrets.token_hex(8).upper()}"
            entity_type = result.entity_type
            await _store_token(token, real_value, entity_type, tenant_id, ttl)
            tokenized = tokenized[:result.start] + token + tokenized[result.end:]
            token_map[token] = entity_type
        return tokenized, token_map
    except Exception as e:
        log.error("tokenize.failed", error=str(e))
        return text, {}

async def detokenize(text: str, tenant_id: str) -> str:
    if TOKEN_PREFIX not in text:
        return text
    token_pattern = re.compile(rf"{TOKEN_PREFIX}_[A-F0-9]{{16}}")
    tokens = token_pattern.findall(text)
    if not tokens:
        return text
    result = text
    for token in set(tokens):
        real_value = await _resolve_token(token, tenant_id)
        if real_value:
            result = result.replace(token, real_value)
    return result

async def _store_token(token, real_value, entity_type, tenant_id, ttl):
    from app.main import pool, redis_conn
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    if redis_conn:
        try:
            await redis_conn.setex(f"ag:tok:{token}", ttl,
                json.dumps({"real": real_value, "type": entity_type, "tid": tenant_id}))
        except Exception:
            pass
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO pii_token_store (token,tenant_id,entity_type,real_value,expires_at)"
            " VALUES ($1,$2,$3,$4,$5) ON CONFLICT (token) DO NOTHING",
            token, tenant_id, entity_type, real_value, expires_at
        )

async def _resolve_token(token, tenant_id):
    from app.main import pool, redis_conn
    if redis_conn:
        try:
            raw = await redis_conn.get(f"ag:tok:{token}")
            if raw:
                data = json.loads(raw)
                if data.get("tid") == tenant_id:
                    return data["real"]
        except Exception:
            pass
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT real_value FROM pii_token_store WHERE token=$1 AND tenant_id=$2 AND expires_at > NOW()",
            token, tenant_id
        )
    return row["real_value"] if row else None

# ── Topic firewall ────────────────────────────────────────────────────────────

BUILTIN_TOPIC_BLOCKS = [
    {"name": "jailbreak",       "keywords": ["ignore previous instructions","ignore all instructions","disregard your instructions","you are now","your new instructions","forget everything","pretend you have no restrictions"]},
    {"name": "prompt_injection", "keywords": ["system prompt","system override","admin mode","developer mode","jailbreak","dan mode","ignore the above"]},
    {"name": "harmful_content",  "keywords": ["how to make a bomb","synthesize drugs","create malware","bypass security","exploit vulnerability"]},
]

async def check_topic_policy(text, direction, tenant_id, agent_id=None, session_id=None):
    text_lower = text.lower()
    for topic in BUILTIN_TOPIC_BLOCKS:
        for keyword in topic["keywords"]:
            if keyword in text_lower:
                await _log_guardrail_event(tenant_id, agent_id, session_id, direction,
                    "topic_firewall", "blocked",
                    f"Built-in policy '{topic['name']}': '{keyword}'", text[:200])
                return False, f"Content blocked by policy '{topic['name']}'", topic["name"]
    from app.main import pool
    async with pool.acquire() as conn:
        policies = await conn.fetch(
            "SELECT name, keywords, action FROM topic_policies"
            " WHERE tenant_id=$1 AND (direction=$2 OR direction='both')",
            tenant_id, direction
        )
    for policy in policies:
        for keyword in (policy["keywords"] or []):
            if keyword.lower() in text_lower:
                await _log_guardrail_event(tenant_id, agent_id, session_id, direction,
                    "topic_firewall", policy["action"],
                    f"Policy '{policy['name']}': '{keyword}'", text[:200])
                if policy["action"] == "block":
                    return False, f"Blocked by policy '{policy['name']}'", policy["name"]
    return True, "ok", ""

# ── Output gate ───────────────────────────────────────────────────────────────

OUTPUT_PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                                    "SSN"),
    (re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),                              "CREDIT_CARD"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),      "EMAIL"),
    (re.compile(r"(?i)\b(?:password|secret|api.?key|token)\s*[:=]\s*\S{8,}"), "SECRET"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "PHONE"),
]

async def scan_output(response_text, tenant_id, agent_id=None, session_id=None):
    findings = []; cleaned = response_text; modified = False
    for pattern, label in OUTPUT_PII_PATTERNS:
        matches = pattern.findall(cleaned)
        if matches:
            cleaned  = pattern.sub(f"[{label} REDACTED]", cleaned)
            modified = True
            findings.append({"type": "pii", "label": label, "count": len(matches)})
    topic_ok, topic_reason, policy_name = await check_topic_policy(
        cleaned, "output", tenant_id, agent_id, session_id)
    if not topic_ok:
        findings.append({"type": "topic", "policy": policy_name})
        cleaned  = f"[RESPONSE BLOCKED: {topic_reason}]"
        modified = True
    injection_findings = scan_for_injection(cleaned, "llm_output")
    if injection_findings:
        for f in injection_findings:
            findings.append({"type": "injection_in_output", "pattern": f["pattern"]})
        cleaned  = "[RESPONSE BLOCKED: Injection detected in LLM output]"
        modified = True
    if findings:
        await _log_guardrail_event(tenant_id, agent_id, session_id, "output",
            "output_gate", "modified" if modified else "allowed",
            json.dumps(findings), response_text[:200])
    return cleaned, findings, modified

# ── Grounding check ───────────────────────────────────────────────────────────

async def store_grounding_source(tenant_id, content, session_id=None, agent_id=None, ttl=3600):
    from app.main import pool
    source_id    = str(uuid.uuid4())
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    expires_at   = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO grounding_sources (id,tenant_id,session_id,agent_id,content,content_hash,expires_at)"
            " VALUES ($1,$2,$3,$4,$5,$6,$7)",
            source_id, tenant_id, session_id, agent_id, content, content_hash, expires_at
        )
    return source_id

async def check_grounding(response_text, tenant_id, session_id=None, agent_id=None, threshold=0.3):
    from app.main import pool
    async with pool.acquire() as conn:
        sources = await conn.fetch(
            "SELECT content FROM grounding_sources"
            " WHERE tenant_id=$1 AND (session_id=$2 OR session_id IS NULL)"
            " AND expires_at > NOW() ORDER BY created_at DESC LIMIT 5",
            tenant_id, session_id
        )
    if not sources:
        return True, 1.0, "no sources registered"
    source_text = "\n\n---\n\n".join(r["content"] for r in sources)[:6000]
    try:
        client = anthropic.AsyncAnthropic()
        msg = await asyncio.wait_for(
            client.messages.create(
                model="claude-haiku-4-5-20251001", max_tokens=200,
                messages=[{"role": "user", "content":
                    f"You are a grounding verifier.\n\n"
                    f"SOURCE DOCUMENTS:\n{source_text}\n\n"
                    f"RESPONSE TO CHECK:\n{response_text[:1000]}\n\n"
                    f"Is the response grounded in the sources? "
                    f"JSON only: {{\"grounded\":true,\"confidence\":0.9,\"reason\":\"brief\"}}"
                }]
            ), timeout=8.0
        )
        raw    = re.sub(r"^```(?:json)?\n?|\n?```$", "", msg.content[0].text.strip())
        result = json.loads(raw)
        grounded   = bool(result.get("grounded", True))
        confidence = float(result.get("confidence", 1.0))
        reason     = result.get("reason", "")
        is_ok      = grounded and confidence >= threshold
        await _log_guardrail_event(tenant_id, agent_id, session_id, "output",
            "grounding_check", "passed" if is_ok else "failed",
            f"confidence={confidence:.2f}: {reason}", response_text[:200])
        return is_ok, confidence, reason
    except Exception as e:
        return True, 1.0, f"check skipped: {type(e).__name__}"

# ── Guardrail event logger ────────────────────────────────────────────────────

async def _log_guardrail_event(tenant_id, agent_id, session_id,
                                direction, layer, action, detail, content=None):
    from app.main import pool
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO guardrail_events"
                " (tenant_id,agent_id,session_id,direction,layer,action,detail,content)"
                " VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
                tenant_id, agent_id, session_id,
                direction, layer, action, detail, content
            )
    except Exception as e:
        log.error("guardrail_event.log_failed", error=str(e))

# ── Full pipeline helpers ─────────────────────────────────────────────────────

async def run_input_guardrails(messages, system, tenant_id, agent_id, session_id, tokenize=True):
    report = {"pii_tokenized": 0, "topics_blocked": False, "injections_blocked": False}
    safe_messages = []
    for msg in messages:
        content = msg.get("content", "")
        if not isinstance(content, str):
            safe_messages.append(msg); continue
        topic_ok, topic_reason, policy_name = await check_topic_policy(
            content, "input", tenant_id, agent_id, session_id)
        if not topic_ok:
            report["topics_blocked"] = True
            return None, None, {**report, "blocked": True, "reason": topic_reason, "layer": "topic_firewall"}
        findings = scan_for_injection(content, "user_input")
        if findings:
            report["injections_blocked"] = True
            return None, None, {**report, "blocked": True,
                                "reason": f"Injection: {findings[0]['pattern']}", "layer": "injection_scan"}
        if tokenize:
            safe_content, token_map = await tokenize_pii(content, tenant_id)
            report["pii_tokenized"] += len(token_map)
        else:
            safe_content = content
        safe_messages.append({**msg, "content": safe_content})
    safe_system = system
    if system and tokenize:
        safe_system, _ = await tokenize_pii(system, tenant_id)
    report["blocked"] = False
    return safe_messages, safe_system, report

async def run_output_guardrails(response_text, tenant_id, agent_id, session_id,
                                 detokenize_pii=True, check_ground=False, grounding_threshold=0.3):
    report = {"pii_detokenized": False, "output_modified": False,
              "grounding_passed": True, "findings": []}
    safe_response = response_text
    if detokenize_pii and TOKEN_PREFIX in safe_response:
        safe_response = await detokenize(safe_response, tenant_id)
        report["pii_detokenized"] = True
    safe_response, findings, modified = await scan_output(
        safe_response, tenant_id, agent_id, session_id)
    report["output_modified"] = modified
    report["findings"]        = findings
    if check_ground:
        grounded, confidence, reason = await check_grounding(
            safe_response, tenant_id, session_id, agent_id, grounding_threshold)
        report["grounding_passed"]     = grounded
        report["grounding_confidence"] = round(confidence, 3)
        report["grounding_reason"]     = reason
        if not grounded:
            safe_response = (
                f"[GROUNDING WARNING: {confidence:.0%} confidence — "
                f"response may not be supported by source documents. {reason}]\n\n"
                + safe_response
            )
    return safe_response, report

# ════════════════════════════════════════════════════════════════════════════
# V3_PY_END
# ════════════════════════════════════════════════════════════════════════════


# ════════════════════════════════════════════════════════════════════════════
# MAIN_CHANGE_1 — update the import block at the top of main.py
# Find: from app.v3 import (
# Replace the entire import block with this:
# ════════════════════════════════════════════════════════════════════════════

"""
from app.v3 import (
    SESSION_MIGRATIONS,
    SessionCreate, SessionToolCall, HITLDecision, ToolRateLimit,
    scan_for_injection, log_injection_event,
    create_session, get_session, increment_session_counters, terminate_session,
    check_intent_drift, check_tool_rate_limit,
    create_hitl_request, get_hitl_status, decide_hitl,
    run_enforcement_v3, _intent_cache,
    # v3.1 guardrails
    GUARDRAIL_MIGRATIONS,
    TopicPolicy, GroundingSource, ProxyRequestV31, OutputScanRequest,
    tokenize_pii, detokenize, check_topic_policy,
    scan_output, store_grounding_source, check_grounding,
    run_input_guardrails, run_output_guardrails,
    _log_guardrail_event,
)
"""

# ════════════════════════════════════════════════════════════════════════════
# MAIN_CHANGE_2 — add GUARDRAIL_MIGRATIONS inside init_db()
# Find the line: for _sql in SESSION_MIGRATIONS:
# Add AFTER that block (still inside init_db, inside conn block):
# ════════════════════════════════════════════════════════════════════════════

"""
        for _sql in GUARDRAIL_MIGRATIONS:
            await conn.execute(_sql)
"""

# ════════════════════════════════════════════════════════════════════════════
# MAIN_CHANGE_3 — add new endpoints at the bottom of main.py
# Paste everything below before the final @app.get("/health") endpoint
# ════════════════════════════════════════════════════════════════════════════

NEW_ENDPOINTS_FOR_MAIN = '''
# ══════════════════════════════════════════════════════════════════════════════
# GUARDRAILS v3.1
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/guardrails/topics")
async def create_topic_policy(body: TopicPolicy, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO topic_policies (tenant_id,name,direction,action,keywords,description)
               VALUES ($1,$2,$3,$4,$5,$6)
               ON CONFLICT (tenant_id,name) DO UPDATE
               SET direction=$3,action=$4,keywords=$5,description=$6""",
            tenant["id"], body.name, body.direction, body.action,
            body.keywords, body.description
        )
    return {"name": body.name, "direction": body.direction,
            "action": body.action, "keywords": body.keywords}

@app.get("/guardrails/topics")
async def list_topic_policies(tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM topic_policies WHERE tenant_id=$1 ORDER BY name", tenant["id"])
    return [dict(r) for r in rows]

@app.delete("/guardrails/topics/{name}")
async def delete_topic_policy(name: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        res = await conn.execute("DELETE FROM topic_policies WHERE tenant_id=$1 AND name=$2", tenant["id"], name)
    if res == "DELETE 0": raise HTTPException(404, "Policy not found")
    return {"deleted": name}

@app.post("/guardrails/grounding")
async def add_grounding_source(body: GroundingSource, tenant=Depends(get_tenant)):
    source_id = await store_grounding_source(
        tenant["id"], body.content, body.session_id, body.agent_id, body.ttl_seconds)
    return {"source_id": source_id, "content_length": len(body.content),
            "expires_in": body.ttl_seconds}

@app.get("/guardrails/grounding")
async def list_grounding_sources(tenant=Depends(get_tenant), session_id: Optional[str]=None):
    where = "WHERE tenant_id=$1 AND expires_at > NOW()"
    vals  = [tenant["id"]]
    if session_id: where += " AND session_id=$2"; vals.append(session_id)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT id,session_id,agent_id,content_hash,created_at,expires_at FROM grounding_sources {where} ORDER BY created_at DESC",
            *vals)
    return [dict(r) for r in rows]

@app.post("/guardrails/scan-output")
async def scan_output_endpoint(body: OutputScanRequest, tenant=Depends(get_tenant)):
    safe, findings, modified = await scan_output(
        body.content, tenant["id"], body.agent_id, body.session_id)
    return {"safe_content": safe, "findings": findings, "modified": modified}

@app.get("/guardrails/events")
async def list_guardrail_events(tenant=Depends(get_tenant), layer: Optional[str]=None,
                                  direction: Optional[str]=None, days: int=7, limit: int=100):
    where = "WHERE tenant_id=$1 AND created_at > NOW() - ($2||\\' days\\')::INTERVAL"
    vals  = [tenant["id"], str(days)]
    if layer:     where += f" AND layer=${len(vals)+1}";     vals.append(layer)
    if direction: where += f" AND direction=${len(vals)+1}"; vals.append(direction)
    vals.append(min(limit, 500))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT * FROM guardrail_events {where} ORDER BY created_at DESC LIMIT ${len(vals)}", *vals)
    return [dict(r) for r in rows]

@app.get("/guardrails/stats")
async def guardrail_stats(tenant=Depends(get_tenant), days: int=30):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT COUNT(*) AS total_events,
                COUNT(*) FILTER (WHERE layer=\'topic_firewall\') AS topic_blocks,
                COUNT(*) FILTER (WHERE layer=\'output_gate\') AS output_scans,
                COUNT(*) FILTER (WHERE layer=\'grounding_check\') AS grounding_checks,
                COUNT(*) FILTER (WHERE layer=\'grounding_check\' AND action=\'failed\') AS grounding_failures,
                COUNT(*) FILTER (WHERE action IN (\'blocked\',\'modified\')) AS total_interventions
               FROM guardrail_events
               WHERE tenant_id=$1 AND created_at > NOW() - ($2||\\' days\\')::INTERVAL""",
            tenant["id"], str(days))
        by_layer = await conn.fetch(
            "SELECT layer, action, COUNT(*) AS count FROM guardrail_events"
            " WHERE tenant_id=$1 AND created_at > NOW() - ($2||\\' days\\')::INTERVAL"
            " GROUP BY layer, action ORDER BY count DESC",
            tenant["id"], str(days))
    return {**dict(row), "by_layer": [dict(r) for r in by_layer]}

@app.post("/proxy/chat/v2")
@limiter.limit("300/minute;30/second")
async def proxy_chat_v2(req: ProxyRequestV31, request: Request,
                          bg: BackgroundTasks, tenant=Depends(get_tenant)):
    """
    Full bidirectional guardrail proxy.
    Input:  topic firewall → injection scan → PII tokenization
    LLM
    Output: PII detokenization → output gate scan → grounding check
    """
    start = time.monotonic()
    tid   = tenant["id"]

    safe_messages, safe_system, input_report = await run_input_guardrails(
        req.messages, req.system, tid, req.agent_id, req.session_id,
        tokenize=req.tokenize_pii
    )

    if input_report.get("blocked"):
        ms = int((time.monotonic() - start) * 1000)
        return JSONResponse(status_code=400, content={
            "allowed": False, "blocked_at": "input",
            "reason": input_report["reason"],
            "layer":  input_report["layer"],
            "duration_ms": ms,
        })

    if req.dry_run:
        return {"dry_run": True, "input_report": input_report,
                "messages_after_guardrails": len(safe_messages)}

    try:
        client = anthropic.AsyncAnthropic()
        build_kwargs = dict(model=req.model, max_tokens=req.max_tokens, messages=safe_messages)
        if safe_system: build_kwargs["system"] = safe_system
        msg = await asyncio.wait_for(client.messages.create(**build_kwargs), timeout=120.0)
        llm_response      = msg.content[0].text if msg.content else ""
        prompt_tokens     = msg.usage.input_tokens
        completion_tokens = msg.usage.output_tokens
    except Exception as e:
        log.error("proxy_v2.llm_error", error=str(e))
        return JSONResponse(status_code=502, content={"error": f"LLM error: {type(e).__name__}"})

    safe_response, output_report = await run_output_guardrails(
        llm_response, tid, req.agent_id, req.session_id,
        detokenize_pii=req.tokenize_pii,
        check_ground=req.check_grounding,
        grounding_threshold=req.grounding_threshold,
    )

    ms = int((time.monotonic() - start) * 1000)
    LATENCY.labels(endpoint="proxy_v2").observe(ms / 1000)

    return {
        "content": safe_response,
        "model":   req.model,
        "usage": {
            "prompt_tokens":     prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens":      prompt_tokens + completion_tokens,
        },
        "guardrails": {"input": input_report, "output": output_report},
        "duration_ms": ms,
    }
'''
