# ══════════════════════════════════════════════════════════════════════════════
# PASTE THIS ENTIRE BLOCK INTO v3.py
# Location: after run_enforcement_v3() and before SEMANTIC_MIGRATIONS
# Also: in embed_text(), replace bare `redis_conn` with:
#   from app.main import redis_conn
# ══════════════════════════════════════════════════════════════════════════════

import secrets as _secrets

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

from datetime import timedelta

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

TOKEN_PREFIX = "AG_TOKEN"
TOKEN_TTL    = 3600

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

# ══════════════════════════════════════════════════════════════════════════════
# END OF PASTE BLOCK
# ══════════════════════════════════════════════════════════════════════════════
