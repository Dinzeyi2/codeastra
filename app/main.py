"""
AgentGuard v3.6.0
"""
import os, uuid, json, hashlib, re, time, socket, ipaddress, asyncio, secrets
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from base64 import b64decode, b64encode
from typing import Any, Optional, AsyncIterator
from urllib.parse import urlparse

import anthropic
import httpx
import redis.asyncio as aioredis
import structlog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI, HTTPException, Header, Request, Depends, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bcrypt as _bcrypt
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from tenacity import AsyncRetrying, stop_after_attempt, wait_exponential, retry_if_exception_type
from pydantic import BaseModel
import asyncpg

# ── v3 imports (all versions) ─────────────────────────────────────────────────
from app.model_router import (
    route_completion, route_stream, validate_model,
    list_ollama_models, PROVIDER_MAP, detect_provider,
)
from app.v3 import (
    # v3.0 — sessions, HITL, injection, rate limits, enforcement
    SESSION_MIGRATIONS,
    SessionCreate, SessionToolCall, HITLDecision, ToolRateLimit,
    scan_for_injection, log_injection_event,
    create_session, get_session, increment_session_counters, terminate_session,
    check_intent_drift, check_tool_rate_limit,
    create_hitl_request, get_hitl_status, decide_hitl,
    run_enforcement_v3, _intent_cache,
    # v3.1 — bidirectional guardrails, PII tokenization, topic firewall, grounding
    GUARDRAIL_MIGRATIONS,
    TopicPolicy, GroundingSource, ProxyRequestV31, OutputScanRequest,
    tokenize_pii, detokenize, check_topic_policy,
    scan_output, store_grounding_source, check_grounding,
    run_input_guardrails, run_output_guardrails,
    _log_guardrail_event, TOKEN_PREFIX,
    # v3.2 — semantic topic classifier
    SEMANTIC_MIGRATIONS,
    SemanticTopicPolicy, SemanticCheckRequest,
    semantic_topic_check, run_semantic_guardrails,
    run_output_semantic_guardrails,
    embed_text, cosine_similarity,
    BUILTIN_SEMANTIC_POLICIES, _get_policy_embedding,
    _embedding_cache,
    # v3.3 — ephemeral certs + AST policy synthesis
    CERT_MIGRATIONS,
    mint_session_cert, verify_session_cert, revoke_session_cert,
    get_session_cert, log_cert_request,
    synthesize_policy_from_code,
    PolicySynthesisRequest, PolicySynthesisResult,
    CertVerifyRequest,
    # v3.4 — citation grounding, conflict detection, vector anchoring, honey-tools
    V34_MIGRATIONS,
    CitationGroundingResult, check_grounding_with_citations,
    PolicyConflictReport, detect_policy_conflicts,
    AnchorCheckResult, anchor_session_intent, check_intent_anchor,
    HoneyToolConfig, generate_honey_tools, inject_honey_tools,
    check_honey_tool_call, HONEY_TOOL_PREFIX,
    run_enforcement_v34,
    _get_honey_tools,
    # v3.5 — streaming + multi-model
    V35_MIGRATIONS,
    StreamProxyRequest,
    build_sse_event, sse_token, sse_done, sse_error, sse_blocked, sse_guardrail,
    run_streaming_guardrails,
    _log_model_usage,
    # v3.5 option C — passthrough streaming + internal model config
    V35_MIGRATIONS,
    SecurityModelConfig, StreamPassthroughRequest,
    get_tenant_security_model, call_security_llm,
    proxy_stream_generator, invalidate_security_cache,
    # v3.6 — no-training headers + ZDR + data privacy
    V36_MIGRATIONS,
    DataPrivacyConfig, PrivacyAuditEntry,
    get_tenant_privacy_config, enforce_privacy_headers,
    wrap_anthropic_with_privacy, wrap_openai_with_privacy,
    wrap_gemini_with_privacy, privacy_compliant_call,
    privacy_compliant_stream, invalidate_privacy_cache,
    PROVIDER_PRIVACY_FACTS, _compute_compliance_score,
)

# ── Logging ───────────────────────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(20),
)
log = structlog.get_logger()

# ── Config ────────────────────────────────────────────────────────────────────
ADMIN_API_KEY      = os.environ.get("AGENTGUARD_API_KEY",  "dev-key-change-me")
AGENTGUARD_ENV     = os.environ.get("AGENTGUARD_ENV",      "dev")
IS_PROD            = AGENTGUARD_ENV == "prod"
REPLAY_WINDOW_SECS = 30
JWT_SECRET         = os.environ.get("JWT_SECRET", "dev-jwt-secret-change-me")
JWT_EXPIRE_HOURS   = 24

_ah = os.environ.get("AGENTGUARD_ALLOWED_HOSTS", "")
ALLOWED_INVOKE_HOSTS: set[str] = set(h.strip() for h in _ah.split(",") if h.strip())

# ── Prometheus ────────────────────────────────────────────────────────────────
REQUESTS_TOTAL   = Counter("agentguard_requests_total",       "Requests", ["endpoint","decision","tenant"])
LATENCY          = Histogram("agentguard_latency_seconds",    "Latency",  ["endpoint"], buckets=[.01,.025,.05,.1,.25,.5,1,2.5,5])
SEMANTIC_CALLS   = Counter("agentguard_semantic_calls_total", "Semantic checks", ["cached","result"])
ANTHROPIC_ERRORS = Counter("agentguard_anthropic_errors_total", "Anthropic errors")
REDIS_ERRORS     = Counter("agentguard_redis_errors_total",   "Redis errors")

bearer  = HTTPBearer(auto_error=False)
limiter = Limiter(key_func=get_remote_address)

# ── DB + Redis ────────────────────────────────────────────────────────────────
pool:       asyncpg.Pool   = None
redis_conn: aioredis.Redis = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool, redis_conn
    pool = await asyncpg.create_pool(os.environ["DATABASE_URL"], min_size=2, max_size=10)
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        redis_conn = await aioredis.from_url(redis_url, decode_responses=True,
                                              socket_connect_timeout=3, socket_timeout=2)
        try:
            await redis_conn.ping()
            log.info("redis.connected")
        except Exception as e:
            log.error("redis.failed", error=str(e))
            if IS_PROD:
                raise RuntimeError("Redis required in prod") from e
    elif IS_PROD:
        raise RuntimeError("REDIS_URL required in prod")
    await init_db()
    log.info("agentguard.started", version="3.6.0", env=AGENTGUARD_ENV)
    yield
    await pool.close()
    if redis_conn:
        await redis_conn.aclose()

async def init_db():
    async with pool.acquire() as conn:
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'starter',
            api_key TEXT UNIQUE NOT NULL, sso_provider TEXT, sso_id TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )""")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, policy TEXT NOT NULL DEFAULT 'default',
            public_key TEXT, allowed_hosts TEXT[], revoked BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
        )""")
        await conn.execute("""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name='agents' AND column_name='tenant_id')
            THEN ALTER TABLE agents ADD COLUMN tenant_id TEXT; END IF;
        END $$""")
        await conn.execute("CREATE INDEX IF NOT EXISTS agents_tenant_idx ON agents(tenant_id)")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_key_history (
            id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, tenant_id TEXT,
            public_key TEXT NOT NULL, rotated_at TIMESTAMPTZ DEFAULT NOW(), reason TEXT
        )""")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY, name TEXT NOT NULL,
            rules JSONB NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW()
        )""")
        await conn.execute("""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name='policies' AND column_name='tenant_id')
            THEN ALTER TABLE policies ADD COLUMN tenant_id TEXT; END IF;
        END $$""")
        await conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS policies_tenant_name_idx
        ON policies(tenant_id, name) WHERE tenant_id IS NOT NULL""")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY, request_id TEXT, agent_id TEXT, user_id TEXT,
            tool TEXT NOT NULL, args JSONB, decision TEXT NOT NULL, reason TEXT,
            redacted BOOLEAN DEFAULT FALSE, duration_ms INTEGER,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )""")
        await conn.execute("""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name='audit_logs' AND column_name='tenant_id')
            THEN ALTER TABLE audit_logs ADD COLUMN tenant_id TEXT; END IF;
        END $$""")
        await conn.execute("""
        CREATE INDEX IF NOT EXISTS audit_tenant_idx
        ON audit_logs(tenant_id, created_at DESC) WHERE tenant_id IS NOT NULL""")
        await conn.execute("""
        CREATE INDEX IF NOT EXISTS audit_agent_idx ON audit_logs(agent_id, created_at DESC)""")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS anomaly_alerts (
            id TEXT PRIMARY KEY, tenant_id TEXT, agent_id TEXT,
            alert_type TEXT NOT NULL, detail TEXT, resolved BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )""")
        await conn.execute("""
        CREATE INDEX IF NOT EXISTS anomaly_tenant_idx
        ON anomaly_alerts(tenant_id, created_at DESC) WHERE tenant_id IS NOT NULL""")
        await conn.execute("""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name='tenants' AND column_name='retention_days')
            THEN ALTER TABLE tenants ADD COLUMN retention_days INTEGER DEFAULT 90; END IF;
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name='tenants' AND column_name='api_call_count')
            THEN ALTER TABLE tenants ADD COLUMN api_call_count INTEGER DEFAULT 0; END IF;
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name='tenants' AND column_name='last_seen_at')
            THEN ALTER TABLE tenants ADD COLUMN last_seen_at TIMESTAMPTZ; END IF;
        END $$""")
        await conn.execute("""CREATE TABLE IF NOT EXISTS policy_history (
            id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
            policy_name TEXT NOT NULL, rules JSONB NOT NULL,
            changed_at TIMESTAMPTZ DEFAULT NOW())""")
        await conn.execute("""CREATE TABLE IF NOT EXISTS webhooks (
            id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
            url TEXT NOT NULL, events TEXT[] NOT NULL, secret TEXT NOT NULL,
            active BOOLEAN DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT NOW())""")

        # v3.0 — sessions, HITL, injection detection, rate limits
        for _sql in SESSION_MIGRATIONS:
            await conn.execute(_sql)
        # v3.1 — guardrails: PII tokens, topic policies, guardrail events, grounding
        for _sql in GUARDRAIL_MIGRATIONS:
            await conn.execute(_sql)
        # v3.2 — semantic classifier tables
        for _sql in SEMANTIC_MIGRATIONS:
            await conn.execute(_sql)
        # v3.3 — ephemeral certs + synthesized policies
        for _sql in CERT_MIGRATIONS:
            await conn.execute(_sql)
        # v3.4 — citation grounding, conflict detection, vector anchoring, honey-tools
        for _sql in V34_MIGRATIONS:
            await conn.execute(_sql)
        # v3.5 — multi-model support + streaming
        for _sql in V35_MIGRATIONS:
            await conn.execute(_sql)
        # v3.6 — no-training headers + ZDR + data privacy enforcement
        for _sql in V36_MIGRATIONS:
            await conn.execute(_sql)

# ── Pydantic models ───────────────────────────────────────────────────────────
class TenantSignup(BaseModel):
    name: str; email: str; password: str

class TenantLogin(BaseModel):
    email: str; password: str

class AgentCreate(BaseModel):
    name: str; policy: str = "default"; allowed_hosts: list[str] = []

class RegisterKeyRequest(BaseModel):
    public_key: str; policy: Optional[str] = None
    allowed_hosts: Optional[list[str]] = None; rotation_reason: Optional[str] = None

class PolicyCreate(BaseModel):
    name: str; rules: dict

class ProtectRequest(BaseModel):
    tool: str; args: dict[str, Any] = {}; agent_id: str; user_id: str
    context: Optional[str] = None; timestamp: Optional[int] = None; nonce: Optional[str] = None

class InvokeRequest(BaseModel):
    tool: str; args: dict[str, Any] = {}; agent_id: str; user_id: str
    context: Optional[str] = None; target_url: str
    timestamp: Optional[int] = None; nonce: Optional[str] = None

# ── JWT ───────────────────────────────────────────────────────────────────────
def create_jwt(tenant_id: str) -> str:
    import hmac as _hmac, base64 as _b64
    header  = _b64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b"=").decode()
    exp     = int((datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)).timestamp())
    payload = _b64.urlsafe_b64encode(json.dumps({"sub": tenant_id, "exp": exp}).encode()).rstrip(b"=").decode()
    msg     = f"{header}.{payload}".encode()
    sig     = _b64.urlsafe_b64encode(_hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"

def decode_jwt(token: str) -> str:
    import hmac as _hmac, base64 as _b64
    try:
        parts = token.split(".")
        if len(parts) != 3: raise ValueError("bad token")
        header_b, payload_b, sig_b = parts
        msg      = f"{header_b}.{payload_b}".encode()
        expected = _b64.urlsafe_b64encode(_hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest()).rstrip(b"=").decode()
        if not _hmac.compare_digest(expected, sig_b): raise ValueError("bad sig")
        pad     = "=" * (-len(payload_b) % 4)
        payload = json.loads(_b64.urlsafe_b64decode(payload_b + pad))
        if payload["exp"] < int(datetime.now(timezone.utc).timestamp()): raise ValueError("expired")
        return payload["sub"]
    except Exception:
        raise HTTPException(401, "Invalid or expired token")

async def get_tenant(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    x_api_key: Optional[str] = Header(None),
) -> asyncpg.Record:
    tenant = None
    async with pool.acquire() as conn:
        if creds:
            tenant_id = decode_jwt(creds.credentials)
            tenant = await conn.fetchrow("SELECT * FROM tenants WHERE id=$1", tenant_id)
        elif x_api_key:
            tenant = await conn.fetchrow("SELECT * FROM tenants WHERE api_key=$1", x_api_key)
            if tenant:
                await conn.execute(
                    "UPDATE tenants SET api_call_count=COALESCE(api_call_count,0)+1, last_seen_at=NOW() WHERE id=$1",
                    tenant["id"]
                )
        if not tenant and x_api_key == ADMIN_API_KEY:
            class AdminTenant(dict):
                def __getitem__(self, k):
                    return {"id":"__admin__","plan":"enterprise","tenant_id":"__admin__","retention_days":90,"api_call_count":0}.get(k)
                def get(self, k, default=None):
                    try: return self[k]
                    except: return default
            return AdminTenant()
    if not tenant:
        raise HTTPException(401, "Authentication required")
    return tenant

# ── Seed policies ─────────────────────────────────────────────────────────────
DEFAULT_POLICIES = [
    ("default", {"allow_tools":[],"deny_tools":[],"max_records":100,"require_approval":[],"read_only":False,
                 "redact_patterns":[r"\b\d{3}-\d{2}-\d{4}\b",r"\b4[0-9]{12}(?:[0-9]{3})?\b",r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"]}),
    ("permissive", {"allow_tools":["*"],"deny_tools":[],"max_records":1000,"require_approval":[],"redact_patterns":[],"read_only":False}),
    ("strict-read-only", {"allow_tools":["*"],"deny_tools":["delete*","drop*","truncate*","update*","insert*","create*","write*","patch*"],
                          "max_records":50,"require_approval":[],"read_only":True,
                          "redact_patterns":[r"\b\d{3}-\d{2}-\d{4}\b",r"\b4[0-9]{12}(?:[0-9]{3})?\b",r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"]}),
]

async def seed_tenant_policies(tenant_id, conn):
    for pol_name, rules in DEFAULT_POLICIES:
        try:
            if await conn.fetchval("SELECT name FROM policies WHERE tenant_id=$1 AND name=$2", tenant_id, pol_name):
                continue
            await conn.execute("INSERT INTO policies (id,tenant_id,name,rules) VALUES ($1,$2,$3,$4)",
                               str(uuid.uuid4()), tenant_id, pol_name, json.dumps(rules))
        except Exception as e:
            log.warning("seed_policy.skipped", name=pol_name, error=str(e))

# ── Ed25519 ───────────────────────────────────────────────────────────────────
def verify_ed25519(public_key_b64, body, sig_b64):
    try:
        pub = Ed25519PublicKey.from_public_bytes(b64decode(public_key_b64))
        pub.verify(b64decode(sig_b64), body)
        return True, "ok"
    except InvalidSignature:
        return False, "Invalid signature"
    except Exception as e:
        return False, f"Signature error: {type(e).__name__}"

# ── Nonce ─────────────────────────────────────────────────────────────────────
_local_nonces: OrderedDict[str, float] = OrderedDict()

async def _redis_ok() -> bool:
    try:
        await asyncio.wait_for(redis_conn.ping(), timeout=1.0)
        return True
    except Exception:
        REDIS_ERRORS.inc()
        return False

async def is_nonce_fresh(nonce):
    if redis_conn:
        if not await _redis_ok(): return not IS_PROD
        return await redis_conn.set(f"ag:n:{nonce}", "1", ex=REPLAY_WINDOW_SECS, nx=True) is not None
    now = time.time()
    cutoff = now - REPLAY_WINDOW_SECS
    while _local_nonces and next(iter(_local_nonces.values())) < cutoff:
        _local_nonces.popitem(last=False)
    while len(_local_nonces) >= 10_000:
        _local_nonces.popitem(last=False)
    if nonce in _local_nonces: return False
    _local_nonces[nonce] = now
    return True

async def verify_request(agent, body, sig, ts, nonce):
    if ts is not None and abs(int(time.time()) - ts) > REPLAY_WINDOW_SECS:
        return False, "Request expired"
    if nonce is not None and not await is_nonce_fresh(nonce):
        return False, "Nonce reused"
    if sig is not None:
        if not agent["public_key"]: return False, "No public key registered"
        ok, reason = verify_ed25519(agent["public_key"], body, sig)
        if not ok: return False, reason
    if os.environ.get("REQUIRE_SIGNATURES") == "true":
        if sig is None and agent.get("public_key"):
            return False, "Signature required"
    return True, "ok"

# ── SSRF ──────────────────────────────────────────────────────────────────────
_PRIVATE_NETS = [ipaddress.ip_network(n) for n in [
    "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8",
    "169.254.0.0/16","0.0.0.0/8","::1/128","fc00::/7","fe80::/10","100.64.0.0/10",
]]

def _is_private(addr):
    try: return any(ipaddress.ip_address(addr) in n for n in _PRIVATE_NETS)
    except ValueError: return True

def validate_and_resolve_target(url, agent_hosts):
    try: parsed = urlparse(url)
    except: return False, "Invalid URL", []
    if parsed.scheme not in ("http","https"): return False, "Scheme not allowed", []
    host = parsed.hostname or ""
    effective = set(ALLOWED_INVOKE_HOSTS) | set(agent_hosts or [])
    if not effective: return False, "No allowed hosts", []
    if host not in effective: return False, f"Host '{host}' not allowed", []
    try: ips = [i[4][0] for i in socket.getaddrinfo(host, None)]
    except socket.gaierror as e: return False, f"DNS failed: {e}", []
    for ip in ips:
        if _is_private(ip): return False, f"'{host}' resolves to private IP", []
    return True, "ok", list(set(ips))

async def invoke_with_pinned_ip(url, pinned_ips, payload, agent_id):
    parsed = urlparse(url)
    host   = parsed.hostname
    ip_url = url.replace(f"://{host}", f"://{pinned_ips[0]}")
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            resp = await client.post(ip_url, json=payload,
                                     headers={"Host": host, "x-agent-id": agent_id})
        result = resp.json() if resp.headers.get("content-type","").startswith("application/json") else {"body": resp.text}
        return resp.is_success, result
    except Exception as e:
        return False, {"error": str(e)}

# ── Redaction ─────────────────────────────────────────────────────────────────
BASELINE_PII = [
    (r"\b\d{3}-\d{2}-\d{4}\b",                                "[SSN]"),
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b",                          "[CARD]"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",  "[EMAIL]"),
    (r"(?i)\b(?:password|secret|token|api_key)\s*[:=]\s*\S+", "[SECRET]"),
]

def build_patterns(rules):
    if isinstance(rules, str): rules = json.loads(rules)
    return BASELINE_PII + [(p, "[REDACTED]") for p in rules.get("redact_patterns", [])]

def redact(data, patterns):
    try: text = json.dumps(data, default=str)
    except: return {"_err": "serialize"}, True
    orig = text
    for pat, label in patterns:
        try: text = re.sub(pat, label, text, flags=re.IGNORECASE)
        except re.error: pass
    changed = text != orig
    try: return json.loads(text), changed
    except: return {"_err": "parse"}, True

def safe_log_args(args, patterns):
    clean, _ = redact(args, patterns)
    return {k: (hashlib.sha256(str(v).encode()).hexdigest()[:12]+"…" if len(str(v))>80 else v)
            for k, v in (clean if isinstance(clean, dict) else {}).items()}

# ── Policy enforcement ────────────────────────────────────────────────────────
WRITE_VERBS = {"delete","drop","truncate","update","insert","create","write","patch",
               "put","post","remove","destroy","clear","reset","purge","wipe","modify",
               "alter","exec","execute","run"}

def _tokens(tool):
    s = re.sub(r'([a-z0-9])([A-Z])',r'\1_\2',tool)
    s = re.sub(r'([A-Z]+)([A-Z][a-z])',r'\1_\2',s)
    return [t for t in re.split(r'[_.\-/]',s.lower()) if t]

def _matches(tool, pattern):
    if pattern == "*": return True
    if pattern.endswith("*"): return tool.lower().startswith(pattern[:-1].lower())
    return tool.lower() == pattern.lower()

def check_tool(tool, rules):
    if isinstance(rules, str): rules = json.loads(rules)
    if rules.get("read_only") and any(t in WRITE_VERBS for t in _tokens(tool)):
        return False, f"'{tool}' is a write op — policy is read-only"
    for p in rules.get("deny_tools", []):
        if _matches(tool, p): return False, f"'{tool}' is blocked by policy"
    allow = rules.get("allow_tools", [])
    if not allow: return False, f"'{tool}' not permitted — deny-by-default"
    for p in allow:
        if _matches(tool, p): return True, "allowed"
    return False, f"'{tool}' not in allowed list"

def check_args(args, rules):
    if isinstance(rules, str): rules = json.loads(rules)
    max_r = rules.get("max_records")
    if not max_r: return True, "ok"
    for k in ("limit","count","max","size","page_size","per_page","top","take"):
        v = args.get(k)
        if v is not None:
            try:
                if int(v) > max_r: return False, f"{k}={v} exceeds max_records={max_r}"
            except (TypeError, ValueError): pass
    return True, "ok"

# ── Semantic check (tool enforcement) ─────────────────────────────────────────
SEMANTIC_CACHE_MAX = 512
SEMANTIC_CACHE_TTL = 60
_sem_cache: OrderedDict = OrderedDict()
_sem_failures = 0
_sem_open_until = 0.0
CIRCUIT_OPEN_SECS = 60
CIRCUIT_THRESH    = 5
SUSPICIOUS_VERBS  = WRITE_VERBS | {"admin","sudo","bypass","override","impersonate","escalate"}

async def semantic_check(tool, args, context, policy):
    global _sem_failures, _sem_open_until
    cache_key = hashlib.sha256(json.dumps([tool,sorted(args.items()),context,policy],default=str).encode()).hexdigest()
    cached = _sem_cache.get(cache_key)
    if cached:
        allowed, reason, ts = cached
        if time.time() - ts < SEMANTIC_CACHE_TTL:
            _sem_cache.move_to_end(cache_key)
            SEMANTIC_CALLS.labels(cached="true", result=str(allowed)).inc()
            return allowed, f"{reason} [cached]"
    if time.time() < _sem_open_until:
        return False, "Semantic circuit open"
    try:
        async for attempt in AsyncRetrying(stop=stop_after_attempt(2),
                                           wait=wait_exponential(min=0.5,max=4),
                                           retry=retry_if_exception_type((anthropic.APIConnectionError,)),
                                           reraise=False):
            with attempt:
                client = anthropic.AsyncAnthropic()
                msg = await asyncio.wait_for(client.messages.create(
                    model="claude-sonnet-4-6", max_tokens=200,
                    messages=[{"role":"user","content":
                        f"Strict AI security agent. Evaluate tool call.\n"
                        f"Tool: {tool}\nArgs: {json.dumps(args,default=str)}\n"
                        f"Context: {context or 'none'}\nPolicy: {policy}\n"
                        f"Deny if destructive/bypass/injection. Allow if clearly legitimate.\n"
                        f"JSON only: {{\"allowed\":true,\"reason\":\"brief\"}}"}]
                ), timeout=8.0)
        raw    = re.sub(r"^```(?:json)?\n?|\n?```$","",msg.content[0].text.strip())
        result = json.loads(raw)
        allowed, reason = bool(result.get("allowed",False)), str(result.get("reason",""))
        _sem_failures = 0
        if len(_sem_cache) >= SEMANTIC_CACHE_MAX: _sem_cache.popitem(last=False)
        _sem_cache[cache_key] = (allowed, reason, time.time())
        SEMANTIC_CALLS.labels(cached="false", result=str(allowed)).inc()
        return allowed, reason
    except Exception as e:
        _sem_failures += 1
        ANTHROPIC_ERRORS.inc()
        if _sem_failures >= CIRCUIT_THRESH:
            _sem_open_until = time.time() + CIRCUIT_OPEN_SECS
        return False, f"Semantic error ({type(e).__name__}) — denying for safety"

# ── Anomaly detection ─────────────────────────────────────────────────────────
async def check_anomalies(tenant_id, agent_id, tool, bg):
    bg.add_task(_run_anomaly_checks, tenant_id, agent_id, tool)

async def _run_anomaly_checks(tenant_id, agent_id, tool):
    try:
        async with pool.acquire() as conn:
            recent   = await conn.fetchval("SELECT COUNT(*) FROM audit_logs WHERE agent_id=$1 AND created_at > NOW() - INTERVAL '5 minutes'", agent_id)
            baseline = await conn.fetchval("SELECT COALESCE(AVG(cnt),0) FROM (SELECT COUNT(*) as cnt FROM audit_logs WHERE agent_id=$1 AND created_at BETWEEN NOW()-INTERVAL '2 hours' AND NOW()-INTERVAL '5 minutes' GROUP BY date_trunc('minute', created_at)) t", agent_id)
            if baseline and recent > (baseline * 3) and recent > 20:
                await _create_alert(conn, tenant_id, agent_id, "rate_spike", f"Agent made {recent} calls in 5min")
            total  = await conn.fetchval("SELECT COUNT(*) FROM audit_logs WHERE agent_id=$1 AND created_at > NOW() - INTERVAL '10 minutes'", agent_id)
            denied = await conn.fetchval("SELECT COUNT(*) FROM audit_logs WHERE agent_id=$1 AND decision='deny' AND created_at > NOW() - INTERVAL '10 minutes'", agent_id)
            if total and total >= 10 and (denied / total) > 0.5:
                await _create_alert(conn, tenant_id, agent_id, "high_deny_rate", f"{denied}/{total} denied in 10min")
            seen_before = await conn.fetchval("SELECT COUNT(*) FROM audit_logs WHERE agent_id=$1 AND tool=$2 AND created_at < NOW() - INTERVAL '1 hour'", agent_id, tool)
            if seen_before == 0:
                recent_this = await conn.fetchval("SELECT COUNT(*) FROM audit_logs WHERE agent_id=$1 AND tool=$2", agent_id, tool)
                if recent_this and recent_this <= 3:
                    await _create_alert(conn, tenant_id, agent_id, "new_tool_detected", f"New tool '{tool}'")
    except Exception as e:
        log.error("anomaly.check_failed", error=str(e))

async def _create_alert(conn, tenant_id, agent_id, alert_type, detail):
    existing = await conn.fetchval(
        "SELECT id FROM anomaly_alerts WHERE agent_id=$1 AND alert_type=$2 AND created_at > NOW() - INTERVAL '1 hour' AND resolved=FALSE",
        agent_id, alert_type
    )
    if not existing:
        await conn.execute("INSERT INTO anomaly_alerts (id,tenant_id,agent_id,alert_type,detail) VALUES ($1,$2,$3,$4,$5)",
                           str(uuid.uuid4()), tenant_id, agent_id, alert_type, detail)

# ── Audit ─────────────────────────────────────────────────────────────────────
VALID_DECISIONS = {"allow","deny","pending","invoke_error"}

async def log_action(request_id, tenant_id, agent_id, user_id, tool, args,
                     decision, reason, redacted, duration_ms, patterns):
    assert decision in VALID_DECISIONS
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO audit_logs (id,request_id,tenant_id,agent_id,user_id,tool,args,decision,reason,redacted,duration_ms)"
            " VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            str(uuid.uuid4()), request_id, tenant_id, agent_id, user_id, tool,
            json.dumps(safe_log_args(args, patterns)), decision, reason, redacted, duration_ms
        )
    REQUESTS_TOTAL.labels(endpoint="protect", decision=decision, tenant=(tenant_id or "")[:8]).inc()

async def load_agent_and_policy(agent_id, tenant_id):
    async with pool.acquire() as conn:
        agent = await conn.fetchrow("SELECT * FROM agents WHERE id=$1 AND tenant_id=$2", agent_id, tenant_id)
        if not agent: raise HTTPException(404, f"Agent '{agent_id}' not found")
        if agent["revoked"]: raise HTTPException(403, f"Agent '{agent_id}' is revoked")
        policy = await conn.fetchrow("SELECT * FROM policies WHERE tenant_id=$1 AND name=$2", tenant_id, agent["policy"])
        if not policy: raise HTTPException(404, f"Policy '{agent['policy']}' not found")
    return agent, policy

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="AgentGuard", version="3.6.0", lifespan=lifespan)
app.state.limiter = limiter

ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS","*").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True,
    allow_methods=["GET","POST","PUT","DELETE","OPTIONS","PATCH"],
    allow_headers=["*"], expose_headers=["*"], max_age=600)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(429, {"error": "rate_limit_exceeded", "detail": str(exc.detail)})

def rid(request: Request) -> str:
    return request.headers.get("x-request-id") or str(uuid.uuid4())

# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/auth/signup")
async def signup(body: TenantSignup):
    tenant_id = f"t_{uuid.uuid4().hex[:16]}"
    api_key   = f"sk-guard-{secrets.token_hex(32)}"
    try:
        pw_hash = _bcrypt.hashpw(body.password.encode(), _bcrypt.gensalt()).decode()
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "server_error", "detail": str(e)})
    try:
        async with pool.acquire() as conn:
            await conn.execute("INSERT INTO tenants (id,name,email,password_hash,api_key) VALUES ($1,$2,$3,$4,$5)",
                               tenant_id, body.name, body.email, pw_hash, api_key)
            await seed_tenant_policies(tenant_id, conn)
    except asyncpg.UniqueViolationError:
        return JSONResponse(status_code=400, content={"error": "email_exists", "detail": "Email already exists."})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "signup_failed", "detail": str(e)})
    return {"token": create_jwt(tenant_id), "api_key": api_key, "tenant_id": tenant_id}

@app.post("/auth/login")
async def login(body: TenantLogin):
    async with pool.acquire() as conn:
        tenant = await conn.fetchrow("SELECT * FROM tenants WHERE email=$1", body.email)
    if not tenant or not _bcrypt.checkpw(body.password.encode(), tenant["password_hash"].encode()):
        raise HTTPException(401, "Invalid email or password")
    return {"token": create_jwt(tenant["id"]), "api_key": tenant["api_key"],
            "tenant_id": tenant["id"], "name": tenant["name"]}

@app.get("/auth/me")
async def me(tenant=Depends(get_tenant)):
    if tenant["id"] == "__admin__": return {"id": "__admin__", "plan": "enterprise"}
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id,name,email,plan,api_key,created_at FROM tenants WHERE id=$1", tenant["id"])
    return dict(row)

# ══════════════════════════════════════════════════════════════════════════════
# PROTECT + INVOKE
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/protect")
@limiter.limit("120/minute;20/second")
async def protect(req: ProtectRequest, request: Request, bg: BackgroundTasks,
                  tenant=Depends(get_tenant), x_agent_signature: Optional[str]=Header(None)):
    start = time.monotonic()
    request_id = rid(request)
    body = await request.body()
    tenant_id = tenant["id"] if tenant["id"] != "__admin__" else "__admin__"
    structlog.contextvars.bind_contextvars(request_id=request_id, tenant_id=tenant_id,
                                           agent_id=req.agent_id, tool=req.tool)
    if tenant_id == "__admin__":
        async with pool.acquire() as conn:
            agent_row = await conn.fetchrow("SELECT * FROM agents WHERE id=$1", req.agent_id)
            if not agent_row: raise HTTPException(404, f"Agent '{req.agent_id}' not found")
            policy_row = await conn.fetchrow("SELECT * FROM policies WHERE tenant_id=$1 AND name=$2",
                                              agent_row["tenant_id"], agent_row["policy"])
            if not policy_row:
                policy_row = {"rules": '{"allow_tools":["*"],"deny_tools":[],"read_only":false,"max_records":1000,"redact_patterns":[]}', "name": "fallback"}
        agent = agent_row
    else:
        agent, policy_row = await load_agent_and_policy(req.agent_id, tenant_id)
    if tenant_id != "__admin__":
        ok, reason = await verify_request(agent, body, x_agent_signature, req.timestamp, req.nonce)
        if not ok: raise HTTPException(401, reason)
    rules    = policy_row["rules"]
    patterns = build_patterns(rules)
    allowed, reason, clean, redacted, action = await run_enforcement_v3(
        req.tool, req.args, agent, rules, patterns, req.context, tenant_id=tenant_id
    )
    decision = "allow" if allowed else ("pending" if action=="pending_approval" else "deny")
    ms = int((time.monotonic()-start)*1000)
    await log_action(request_id, tenant["id"], req.agent_id, req.user_id,
                     req.tool, clean, decision, reason, redacted, ms, patterns)
    LATENCY.labels(endpoint="protect").observe(ms/1000)
    if decision == "allow":
        await check_anomalies(tenant["id"], req.agent_id, req.tool, bg)
    if not allowed:
        if action == "pending_approval":
            return {"allowed": False, "action": action, "reason": reason, "args": clean}
        return JSONResponse(status_code=403, content={"allowed": False, "reason": reason, "action": action, "request_id": request_id})
    return {"allowed": True, "action": "proceed", "args": clean, "redacted": redacted,
            "duration_ms": ms, "policy": agent["policy"], "request_id": request_id}

@app.post("/invoke")
@limiter.limit("60/minute;10/second")
async def invoke(req: InvokeRequest, request: Request, bg: BackgroundTasks,
                 tenant=Depends(get_tenant), x_agent_signature: Optional[str]=Header(None)):
    start = time.monotonic()
    request_id = rid(request)
    body = await request.body()
    agent, policy_row = await load_agent_and_policy(req.agent_id, tenant["id"])
    ok, reason = await verify_request(agent, body, x_agent_signature, req.timestamp, req.nonce)
    if not ok: raise HTTPException(401, reason)
    rules    = policy_row["rules"]
    patterns = build_patterns(rules)
    url_ok, url_reason, pinned_ips = validate_and_resolve_target(req.target_url, list(agent["allowed_hosts"] or []))
    if not url_ok:
        return JSONResponse(status_code=400, content={"allowed": False, "reason": url_reason, "action": "ssrf_blocked"})
    allowed, reason, clean, redacted, action = await run_enforcement_v3(
        req.tool, req.args, agent, rules, patterns, req.context, tenant_id=tenant["id"]
    )
    ms = int((time.monotonic()-start)*1000)
    if not allowed:
        decision = "pending" if action=="pending_approval" else "deny"
        await log_action(request_id, tenant["id"], req.agent_id, req.user_id, req.tool, clean, decision, reason, redacted, ms, patterns)
        if action == "pending_approval": return {"allowed": False, "action": action, "reason": reason}
        return JSONResponse(status_code=403, content={"allowed": False, "reason": reason, "action": action})
    invoke_ok, tool_result = await invoke_with_pinned_ip(req.target_url, pinned_ips,
                                                          {"tool": req.tool, "args": clean, "user_id": req.user_id}, req.agent_id)
    ms = int((time.monotonic()-start)*1000)
    decision = "allow" if invoke_ok else "invoke_error"
    await log_action(request_id, tenant["id"], req.agent_id, req.user_id, req.tool, clean, decision, reason, redacted, ms, patterns)
    LATENCY.labels(endpoint="invoke").observe(ms/1000)
    if invoke_ok: await check_anomalies(tenant["id"], req.agent_id, req.tool, bg)
    return {"allowed": True, "action": "invoked", "result": tool_result, "success": invoke_ok,
            "redacted": redacted, "duration_ms": ms, "policy": agent["policy"]}

# ══════════════════════════════════════════════════════════════════════════════
# SESSIONS
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/sessions")
async def start_session(body: SessionCreate, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        agent = await conn.fetchrow("SELECT id FROM agents WHERE id=$1 AND tenant_id=$2 AND revoked=FALSE",
                                     body.agent_id, tenant["id"])
    if not agent: raise HTTPException(404, "Agent not found or revoked")
    result = await create_session(tenant["id"], body.agent_id, body.user_id,
                                  body.intent, body.ttl_seconds, body.metadata)
    if result.get("session_id"):
        try:
            await anchor_session_intent(result["session_id"], tenant["id"],
                                         body.agent_id, body.intent)
        except Exception:
            pass
    return result

@app.get("/sessions")
async def list_sessions(tenant=Depends(get_tenant), agent_id: Optional[str]=None,
                         status: str="active", limit: int=50):
    where = "WHERE tenant_id=$1 AND status=$2"
    vals  = [tenant["id"], status]
    if agent_id: where += " AND agent_id=$3"; vals.append(agent_id)
    vals.append(min(limit, 200))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT id,agent_id,user_id,intent,status,tool_call_count,deny_count,started_at,last_active_at"
            f" FROM agent_sessions {where} ORDER BY last_active_at DESC LIMIT ${len(vals)}", *vals)
    return [dict(r) for r in rows]

@app.get("/sessions/{session_id}")
async def get_session_detail(session_id: str, tenant=Depends(get_tenant)):
    sess = await get_session(session_id, tenant["id"])
    if not sess: raise HTTPException(404, "Session not found or expired")
    async with pool.acquire() as conn:
        calls = await conn.fetch("SELECT tool,decision,turn,created_at FROM session_tool_calls WHERE session_id=$1 ORDER BY turn DESC LIMIT 50", session_id)
    return {**sess, "recent_calls": [dict(c) for c in calls]}

@app.delete("/sessions/{session_id}")
async def end_session(session_id: str, tenant=Depends(get_tenant)):
    await terminate_session(session_id, tenant["id"], "terminated")
    return {"session_id": session_id, "status": "terminated"}

@app.get("/sessions/{session_id}/drift")
async def session_drift_report(session_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        sess  = await conn.fetchrow("SELECT * FROM agent_sessions WHERE id=$1 AND tenant_id=$2", session_id, tenant["id"])
        if not sess: raise HTTPException(404, "Session not found")
        calls = await conn.fetch("SELECT tool,decision,turn,created_at FROM session_tool_calls WHERE session_id=$1 ORDER BY turn ASC", session_id)
    cached = _intent_cache.get(session_id, {})
    return {"session_id": session_id, "intent": sess["intent"], "tool_calls": len(calls),
            "deny_count": sess["deny_count"], "last_drift_score": cached.get("drift_score"),
            "last_drift_reason": cached.get("reason"), "calls": [dict(c) for c in calls]}

@app.post("/sessions/{session_id}/protect")
@limiter.limit("200/minute;30/second")
async def session_protect(session_id: str, req: SessionToolCall, request: Request,
                           bg: BackgroundTasks, tenant=Depends(get_tenant),
                           x_agent_signature: Optional[str]=Header(None)):
    start = time.monotonic()
    request_id = rid(request)
    body_bytes = await request.body()
    tid = tenant["id"]
    session = await get_session(session_id, tid)
    if not session: raise HTTPException(404, "Session not found or expired")
    agent, policy_row = await load_agent_and_policy(req.agent_id, tid)
    ok, reason = await verify_request(agent, body_bytes, x_agent_signature, req.timestamp, req.nonce)
    if not ok: raise HTTPException(401, reason)
    if req.tool_result is not None:
        findings = scan_for_injection(req.tool_result, "tool_result")
        if findings:
            f = findings[0]
            bg.add_task(log_injection_event, tid, req.agent_id, session_id, "tool_result", f)
            ms = int((time.monotonic()-start)*1000)
            await log_action(request_id, tid, req.agent_id, req.user_id, req.tool, {},
                             "deny", f"Injection in tool result: {f['pattern']}", False, ms, [])
            return JSONResponse(status_code=403, content={"allowed": False, "action": "injection_blocked",
                                "reason": f"Prompt injection in tool result: {f['pattern']}", "request_id": request_id})
    rules    = policy_row["rules"]
    patterns = build_patterns(rules)
    turn     = (session.get("tool_call_count") or 0) + 1
    session["id"] = session_id
    allowed, reason, clean, redacted, action = await run_enforcement_v34(
        req.tool, req.args, agent, rules, patterns, req.context,
        tenant_id=tid, session=session, session_id=session_id
    )
    decision = "allow" if allowed else ("pending" if action=="pending_approval" else "deny")
    ms = int((time.monotonic()-start)*1000)
    await log_action(request_id, tid, req.agent_id, req.user_id, req.tool, clean,
                     decision, reason, redacted, ms, patterns)
    bg.add_task(increment_session_counters, session_id, tid, decision, req.tool, turn)
    LATENCY.labels(endpoint="session_protect").observe(ms/1000)
    if not allowed:
        if action == "honey_tool_trip":
            bg.add_task(terminate_session, session_id, tid, "honey_tool_trip")
            return JSONResponse(status_code=403, content={"allowed": False, "action": "honey_tool_trip",
                                "reason": reason, "session_id": session_id, "request_id": request_id})
        if action == "pending_approval":
            hitl = await create_hitl_request(tid, req.agent_id, session_id, request_id, req.tool, clean, reason)
            return JSONResponse(status_code=202, content={"allowed": False, "action": "pending_approval",
                                "reason": reason, "hitl": hitl, "request_id": request_id})
        new_deny = (session.get("deny_count") or 0) + 1
        if new_deny >= 5:
            bg.add_task(terminate_session, session_id, tid, "auto_terminated_high_deny")
        return JSONResponse(status_code=403, content={"allowed": False, "action": action,
                            "reason": reason, "session_id": session_id, "session_turn": turn, "request_id": request_id})
    bg.add_task(check_anomalies, tid, req.agent_id, req.tool, bg)
    return {"allowed": True, "action": "proceed", "args": clean, "redacted": redacted,
            "duration_ms": ms, "policy": agent["policy"], "session_id": session_id,
            "session_turn": turn, "request_id": request_id}

# ══════════════════════════════════════════════════════════════════════════════
# EPHEMERAL SESSION CERTIFICATES v3.3
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/sessions/{session_id}/cert")
async def issue_session_cert(session_id: str, tenant=Depends(get_tenant)):
    """
    Issue a short-lived X.509 certificate for a session.
    The private key is returned ONCE and never stored server-side.
    """
    sess = await get_session(session_id, tenant["id"])
    if not sess:
        raise HTTPException(404, "Session not found or expired")
    ttl = 3600
    if redis_conn:
        try:
            remaining = await redis_conn.ttl(f"ag:sess:{session_id}")
            if remaining > 0:
                ttl = remaining
        except Exception:
            pass
    result = await mint_session_cert(session_id, tenant["id"],
                                      sess.get("agent_id", "unknown"), ttl)
    log.info("cert.issued", session_id=session_id, fingerprint=result["fingerprint"])
    return result

@app.get("/sessions/{session_id}/cert")
async def get_cert_status(session_id: str, tenant=Depends(get_tenant)):
    """Check the status of a session certificate (without the private key)."""
    cert = await get_session_cert(session_id, tenant["id"])
    if not cert:
        raise HTTPException(404, "No certificate found for this session")
    return cert

@app.post("/sessions/{session_id}/cert/verify")
async def verify_cert_signature(session_id: str, body: CertVerifyRequest,
                                  request: Request, tenant=Depends(get_tenant)):
    """Verify a payload was signed with the session certificate's private key."""
    ip = request.client.host if request.client else None
    ok, reason = await verify_session_cert(
        session_id, tenant["id"], body.payload, body.signature)
    cert = await get_session_cert(session_id, tenant["id"])
    fingerprint = cert["fingerprint"] if cert else None
    await log_cert_request(tenant["id"], cert.get("agent_id", "") if cert else "",
                            session_id, fingerprint, ok, reason if not ok else None, ip)
    if not ok:
        raise HTTPException(401, f"Certificate verification failed: {reason}")
    return {"verified": True, "session_id": session_id, "fingerprint": fingerprint}

@app.post("/sessions/{session_id}/cert/revoke")
async def revoke_cert(session_id: str, body: dict, tenant=Depends(get_tenant)):
    """Revoke a session certificate immediately."""
    reason = body.get("reason", "manual_revocation")
    ok = await revoke_session_cert(session_id, tenant["id"], reason)
    if not ok:
        raise HTTPException(404, "Certificate not found")
    log.warning("cert.revoked", session_id=session_id, reason=reason)
    return {"revoked": True, "session_id": session_id, "reason": reason}

@app.get("/certs")
async def list_certs(tenant=Depends(get_tenant), revoked: Optional[bool]=None, limit: int=50):
    """List all session certificates for this tenant."""
    where = "WHERE tenant_id=$1"; vals = [tenant["id"]]
    if revoked is not None:
        where += " AND revoked=$2"; vals.append(revoked)
    vals.append(min(limit, 200))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT session_id, agent_id, fingerprint, issued_at, expires_at,"
            f" revoked, revoked_at, revoke_reason"
            f" FROM session_certificates {where}"
            f" ORDER BY issued_at DESC LIMIT ${len(vals)}", *vals)
    return [dict(r) for r in rows]

@app.get("/certs/stats")
async def cert_stats(tenant=Depends(get_tenant), days: int=30):
    """Certificate issuance and verification stats."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS total_issued,"
            " COUNT(*) FILTER (WHERE revoked=TRUE) AS total_revoked,"
            " COUNT(*) FILTER (WHERE expires_at > NOW() AND revoked=FALSE) AS currently_active"
            " FROM session_certificates WHERE tenant_id=$1"
            " AND issued_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
        verify_row = await conn.fetchrow(
            "SELECT COUNT(*) AS total_checks,"
            " COUNT(*) FILTER (WHERE verified=TRUE) AS passed,"
            " COUNT(*) FILTER (WHERE verified=FALSE) AS failed"
            " FROM cert_request_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
    return {**dict(row), "verification": dict(verify_row)}

# ══════════════════════════════════════════════════════════════════════════════
# HITL
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/hitl")
async def list_hitl(tenant=Depends(get_tenant), status: Optional[str]=None,
                     agent_id: Optional[str]=None, limit: int=50):
    where = "WHERE tenant_id=$1"; vals = [tenant["id"]]
    if status:   where += f" AND status=${len(vals)+1}";   vals.append(status)
    if agent_id: where += f" AND agent_id=${len(vals)+1}"; vals.append(agent_id)
    vals.append(min(limit, 200))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT id,agent_id,session_id,tool,reason,status,decision,decided_by,decided_at,expires_at,webhook_sent,created_at"
            f" FROM hitl_approvals {where} ORDER BY created_at DESC LIMIT ${len(vals)}", *vals)
    return [dict(r) for r in rows]

@app.get("/hitl/{hitl_id}")
async def poll_hitl(hitl_id: str, tenant=Depends(get_tenant)):
    result = await get_hitl_status(hitl_id, tenant["id"])
    if not result: raise HTTPException(404, "HITL request not found")
    status = result.get("status", "pending")
    if status == "pending":
        expires_at = result.get("expires_at")
        if expires_at:
            exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00")) if isinstance(expires_at, str) else expires_at
            if exp < datetime.now(timezone.utc):
                return {"status": "expired", "hitl_id": hitl_id}
    return {"hitl_id": hitl_id, "status": status, "decision": result.get("decision"),
            "decided_by": result.get("decided_by"), "tool": result.get("tool"),
            "expires_at": result.get("expires_at")}

@app.post("/hitl/{hitl_id}/decide")
async def decide_hitl_endpoint(hitl_id: str, body: HITLDecision, tenant=Depends(get_tenant)):
    try:
        return await decide_hitl(hitl_id, tenant["id"], body.decision, body.decided_by, body.reason)
    except LookupError as e: raise HTTPException(404, str(e))
    except TimeoutError as e: raise HTTPException(410, str(e))
    except ValueError as e:  raise HTTPException(400, str(e))

# ══════════════════════════════════════════════════════════════════════════════
# RATE LIMITS
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/rate-limits")
async def set_tool_rate_limit(body: ToolRateLimit, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        agent = await conn.fetchrow("SELECT id FROM agents WHERE id=$1 AND tenant_id=$2", body.agent_id, tenant["id"])
        if not agent: raise HTTPException(404, "Agent not found")
        await conn.execute(
            "INSERT INTO tool_rate_limits (tenant_id,agent_id,tool_pattern,max_calls,window_secs) VALUES ($1,$2,$3,$4,$5)"
            " ON CONFLICT (tenant_id,agent_id,tool_pattern) DO UPDATE SET max_calls=$4, window_secs=$5",
            tenant["id"], body.agent_id, body.tool_pattern, body.max_calls, body.window_secs)
    return {"agent_id": body.agent_id, "tool_pattern": body.tool_pattern,
            "max_calls": body.max_calls, "window_secs": body.window_secs}

@app.get("/rate-limits")
async def list_rate_limits(tenant=Depends(get_tenant), agent_id: Optional[str]=None):
    where = "WHERE tenant_id=$1"; vals = [tenant["id"]]
    if agent_id: where += " AND agent_id=$2"; vals.append(agent_id)
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"SELECT * FROM tool_rate_limits {where} ORDER BY created_at DESC", *vals)
    return [dict(r) for r in rows]

@app.delete("/rate-limits/{limit_id}")
async def delete_rate_limit(limit_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        res = await conn.execute("DELETE FROM tool_rate_limits WHERE id=$1 AND tenant_id=$2", limit_id, tenant["id"])
    if res == "DELETE 0": raise HTTPException(404, "Rate limit not found")
    return {"deleted": limit_id}

# ══════════════════════════════════════════════════════════════════════════════
# INJECTION ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/security/injections")
async def list_injections(tenant=Depends(get_tenant), agent_id: Optional[str]=None,
                           days: int=7, limit: int=100):
    where = "WHERE tenant_id=$1 AND created_at > NOW() - ($2||' days')::INTERVAL"
    vals  = [tenant["id"], str(days)]
    if agent_id: where += " AND agent_id=$3"; vals.append(agent_id)
    vals.append(min(limit, 500))
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"SELECT * FROM injection_events {where} ORDER BY created_at DESC LIMIT ${len(vals)}", *vals)
    return [dict(r) for r in rows]

@app.get("/security/injections/stats")
async def injection_stats(tenant=Depends(get_tenant), days: int=30):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS total, COUNT(DISTINCT agent_id) AS agents_affected,"
            " COUNT(DISTINCT session_id) AS sessions_affected"
            " FROM injection_events WHERE tenant_id=$1 AND created_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
        by_pattern = await conn.fetch(
            "SELECT pattern, COUNT(*) AS count FROM injection_events"
            " WHERE tenant_id=$1 AND created_at > NOW() - ($2||' days')::INTERVAL"
            " GROUP BY pattern ORDER BY count DESC",
            tenant["id"], str(days))
    return {**dict(row), "by_pattern": [dict(r) for r in by_pattern]}

# ══════════════════════════════════════════════════════════════════════════════
# GUARDRAILS v3.1
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/guardrails/topics")
async def create_topic_policy(body: TopicPolicy, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO topic_policies (tenant_id,name,direction,action,keywords,description)"
            " VALUES ($1,$2,$3,$4,$5,$6)"
            " ON CONFLICT (tenant_id,name) DO UPDATE SET direction=$3,action=$4,keywords=$5,description=$6",
            tenant["id"], body.name, body.direction, body.action, body.keywords, body.description)
    return {"name": body.name, "direction": body.direction, "action": body.action, "keywords": body.keywords}

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
    return {"source_id": source_id, "content_length": len(body.content), "expires_in": body.ttl_seconds}

@app.get("/guardrails/grounding")
async def list_grounding_sources(tenant=Depends(get_tenant), session_id: Optional[str]=None):
    where = "WHERE tenant_id=$1 AND expires_at > NOW()"; vals = [tenant["id"]]
    if session_id: where += " AND session_id=$2"; vals.append(session_id)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT id,session_id,agent_id,content_hash,created_at,expires_at FROM grounding_sources {where} ORDER BY created_at DESC", *vals)
    return [dict(r) for r in rows]

@app.post("/guardrails/scan-output")
async def scan_output_endpoint(body: OutputScanRequest, tenant=Depends(get_tenant)):
    safe, findings, modified = await scan_output(body.content, tenant["id"], body.agent_id, body.session_id)
    return {"safe_content": safe, "findings": findings, "modified": modified}

@app.get("/guardrails/events")
async def list_guardrail_events(tenant=Depends(get_tenant), layer: Optional[str]=None,
                                  direction: Optional[str]=None, days: int=7, limit: int=100):
    where = "WHERE tenant_id=$1 AND created_at > NOW() - ($2||' days')::INTERVAL"
    vals  = [tenant["id"], str(days)]
    if layer:     where += f" AND layer=${len(vals)+1}";     vals.append(layer)
    if direction: where += f" AND direction=${len(vals)+1}"; vals.append(direction)
    vals.append(min(limit, 500))
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"SELECT * FROM guardrail_events {where} ORDER BY created_at DESC LIMIT ${len(vals)}", *vals)
    return [dict(r) for r in rows]

@app.get("/guardrails/stats")
async def guardrail_stats(tenant=Depends(get_tenant), days: int=30):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS total_events,"
            " COUNT(*) FILTER (WHERE layer='topic_firewall') AS topic_blocks,"
            " COUNT(*) FILTER (WHERE layer='output_gate') AS output_scans,"
            " COUNT(*) FILTER (WHERE layer='grounding_check') AS grounding_checks,"
            " COUNT(*) FILTER (WHERE layer='grounding_check' AND action='failed') AS grounding_failures,"
            " COUNT(*) FILTER (WHERE layer='semantic_classifier') AS semantic_checks,"
            " COUNT(*) FILTER (WHERE action IN ('blocked','modified')) AS total_interventions"
            " FROM guardrail_events WHERE tenant_id=$1 AND created_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
        by_layer = await conn.fetch(
            "SELECT layer, action, COUNT(*) AS count FROM guardrail_events"
            " WHERE tenant_id=$1 AND created_at > NOW() - ($2||' days')::INTERVAL"
            " GROUP BY layer, action ORDER BY count DESC",
            tenant["id"], str(days))
    return {**dict(row), "by_layer": [dict(r) for r in by_layer]}

@app.post("/proxy/chat/v2")
@limiter.limit("300/minute;30/second")
async def proxy_chat_v2(req: ProxyRequestV31, request: Request,
                          bg: BackgroundTasks, tenant=Depends(get_tenant)):
    """Bidirectional guardrail proxy: keyword firewall + PII + output gate + grounding."""
    start = time.monotonic(); tid = tenant["id"]
    safe_messages, safe_system, input_report = await run_input_guardrails(
        req.messages, req.system, tid, req.agent_id, req.session_id, tokenize=req.tokenize_pii)
    if input_report.get("blocked"):
        ms = int((time.monotonic()-start)*1000)
        return JSONResponse(status_code=400, content={
            "allowed": False, "blocked_at": "input",
            "reason": input_report["reason"], "layer": input_report["layer"], "duration_ms": ms})
    if req.dry_run:
        return {"dry_run": True, "input_report": input_report, "messages_after_guardrails": len(safe_messages)}
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
        detokenize_pii=req.tokenize_pii, check_ground=req.check_grounding,
        grounding_threshold=req.grounding_threshold)
    ms = int((time.monotonic()-start)*1000)
    LATENCY.labels(endpoint="proxy_v2").observe(ms/1000)
    return {"content": safe_response, "model": req.model,
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                      "total_tokens": prompt_tokens+completion_tokens},
            "guardrails": {"input": input_report, "output": output_report}, "duration_ms": ms}

# ══════════════════════════════════════════════════════════════════════════════
# SEMANTIC CLASSIFIER v3.2
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/guardrails/semantic-topics")
async def create_semantic_policy(body: SemanticTopicPolicy, tenant=Depends(get_tenant)):
    policy_dict = {"name": body.name, "example_phrases": body.example_phrases,
                   "confidence_threshold": body.confidence_threshold}
    policy_vec = await _get_policy_embedding(policy_dict)
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO semantic_topic_policies"
            " (tenant_id,name,description,example_phrases,confidence_threshold,direction,action)"
            " VALUES ($1,$2,$3,$4,$5,$6,$7)"
            " ON CONFLICT (tenant_id,name) DO UPDATE"
            " SET description=$3,example_phrases=$4,confidence_threshold=$5,direction=$6,action=$7,updated_at=NOW()",
            tenant["id"], body.name, body.description, body.example_phrases,
            body.confidence_threshold, body.direction, body.action)
    return {"name": body.name, "description": body.description,
            "confidence_threshold": body.confidence_threshold, "direction": body.direction,
            "action": body.action, "example_count": len(body.example_phrases),
            "embedding_cached": any(v != 0.0 for v in policy_vec)}

@app.get("/guardrails/semantic-topics")
async def list_semantic_policies(tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM semantic_topic_policies WHERE tenant_id=$1 ORDER BY name", tenant["id"])
    return [dict(r) for r in rows]

@app.delete("/guardrails/semantic-topics/{name}")
async def delete_semantic_policy(name: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        res = await conn.execute("DELETE FROM semantic_topic_policies WHERE tenant_id=$1 AND name=$2", tenant["id"], name)
    _embedding_cache.pop(f"policy_{name}", None)
    if res == "DELETE 0": raise HTTPException(404, "Semantic policy not found")
    return {"deleted": name}

@app.patch("/guardrails/semantic-topics/{name}/threshold")
async def update_threshold(name: str, body: dict, tenant=Depends(get_tenant)):
    threshold = float(body.get("threshold", 0.75))
    if not 0.0 <= threshold <= 1.0: raise HTTPException(400, "threshold must be 0.0-1.0")
    async with pool.acquire() as conn:
        res = await conn.execute(
            "UPDATE semantic_topic_policies SET confidence_threshold=$1, updated_at=NOW() WHERE tenant_id=$2 AND name=$3",
            threshold, tenant["id"], name)
    if res == "UPDATE 0": raise HTTPException(404, "Semantic policy not found")
    return {"name": name, "new_threshold": threshold}

@app.post("/guardrails/semantic-topics/test")
async def test_semantic_classifier(body: SemanticCheckRequest, tenant=Depends(get_tenant)):
    text_vec = await embed_text(body.text)
    async with pool.acquire() as conn:
        db_policies = await conn.fetch(
            "SELECT name,description,example_phrases,confidence_threshold,direction,action"
            " FROM semantic_topic_policies WHERE tenant_id=$1 AND enabled=TRUE", tenant["id"])
    all_policies = BUILTIN_SEMANTIC_POLICIES + [dict(r) for r in db_policies]
    results = []
    for policy in all_policies:
        if policy.get("direction") not in (body.direction, "both"): continue
        policy_vec = await _get_policy_embedding(policy)
        similarity = cosine_similarity(text_vec, policy_vec)
        threshold  = float(policy.get("confidence_threshold", 0.75))
        results.append({"policy": policy["name"], "similarity": round(similarity, 4),
                         "threshold": threshold, "would_block": similarity >= threshold,
                         "margin": round(similarity - threshold, 4),
                         "builtin": policy in BUILTIN_SEMANTIC_POLICIES})
    results.sort(key=lambda x: x["similarity"], reverse=True)
    blocked_by = [r["policy"] for r in results if r["would_block"]]
    return {"text": body.text[:200], "direction": body.direction,
            "blocked": len(blocked_by) > 0, "blocked_by": blocked_by, "scores": results}

@app.get("/guardrails/semantic-topics/stats")
async def semantic_classifier_stats(tenant=Depends(get_tenant), days: int=30):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS total_checks,"
            " COUNT(*) FILTER (WHERE action='blocked') AS total_blocked,"
            " COUNT(DISTINCT policy_name) AS policies_triggered,"
            " ROUND(AVG(similarity)::numeric,4) AS avg_similarity,"
            " ROUND(MAX(similarity)::numeric,4) AS max_similarity"
            " FROM semantic_classifier_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
        by_policy = await conn.fetch(
            "SELECT policy_name, COUNT(*) AS checks,"
            " COUNT(*) FILTER (WHERE action='blocked') AS blocked,"
            " ROUND(AVG(similarity)::numeric,4) AS avg_similarity"
            " FROM semantic_classifier_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL"
            " GROUP BY policy_name ORDER BY blocked DESC",
            tenant["id"], str(days))
    return {**dict(row), "by_policy": [dict(r) for r in by_policy]}

@app.post("/proxy/chat/v3")
@limiter.limit("300/minute;30/second")
async def proxy_chat_v3(req: ProxyRequestV31, request: Request,
                          bg: BackgroundTasks, tenant=Depends(get_tenant)):
    """Full semantic guardrail proxy: keyword + semantic + injection + PII + grounding."""
    start = time.monotonic(); tid = tenant["id"]
    safe_messages, safe_system, input_report = await run_semantic_guardrails(
        req.messages, req.system, tid, req.agent_id, req.session_id, tokenize=req.tokenize_pii)
    if input_report.get("blocked"):
        ms = int((time.monotonic()-start)*1000)
        return JSONResponse(status_code=400, content={
            "allowed": False, "blocked_at": "input",
            "reason": input_report.get("reason"), "layer": input_report.get("layer"),
            "confidence": input_report.get("confidence"), "policy": input_report.get("policy"),
            "duration_ms": ms})
    if req.dry_run:
        return {"dry_run": True, "input_report": input_report, "messages_after_guardrails": len(safe_messages)}
    try:
        client = anthropic.AsyncAnthropic()
        build_kwargs = dict(model=req.model, max_tokens=req.max_tokens, messages=safe_messages)
        if safe_system: build_kwargs["system"] = safe_system
        msg = await asyncio.wait_for(client.messages.create(**build_kwargs), timeout=120.0)
        llm_response      = msg.content[0].text if msg.content else ""
        prompt_tokens     = msg.usage.input_tokens
        completion_tokens = msg.usage.output_tokens
    except Exception as e:
        log.error("proxy_v3.llm_error", error=str(e))
        return JSONResponse(status_code=502, content={"error": f"LLM error: {type(e).__name__}"})
    safe_response, output_report = await run_output_semantic_guardrails(
        llm_response, tid, req.agent_id, req.session_id,
        detokenize_pii=req.tokenize_pii, check_ground=req.check_grounding,
        grounding_threshold=req.grounding_threshold)
    ms = int((time.monotonic()-start)*1000)
    LATENCY.labels(endpoint="proxy_v3").observe(ms/1000)
    return {"content": safe_response, "model": req.model,
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                      "total_tokens": prompt_tokens+completion_tokens},
            "guardrails": {"input": input_report, "output": output_report}, "duration_ms": ms}

# ══════════════════════════════════════════════════════════════════════════════
# AST POLICY SYNTHESIS v3.3
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/policies/synthesize")
async def synthesize_policy(body: PolicySynthesisRequest, tenant=Depends(get_tenant)):
    """Parse agent source code and auto-generate a least-privilege policy."""
    if len(body.code) > 500_000:
        raise HTTPException(400, "Code too large (max 500KB)")
    result = await synthesize_policy_from_code(
        body.code, body.language, body.policy_name, tenant["id"], body.auto_activate)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result

@app.post("/policies/synthesize/{policy_id}/activate")
async def activate_synthesized_policy(policy_id: str, tenant=Depends(get_tenant)):
    """Activate a draft synthesized policy — copies it to the active policies table."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM synthesized_policies WHERE id=$1 AND tenant_id=$2",
            policy_id, tenant["id"])
        if not row: raise HTTPException(404, "Synthesized policy not found")
        rules = row["rules"]; name = row["name"]
        existing = await conn.fetchrow(
            "SELECT id FROM policies WHERE tenant_id=$1 AND name=$2", tenant["id"], name)
        if existing:
            await conn.execute(
                "UPDATE policies SET rules=$1 WHERE tenant_id=$2 AND name=$3",
                json.dumps(rules) if isinstance(rules, dict) else rules, tenant["id"], name)
        else:
            await conn.execute(
                "INSERT INTO policies (id,tenant_id,name,rules) VALUES ($1,$2,$3,$4)",
                str(uuid.uuid4()), tenant["id"], name,
                json.dumps(rules) if isinstance(rules, dict) else rules)
        await conn.execute(
            "UPDATE synthesized_policies SET status='active', activated_at=NOW() WHERE id=$1",
            policy_id)
    return {"activated": True, "policy_id": policy_id, "policy_name": name,
            "message": f"Policy '{name}' is now active. Assign it to an agent with POST /agents."}

@app.get("/policies/synthesize")
async def list_synthesized_policies(tenant=Depends(get_tenant),
                                      status: Optional[str]=None, limit: int=50):
    """List all synthesized policies (draft and active)."""
    where = "WHERE tenant_id=$1"; vals = [tenant["id"]]
    if status: where += " AND status=$2"; vals.append(status)
    vals.append(min(limit, 200))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT id, name, language, inferred_tools, inferred_hosts,"
            f" inferred_paths, status, created_at, activated_at"
            f" FROM synthesized_policies {where}"
            f" ORDER BY created_at DESC LIMIT ${len(vals)}", *vals)
    return [dict(r) for r in rows]

@app.get("/policies/synthesize/{policy_id}")
async def get_synthesized_policy(policy_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM synthesized_policies WHERE id=$1 AND tenant_id=$2",
            policy_id, tenant["id"])
    if not row: raise HTTPException(404, "Synthesized policy not found")
    return dict(row)

@app.delete("/policies/synthesize/{policy_id}")
async def delete_synthesized_policy(policy_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        res = await conn.execute(
            "DELETE FROM synthesized_policies WHERE id=$1 AND tenant_id=$2",
            policy_id, tenant["id"])
    if res == "DELETE 0": raise HTTPException(404, "Synthesized policy not found")
    return {"deleted": policy_id}

# ══════════════════════════════════════════════════════════════════════════════
# AGENTS
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/agents")
async def create_agent(body: AgentCreate, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        if not await conn.fetchrow("SELECT id FROM policies WHERE tenant_id=$1 AND name=$2", tenant["id"], body.policy):
            raise HTTPException(400, f"Policy '{body.policy}' not found")
    agent_id = f"agent_{uuid.uuid4().hex[:12]}"
    async with pool.acquire() as conn:
        await conn.execute("INSERT INTO agents (id,tenant_id,name,policy,allowed_hosts) VALUES ($1,$2,$3,$4,$5)",
                           agent_id, tenant["id"], body.name, body.policy, body.allowed_hosts or [])
    return {"agent_id": agent_id, "name": body.name, "policy": body.policy}

@app.post("/agents/{agent_id}/register-key")
async def register_key(agent_id: str, body: RegisterKeyRequest, tenant=Depends(get_tenant)):
    try: Ed25519PublicKey.from_public_bytes(b64decode(body.public_key))
    except Exception as e: raise HTTPException(400, f"Invalid Ed25519 public key: {e}")
    async with pool.acquire() as conn:
        agent = await conn.fetchrow("SELECT * FROM agents WHERE id=$1 AND tenant_id=$2", agent_id, tenant["id"])
        if not agent: raise HTTPException(404, "Agent not found")
        if agent["public_key"]:
            await conn.execute("INSERT INTO agent_key_history (id,agent_id,tenant_id,public_key,reason) VALUES ($1,$2,$3,$4,$5)",
                               str(uuid.uuid4()), agent_id, tenant["id"], agent["public_key"], body.rotation_reason or "rotation")
        updates = {"public_key": body.public_key}
        if body.policy:
            if not await conn.fetchrow("SELECT id FROM policies WHERE tenant_id=$1 AND name=$2", tenant["id"], body.policy):
                raise HTTPException(400, f"Policy '{body.policy}' not found")
            updates["policy"] = body.policy
        if body.allowed_hosts is not None:
            updates["allowed_hosts"] = body.allowed_hosts
        set_clause = ", ".join(f"{k}=${i+2}" for i,k in enumerate(updates))
        await conn.execute(f"UPDATE agents SET {set_clause}, updated_at=NOW() WHERE id=$1", agent_id, *updates.values())
    return {"agent_id": agent_id, "registered": True, "rotated": bool(agent["public_key"])}

@app.post("/agents/{agent_id}/revoke")
async def revoke_agent(agent_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        res = await conn.execute("UPDATE agents SET revoked=TRUE, updated_at=NOW() WHERE id=$1 AND tenant_id=$2", agent_id, tenant["id"])
    if res == "UPDATE 0": raise HTTPException(404, "Agent not found")
    return {"agent_id": agent_id, "revoked": True}

@app.get("/agents")
async def list_agents(tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT id,name,policy,allowed_hosts,revoked,created_at FROM agents WHERE tenant_id=$1 ORDER BY created_at DESC", tenant["id"])
    return [dict(r) for r in rows]

@app.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        res = await conn.execute("DELETE FROM agents WHERE id=$1 AND tenant_id=$2", agent_id, tenant["id"])
    if res == "DELETE 0": raise HTTPException(404, "Agent not found")
    return {"deleted": agent_id}

# ══════════════════════════════════════════════════════════════════════════════
# POLICIES
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/policies")
async def create_policy(body: PolicyCreate, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        if await conn.fetchrow("SELECT id FROM policies WHERE tenant_id=$1 AND name=$2", tenant["id"], body.name):
            await conn.execute("UPDATE policies SET rules=$1 WHERE tenant_id=$2 AND name=$3",
                               json.dumps(body.rules), tenant["id"], body.name)
        else:
            await conn.execute("INSERT INTO policies (id,tenant_id,name,rules) VALUES ($1,$2,$3,$4)",
                               str(uuid.uuid4()), tenant["id"], body.name, json.dumps(body.rules))
    return {"name": body.name, "rules": body.rules}

@app.get("/policies")
async def list_policies(tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM policies WHERE tenant_id=$1 ORDER BY name", tenant["id"])
    return [dict(r) for r in rows]

@app.get("/policies/{name}")
async def get_policy(name: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM policies WHERE tenant_id=$1 AND name=$2", tenant["id"], name)
    if not row: raise HTTPException(404, f"Policy '{name}' not found")
    return dict(row)

@app.delete("/policies/{name}")
async def delete_policy(name: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        res = await conn.execute("DELETE FROM policies WHERE tenant_id=$1 AND name=$2", tenant["id"], name)
    if res == "DELETE 0": raise HTTPException(404, "Policy not found")
    return {"deleted": name}

@app.get("/policies/{name}/history")
async def policy_history(name: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM policy_history WHERE tenant_id=$1 AND policy_name=$2 ORDER BY changed_at DESC", tenant["id"], name)
    return [dict(r) for r in rows]

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/audit")
async def audit_logs(tenant=Depends(get_tenant), agent_id: Optional[str]=None,
                      decision: Optional[str]=None, tool: Optional[str]=None, limit: int=100):
    filters = ["tenant_id=$1"]; vals = [tenant["id"]]; i = 2
    for col, val in [("agent_id",agent_id),("decision",decision),("tool",tool)]:
        if val: filters.append(f"{col}=${i}"); vals.append(val); i+=1
    vals.append(min(limit,1000))
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"SELECT * FROM audit_logs WHERE {' AND '.join(filters)} ORDER BY created_at DESC LIMIT ${i}", *vals)
    return [dict(r) for r in rows]

@app.get("/audit/stats")
async def audit_stats(tenant=Depends(get_tenant), agent_id: Optional[str]=None):
    where = "WHERE tenant_id=$1"; vals = [tenant["id"]]
    if agent_id: where += " AND agent_id=$2"; vals.append(agent_id)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(f"""
            SELECT COUNT(*) AS total,
                COUNT(*) FILTER (WHERE decision='allow') AS allowed,
                COUNT(*) FILTER (WHERE decision='deny')  AS denied,
                COUNT(*) FILTER (WHERE decision='pending') AS pending,
                COUNT(*) FILTER (WHERE redacted=true) AS redacted,
                ROUND(AVG(duration_ms)) AS avg_ms,
                ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms)) AS p95_ms
            FROM audit_logs {where}""", *vals)
    return dict(row)

@app.get("/audit/export/json")
async def export_json(tenant=Depends(get_tenant), days: int=30, agent_id: Optional[str]=None):
    where = "WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::INTERVAL"
    vals  = [tenant["id"], str(days)]
    if agent_id: where += " AND agent_id=$3"; vals.append(agent_id)
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"SELECT * FROM audit_logs {where} ORDER BY created_at DESC", *vals)
    data = {"export_date": datetime.now(timezone.utc).isoformat(), "tenant_id": tenant["id"],
            "period_days": days, "total_records": len(rows), "records": [dict(r) for r in rows]}
    content = json.dumps(data, default=str, indent=2).encode()
    return StreamingResponse(iter([content]), media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=agentguard-audit-{days}d.json"})

@app.get("/audit/export/csv")
async def export_csv(tenant=Depends(get_tenant), days: int=30):
    import csv, io
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id,request_id,agent_id,user_id,tool,decision,reason,redacted,duration_ms,created_at"
            " FROM audit_logs WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::INTERVAL"
            " ORDER BY created_at DESC", tenant["id"], str(days))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id","request_id","agent_id","user_id","tool","decision","reason","redacted","duration_ms","created_at"])
    for r in rows:
        writer.writerow([r["id"],r["request_id"],r["agent_id"],r["user_id"],r["tool"],
                         r["decision"],r["reason"],r["redacted"],r["duration_ms"],r["created_at"]])
    return StreamingResponse(iter([output.getvalue().encode()]), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=agentguard-audit-{days}d.csv"})

@app.get("/audit/stats/timeseries")
async def stats_timeseries(tenant=Depends(get_tenant), interval: str="hour", days: int=30, agent_id: Optional[str]=None):
    trunc = {"hour":"hour","day":"day","week":"week"}.get(interval,"hour")
    where = "WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::INTERVAL"
    vals  = [tenant["id"], str(days)]
    if agent_id: where += " AND agent_id=$3"; vals.append(agent_id)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT date_trunc('{trunc}', created_at) AS period, COUNT(*) AS total,"
            f" COUNT(*) FILTER (WHERE decision='allow') AS allowed,"
            f" COUNT(*) FILTER (WHERE decision='deny') AS denied,"
            f" ROUND(AVG(duration_ms)) AS avg_ms"
            f" FROM audit_logs {where} GROUP BY period ORDER BY period ASC", *vals)
    return [dict(r) for r in rows]

@app.get("/audit/stats/by-tool")
async def stats_by_tool(tenant=Depends(get_tenant), days: int=30, agent_id: Optional[str]=None, limit: int=20):
    where = "WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::INTERVAL"
    vals  = [tenant["id"], str(days)]
    if agent_id: where += " AND agent_id=$3"; vals.append(agent_id)
    vals.append(min(limit, 100))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT tool, COUNT(*) AS total,"
            f" COUNT(*) FILTER (WHERE decision='allow') AS allowed,"
            f" COUNT(*) FILTER (WHERE decision='deny') AS denied,"
            f" ROUND(AVG(duration_ms)) AS avg_ms,"
            f" ROUND(100.0 * COUNT(*) FILTER (WHERE decision='deny') / NULLIF(COUNT(*),0), 1) AS deny_rate_pct"
            f" FROM audit_logs {where} GROUP BY tool ORDER BY total DESC LIMIT ${len(vals)}", *vals)
    return [dict(r) for r in rows]

# ══════════════════════════════════════════════════════════════════════════════
# ALERTS, WEBHOOKS, SETTINGS, ADMIN, HEALTH
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/alerts")
async def list_alerts(tenant=Depends(get_tenant), resolved: Optional[bool]=None, limit: int=50):
    where = "WHERE tenant_id=$1"; vals = [tenant["id"]]
    if resolved is not None: where += " AND resolved=$2"; vals.append(resolved)
    vals.append(min(limit, 200))
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"SELECT * FROM anomaly_alerts {where} ORDER BY created_at DESC LIMIT ${len(vals)}", *vals)
    return [dict(r) for r in rows]

@app.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        res = await conn.execute("UPDATE anomaly_alerts SET resolved=TRUE WHERE id=$1 AND tenant_id=$2", alert_id, tenant["id"])
    if res == "UPDATE 0": raise HTTPException(404, "Alert not found")
    return {"resolved": alert_id}

@app.post("/webhooks")
async def create_webhook(body: dict, tenant=Depends(get_tenant)):
    url = body.get("url")
    if not url: raise HTTPException(400, "url is required")
    events = body.get("events", ["deny", "anomaly"])
    async with pool.acquire() as conn:
        wh_id = str(uuid.uuid4()); secret = secrets.token_hex(24)
        await conn.execute("INSERT INTO webhooks (id,tenant_id,url,events,secret) VALUES ($1,$2,$3,$4,$5)",
                           wh_id, tenant["id"], url, events, secret)
    return {"id": wh_id, "url": url, "events": events, "secret": secret}

@app.get("/webhooks")
async def list_webhooks(tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        try:
            rows = await conn.fetch("SELECT id,url,events,active,created_at FROM webhooks WHERE tenant_id=$1", tenant["id"])
            return [dict(r) for r in rows]
        except Exception: return []

@app.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        res = await conn.execute("DELETE FROM webhooks WHERE id=$1 AND tenant_id=$2", webhook_id, tenant["id"])
    if res == "DELETE 0": raise HTTPException(404, "Webhook not found")
    return {"deleted": webhook_id}

@app.get("/settings/retention")
async def get_retention(tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT retention_days FROM tenants WHERE id=$1", tenant["id"])
    return {"retention_days": (row["retention_days"] if row and row["retention_days"] else 90)}

@app.put("/settings/retention")
async def set_retention(body: dict, tenant=Depends(get_tenant)):
    days = int(body.get("days", 90))
    if not 7 <= days <= 3650: raise HTTPException(400, "Retention must be 7-3650 days")
    async with pool.acquire() as conn:
        await conn.execute("UPDATE tenants SET retention_days=$1 WHERE id=$2", days, tenant["id"])
        deleted = await conn.fetchval(
            "WITH d AS (DELETE FROM audit_logs WHERE tenant_id=$1 AND created_at < NOW() - ($2 || ' days')::INTERVAL RETURNING id) SELECT COUNT(*) FROM d",
            tenant["id"], str(days))
    return {"retention_days": days, "purged_records": deleted}

@app.get("/metrics")
async def metrics(x_api_key: str=Header(...)):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, "Admin key required")
    from fastapi.responses import Response
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/admin/tenants")
async def admin_tenants(x_api_key: str=Header(...)):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, "Admin key required")
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT t.id, t.name, t.email, t.plan, t.created_at,
                   COALESCE(t.api_call_count, 0) AS api_call_count, t.last_seen_at,
                   COUNT(DISTINCT a.id) AS agent_count, COUNT(DISTINCT al.id) AS audit_log_count
            FROM tenants t
            LEFT JOIN agents a ON a.tenant_id = t.id
            LEFT JOIN audit_logs al ON al.tenant_id = t.id
            GROUP BY t.id, t.name, t.email, t.plan, t.created_at, t.api_call_count, t.last_seen_at
            ORDER BY t.created_at DESC""")
    return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════════════
# VECTOR INTENT ANCHORING v3.4
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/sessions/{session_id}/anchor")
async def create_intent_anchor(session_id: str, tenant=Depends(get_tenant), threshold: float=0.78):
    """Embed the session intent as the security anchor for zero-latency drift detection."""
    sess = await get_session(session_id, tenant["id"])
    if not sess: raise HTTPException(404, "Session not found or expired")
    intent = sess.get("intent", "")
    if not intent: raise HTTPException(400, "Session has no intent set")
    anchor_vec = await anchor_session_intent(
        session_id, tenant["id"], sess.get("agent_id", ""), intent, threshold)
    non_zero = sum(1 for v in anchor_vec if v != 0.0)
    return {"session_id": session_id, "intent": intent, "threshold": threshold,
            "anchor_dims": len(anchor_vec),
            "anchor_quality": "good" if non_zero >= 15 else "degraded",
            "message": "Anchor set. All tool calls will be checked against this intent vector."}

@app.get("/sessions/{session_id}/anchor")
async def get_anchor_status(session_id: str, tenant=Depends(get_tenant)):
    """Get the current anchor status and recent drift measurements."""
    async with pool.acquire() as conn:
        anchor = await conn.fetchrow(
            "SELECT intent_text, threshold, trip_count, last_distance, last_checked_at"
            " FROM session_intent_anchors WHERE session_id=$1 AND tenant_id=$2",
            session_id, tenant["id"])
        recent_checks = await conn.fetch(
            "SELECT tool, distance, threshold, tripped, turn, created_at"
            " FROM anchor_check_log WHERE session_id=$1 ORDER BY created_at DESC LIMIT 20",
            session_id)
    if not anchor: raise HTTPException(404, "No anchor found for this session")
    return {**dict(anchor), "recent_checks": [dict(r) for r in recent_checks]}

@app.patch("/sessions/{session_id}/anchor/threshold")
async def update_anchor_threshold(session_id: str, body: dict, tenant=Depends(get_tenant)):
    """Tune the drift threshold for a running session without re-anchoring."""
    threshold = float(body.get("threshold", 0.78))
    if not 0.0 <= threshold <= 1.0: raise HTTPException(400, "threshold must be 0.0-1.0")
    async with pool.acquire() as conn:
        res = await conn.execute(
            "UPDATE session_intent_anchors SET threshold=$1 WHERE session_id=$2 AND tenant_id=$3",
            threshold, session_id, tenant["id"])
    if res == "UPDATE 0": raise HTTPException(404, "Anchor not found")
    return {"session_id": session_id, "new_threshold": threshold}

@app.get("/sessions/{session_id}/anchor/trips")
async def get_anchor_trips(session_id: str, tenant=Depends(get_tenant)):
    """Get all anchor trip events for a session."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT tool, distance, threshold, turn, created_at"
            " FROM anchor_check_log WHERE session_id=$1 AND tripped=TRUE ORDER BY created_at DESC",
            session_id)
    return [dict(r) for r in rows]

@app.get("/anchors/stats")
async def anchor_stats(tenant=Depends(get_tenant), days: int=30):
    """Anchor drift stats across all sessions."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS total_checks,"
            " COUNT(*) FILTER (WHERE tripped=TRUE) AS total_trips,"
            " ROUND(AVG(distance)::numeric,4) AS avg_distance,"
            " ROUND(MAX(distance)::numeric,4) AS max_distance,"
            " COUNT(DISTINCT session_id) AS sessions_checked"
            " FROM anchor_check_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
        top_trippers = await conn.fetch(
            "SELECT session_id, agent_id, tool, distance, created_at"
            " FROM anchor_check_log WHERE tenant_id=$1 AND tripped=TRUE"
            " AND created_at > NOW() - ($2||' days')::INTERVAL"
            " ORDER BY created_at DESC LIMIT 10",
            tenant["id"], str(days))
    return {**dict(row), "recent_trips": [dict(r) for r in top_trippers]}

# ══════════════════════════════════════════════════════════════════════════════
# HONEY-TOOLS v3.4
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/agents/{agent_id}/honey-tools")
async def configure_honey_tools(agent_id: str, body: HoneyToolConfig, tenant=Depends(get_tenant)):
    """Configure honey (trap) tools for an agent. Any call to them = confirmed injection."""
    async with pool.acquire() as conn:
        agent = await conn.fetchrow("SELECT id FROM agents WHERE id=$1 AND tenant_id=$2", agent_id, tenant["id"])
    if not agent: raise HTTPException(404, "Agent not found")
    honey_tools = body.honey_tools
    if not honey_tools:
        async with pool.acquire() as conn:
            sp = await conn.fetchrow(
                "SELECT inferred_tools FROM synthesized_policies"
                " WHERE tenant_id=$1 AND status='active' ORDER BY activated_at DESC LIMIT 1",
                tenant["id"])
        legitimate = list(sp["inferred_tools"]) if sp else []
        honey_tools = await generate_honey_tools(tenant["id"], agent_id, legitimate, count=5)
    else:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO honey_tool_configs (tenant_id,agent_id,honey_tools,auto_generated,enabled)"
                " VALUES ($1,$2,$3,FALSE,$4)"
                " ON CONFLICT (agent_id) DO UPDATE SET honey_tools=$3, enabled=$4, updated_at=NOW()",
                tenant["id"], agent_id, json.dumps(honey_tools), body.enabled)
    return {"agent_id": agent_id, "honey_tools": honey_tools, "count": len(honey_tools),
            "enabled": body.enabled,
            "message": "Honey tools active. Any call to these will instantly flag a session as compromised."}

@app.get("/agents/{agent_id}/honey-tools")
async def get_honey_tools_config(agent_id: str, tenant=Depends(get_tenant)):
    """Get the honey tools configured for an agent."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT honey_tools, auto_generated, enabled, updated_at"
            " FROM honey_tool_configs WHERE agent_id=$1 AND tenant_id=$2",
            agent_id, tenant["id"])
    if not row: raise HTTPException(404, "No honey tools configured for this agent")
    return dict(row)

@app.delete("/agents/{agent_id}/honey-tools")
async def disable_honey_tools(agent_id: str, tenant=Depends(get_tenant)):
    """Disable honey tools for an agent."""
    async with pool.acquire() as conn:
        res = await conn.execute(
            "UPDATE honey_tool_configs SET enabled=FALSE, updated_at=NOW()"
            " WHERE agent_id=$1 AND tenant_id=$2", agent_id, tenant["id"])
    if res == "UPDATE 0": raise HTTPException(404, "No honey tools found")
    return {"agent_id": agent_id, "enabled": False}

@app.get("/honey-tools/trips")
async def list_honey_trips(tenant=Depends(get_tenant), agent_id: Optional[str]=None,
                            days: int=30, limit: int=100):
    """List all honey-tool trip events. Each trip = 100% confirmed injection attempt."""
    where = "WHERE tenant_id=$1 AND created_at > NOW() - ($2||' days')::INTERVAL"
    vals  = [tenant["id"], str(days)]
    if agent_id: where += " AND agent_id=$3"; vals.append(agent_id)
    vals.append(min(limit, 500))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT * FROM honey_tool_trips {where} ORDER BY created_at DESC LIMIT ${len(vals)}", *vals)
    return [dict(r) for r in rows]

@app.get("/honey-tools/stats")
async def honey_tool_stats(tenant=Depends(get_tenant), days: int=30):
    """Honey-tool trip statistics."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS total_trips,"
            " COUNT(DISTINCT session_id) AS sessions_compromised,"
            " COUNT(DISTINCT agent_id) AS agents_targeted,"
            " COUNT(DISTINCT honey_tool) AS unique_traps_triggered"
            " FROM honey_tool_trips WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
        by_tool = await conn.fetch(
            "SELECT honey_tool, COUNT(*) AS trips FROM honey_tool_trips"
            " WHERE tenant_id=$1 AND created_at > NOW() - ($2||' days')::INTERVAL"
            " GROUP BY honey_tool ORDER BY trips DESC", tenant["id"], str(days))
    return {**dict(row), "by_trap": [dict(r) for r in by_tool]}

# ══════════════════════════════════════════════════════════════════════════════
# CITATION-LEVEL GROUNDING v3.4
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/guardrails/grounding/citation-check")
async def citation_grounding_check(body: OutputScanRequest, tenant=Depends(get_tenant), threshold: float=0.5):
    """Citation-level grounding. Maps every sentence to a source doc. Bedrock-equivalent."""
    result = await check_grounding_with_citations(
        body.content, tenant["id"], body.session_id, body.agent_id, threshold)
    return result

@app.get("/guardrails/grounding/citations/stats")
async def citation_grounding_stats(tenant=Depends(get_tenant), days: int=30):
    """Citation grounding stats — support ratios over time."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS total_checks,"
            " ROUND(AVG(support_ratio)::numeric,4) AS avg_support_ratio,"
            " ROUND(MIN(support_ratio)::numeric,4) AS min_support_ratio,"
            " SUM(total_sentences) AS total_sentences_checked,"
            " SUM(unsupported) AS total_unsupported_sentences"
            " FROM grounding_citation_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
        recent = await conn.fetch(
            "SELECT session_id, agent_id, total_sentences, supported, unsupported, support_ratio, created_at"
            " FROM grounding_citation_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL"
            " ORDER BY created_at DESC LIMIT 20", tenant["id"], str(days))
    return {**dict(row), "recent_checks": [dict(r) for r in recent]}

@app.get("/guardrails/grounding/citations/{session_id}")
async def get_session_citation_history(session_id: str, tenant=Depends(get_tenant)):
    """Get full citation grounding history for a session."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM grounding_citation_log WHERE tenant_id=$1 AND session_id=$2 ORDER BY created_at DESC",
            tenant["id"], session_id)
    return [dict(r) for r in rows]

# ══════════════════════════════════════════════════════════════════════════════
# POLICY CONFLICT DETECTION v3.4
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/policies/{name}/check-conflicts")
async def check_policy_conflicts(name: str, tenant=Depends(get_tenant),
                                   synthesized_policy_id: Optional[str]=None):
    """Detect conflicts in a policy — allow/deny overlaps, read_only violations, unreachable tools."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT name, rules FROM policies WHERE tenant_id=$1 AND name=$2", tenant["id"], name)
    if not row: raise HTTPException(404, f"Policy '{name}' not found")
    rules = json.loads(row["rules"]) if isinstance(row["rules"], str) else dict(row["rules"])
    synthesized_tools = None
    if synthesized_policy_id:
        async with pool.acquire() as conn:
            sp = await conn.fetchrow(
                "SELECT inferred_tools FROM synthesized_policies WHERE id=$1 AND tenant_id=$2",
                synthesized_policy_id, tenant["id"])
        if sp: synthesized_tools = list(sp["inferred_tools"] or [])
    return await detect_policy_conflicts(name, rules, tenant["id"], synthesized_tools)

@app.post("/policies/validate")
async def validate_policy_rules(body: PolicyCreate, tenant=Depends(get_tenant)):
    """Validate a policy rules dict BEFORE saving it. Returns conflict report."""
    report = await detect_policy_conflicts(body.name, body.rules, tenant["id"])
    return {"valid": not report.has_conflicts, "report": report,
            "message": "Policy has no conflicts — safe to save." if not report.has_conflicts
                       else f"Policy has {report.conflict_count} conflict(s). Review before saving."}

@app.get("/policies/conflicts/history")
async def conflict_check_history(tenant=Depends(get_tenant), limit: int=50):
    """History of all policy conflict checks for this tenant."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT policy_name, conflict_count, checked_at FROM policy_conflict_log"
            " WHERE tenant_id=$1 ORDER BY checked_at DESC LIMIT $2",
            tenant["id"], min(limit, 200))
    return [dict(r) for r in rows]

@app.post("/policies/synthesize/{policy_id}/check-conflicts")
async def check_synthesized_conflicts(policy_id: str, tenant=Depends(get_tenant),
                                        target_policy: Optional[str]=None):
    """Check if a synthesized policy conflicts with an existing active policy."""
    async with pool.acquire() as conn:
        sp = await conn.fetchrow(
            "SELECT * FROM synthesized_policies WHERE id=$1 AND tenant_id=$2", policy_id, tenant["id"])
    if not sp: raise HTTPException(404, "Synthesized policy not found")
    rules = sp["rules"]
    if isinstance(rules, str): rules = json.loads(rules)
    elif not isinstance(rules, dict): rules = dict(rules)
    synthesized_tools = list(sp["inferred_tools"] or [])
    report = await detect_policy_conflicts(sp["name"], rules, tenant["id"], synthesized_tools)
    target_report = None
    if target_policy:
        async with pool.acquire() as conn:
            tp_row = await conn.fetchrow(
                "SELECT rules FROM policies WHERE tenant_id=$1 AND name=$2", tenant["id"], target_policy)
        if tp_row:
            target_rules = json.loads(tp_row["rules"]) if isinstance(tp_row["rules"], str) else dict(tp_row["rules"])
            target_report = await detect_policy_conflicts(target_policy, target_rules, tenant["id"], synthesized_tools)
    return {"synthesized_policy": report, "target_policy_check": target_report,
            "safe_to_activate": not report.has_conflicts and
                                 (target_report is None or not target_report.has_conflicts)}

# ══════════════════════════════════════════════════════════════════════════════
# PROXY v3.4 — full pipeline
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/proxy/chat/v4")
@limiter.limit("300/minute;30/second")
async def proxy_chat_v4(req: ProxyRequestV31, request: Request,
                          bg: BackgroundTasks, tenant=Depends(get_tenant)):
    """Full v3.4 proxy: honey injection + semantic + vector anchor + citation grounding."""
    start = time.monotonic(); tid = tenant["id"]
    honey_tools = []
    honey_system = req.system
    if req.agent_id:
        honey_tools = await _get_honey_tools(tid, req.agent_id)
        if honey_tools:
            honey_system = inject_honey_tools(req.system, honey_tools)
    safe_messages, safe_system, input_report = await run_semantic_guardrails(
        req.messages, honey_system, tid, req.agent_id, req.session_id, tokenize=req.tokenize_pii)
    if input_report.get("blocked"):
        ms = int((time.monotonic()-start)*1000)
        return JSONResponse(status_code=400, content={"allowed": False, "blocked_at": "input",
            "reason": input_report.get("reason"), "layer": input_report.get("layer"),
            "confidence": input_report.get("confidence"), "policy": input_report.get("policy"),
            "duration_ms": ms})
    if req.dry_run:
        return {"dry_run": True, "input_report": input_report,
                "honey_tools_injected": len(honey_tools), "messages_after_guardrails": len(safe_messages)}
    try:
        client = anthropic.AsyncAnthropic()
        build_kwargs = dict(model=req.model, max_tokens=req.max_tokens, messages=safe_messages)
        if safe_system: build_kwargs["system"] = safe_system
        msg = await asyncio.wait_for(client.messages.create(**build_kwargs), timeout=120.0)
        llm_response      = msg.content[0].text if msg.content else ""
        prompt_tokens     = msg.usage.input_tokens
        completion_tokens = msg.usage.output_tokens
    except Exception as e:
        log.error("proxy_v4.llm_error", error=str(e))
        return JSONResponse(status_code=502, content={"error": f"LLM error: {type(e).__name__}"})
    honey_in_output = False
    if req.agent_id and req.session_id and honey_tools:
        for ht in honey_tools:
            if ht.lower() in llm_response.lower():
                is_honey, honey_reason = await check_honey_tool_call(
                    ht, req.session_id, tid, req.agent_id, {}, llm_response[:200], 0)
                if is_honey:
                    honey_in_output = True
                    llm_response = f"[SESSION TERMINATED: {honey_reason}]"
                    break
    safe_response, output_report = await run_output_semantic_guardrails(
        llm_response, tid, req.agent_id, req.session_id,
        detokenize_pii=req.tokenize_pii, check_ground=False,
        grounding_threshold=req.grounding_threshold)
    citation_result = None
    if req.check_grounding and not honey_in_output:
        citation_result = await check_grounding_with_citations(
            safe_response, tid, req.session_id, req.agent_id, threshold=req.grounding_threshold)
        if not citation_result.grounded:
            safe_response = (
                ("[GROUNDING WARNING: "
                 + f"{citation_result.support_ratio:.0%} supported "
                 f"({citation_result.supported}/{citation_result.total_sentences} sentences). "
                 "Unsupported claims detected.\n\n"
                 + safe_response))
    ms = int((time.monotonic()-start)*1000)
    LATENCY.labels(endpoint="proxy_v4").observe(ms/1000)
    response_body = {"content": safe_response, "model": req.model,
                     "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                               "total_tokens": prompt_tokens+completion_tokens},
                     "guardrails": {"input": input_report, "output": output_report,
                                    "honey_tool_tripped": honey_in_output},
                     "duration_ms": ms}
    if citation_result:
        response_body["grounding"] = {"grounded": citation_result.grounded,
                                       "support_ratio": citation_result.support_ratio,
                                       "total_sentences": citation_result.total_sentences,
                                       "supported": citation_result.supported,
                                       "unsupported": citation_result.unsupported,
                                       "citations": citation_result.citations,
                                       "summary": citation_result.summary}
    return response_body


# ══════════════════════════════════════════════════════════════════════════════
# MULTI-MODEL + STREAMING v3.5
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/models")
async def list_models(tenant=Depends(get_tenant)):
    """List all supported models by provider."""
    ollama_available = await list_ollama_models()
    result = {}
    for provider, models in PROVIDER_MAP.items():
        env_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai":    "OPENAI_API_KEY",
            "gemini":    "GEMINI_API_KEY",
            "groq":      "GROQ_API_KEY",
            "ollama":    "OLLAMA_BASE_URL",
        }
        env_key = env_map.get(provider, "")
        result[provider] = {
            "models":    models if provider != "ollama" else ollama_available,
            "configured": bool(os.environ.get(env_key)) if env_key else True,
            "env_var":   env_key,
        }
    return result

@app.get("/models/ollama/available")
async def get_ollama_models(tenant=Depends(get_tenant)):
    """List models currently available in the local Ollama instance."""
    models = await list_ollama_models()
    base   = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    return {"base_url": base, "models": models, "count": len(models),
            "reachable": len(models) > 0 or models is not None}

@app.get("/models/{model:path}/validate")
async def validate_model_endpoint(model: str, tenant=Depends(get_tenant)):
    """Validate a model string — returns provider, env var needed, and readiness."""
    return await validate_model(model)

@app.get("/models/usage/stats")
async def model_usage_stats(tenant=Depends(get_tenant), days: int=30):
    """Token usage and request counts broken down by provider and model."""
    async with pool.acquire() as conn:
        by_provider = await conn.fetch(
            "SELECT provider, model,"
            " COUNT(*) AS requests,"
            " SUM(prompt_tokens) AS prompt_tokens,"
            " SUM(completion_tokens) AS completion_tokens,"
            " SUM(total_tokens) AS total_tokens,"
            " ROUND(AVG(duration_ms)) AS avg_ms,"
            " COUNT(*) FILTER (WHERE streaming=TRUE) AS streaming_requests,"
            " COUNT(*) FILTER (WHERE guardrail_blocked=TRUE) AS blocked_requests"
            " FROM model_usage_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL"
            " GROUP BY provider, model ORDER BY requests DESC",
            tenant["id"], str(days))
        totals = await conn.fetchrow(
            "SELECT SUM(total_tokens) AS total_tokens,"
            " COUNT(*) AS total_requests,"
            " COUNT(*) FILTER (WHERE streaming=TRUE) AS streaming_requests"
            " FROM model_usage_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
    return {"totals": dict(totals), "by_provider_model": [dict(r) for r in by_provider]}

# ══════════════════════════════════════════════════════════════════════════════
# NON-STREAMING MULTI-MODEL PROXY (replaces existing v2/v3/v4 for all providers)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/proxy/chat")
@limiter.limit("300/minute;30/second")
async def proxy_chat(req: ProxyRequestV31, request: Request,
                     bg: BackgroundTasks, tenant=Depends(get_tenant)):
    """
    Universal non-streaming proxy. Supports all providers via model string.
    Runs full semantic guardrail pipeline (equivalent to v3 but multi-model).
    Use /proxy/chat/v4 for the full v3.4 pipeline with honey-tools + anchoring.
    """
    start = time.monotonic()
    tid   = tenant["id"]

    # Input guardrails
    safe_messages, safe_system, input_report = await run_semantic_guardrails(
        req.messages, req.system, tid, req.agent_id, req.session_id,
        tokenize=req.tokenize_pii)

    if input_report.get("blocked"):
        ms = int((time.monotonic()-start)*1000)
        return JSONResponse(status_code=400, content={
            "allowed": False, "blocked_at": "input",
            "reason": input_report.get("reason"), "layer": input_report.get("layer"),
            "duration_ms": ms})

    if req.dry_run:
        provider = detect_provider(req.model)
        return {"dry_run": True, "input_report": input_report,
                "model": req.model, "provider": provider}

    # Route to provider
    try:
        response = await route_completion(
            model=req.model, messages=safe_messages, system=safe_system,
            max_tokens=req.max_tokens)
    except Exception as e:
        log.error("proxy_chat.llm_error", model=req.model, error=str(e))
        return JSONResponse(status_code=502, content={"error": str(e)})

    # Output guardrails
    safe_response, output_report = await run_output_semantic_guardrails(
        response.content, tid, req.agent_id, req.session_id,
        detokenize_pii=req.tokenize_pii,
        check_ground=req.check_grounding,
        grounding_threshold=req.grounding_threshold)

    ms = int((time.monotonic()-start)*1000)
    LATENCY.labels(endpoint="proxy_chat").observe(ms/1000)

    bg.add_task(_log_model_usage, tid, req.session_id, req.agent_id,
                response.model, response.provider,
                response.prompt_tokens, response.completion_tokens,
                False, ms, response.finish_reason, False)

    return {"content": safe_response, "model": response.model,
            "provider": response.provider,
            "usage": {"prompt_tokens": response.prompt_tokens,
                      "completion_tokens": response.completion_tokens,
                      "total_tokens": response.total_tokens},
            "guardrails": {"input": input_report, "output": output_report},
            "duration_ms": ms}

# ══════════════════════════════════════════════════════════════════════════════
# STREAMING PROXY ENDPOINTS
# All return Server-Sent Events (SSE) stream.
# Client reads: event: token / data: {"delta": "..."}
#               event: done  / data: {"usage": {...}, "guardrails": {...}}
#               event: blocked / data: {"reason": "...", "layer": "..."}
#               event: error / data: {"message": "..."}
# ══════════════════════════════════════════════════════════════════════════════

async def _stream_with_guardrails(
    req:        StreamProxyRequest,
    tid:        str,
    pipeline:   str,           # "v2" | "v3" | "v4"
    bg:         BackgroundTasks,
) -> AsyncIterator[str]:
    """
    Core streaming generator. Handles all three pipeline tiers.
    Yields SSE-formatted strings.

    Pipeline:
      v2 — keyword + PII + binary grounding
      v3 — keyword + semantic + PII + grounding
      v4 — honey injection + semantic + anchor + citation grounding
    """
    start = time.monotonic()

    # ── Pre-stream: inject honey tools (v4 only) ──────────────────────────────
    honey_tools  = []
    active_system = req.system

    if pipeline == "v4" and req.agent_id:
        honey_tools = await _get_honey_tools(tid, req.agent_id)
        if honey_tools:
            active_system = inject_honey_tools(req.system, honey_tools)

    # ── Input guardrails ──────────────────────────────────────────────────────
    if pipeline == "v2":
        safe_messages, safe_system, input_report = await run_input_guardrails(
            req.messages, active_system, tid, req.agent_id, req.session_id,
            tokenize=req.tokenize_pii)
    else:
        # v3 and v4 both use semantic guardrails
        safe_messages, safe_system, input_report = await run_semantic_guardrails(
            req.messages, active_system, tid, req.agent_id, req.session_id,
            tokenize=req.tokenize_pii)

    if input_report.get("blocked"):
        yield sse_blocked(
            reason=input_report.get("reason", "blocked"),
            layer=input_report.get("layer", "input"),
        )
        return

    if req.stream_guardrail_events:
        yield sse_guardrail("input_passed", {"pipeline": pipeline,
                                              "pii_tokenized": req.tokenize_pii})

    if req.dry_run:
        provider = detect_provider(req.model)
        yield build_sse_event({"type": "dry_run", "input_report": input_report,
                                "model": req.model, "provider": provider,
                                "honey_tools_injected": len(honey_tools)}, event="dry_run")
        return

    # ── Stream from LLM ───────────────────────────────────────────────────────
    buffer        = []
    prompt_toks   = 0
    compl_toks    = 0
    finish_reason = "stop"
    provider      = detect_provider(req.model)

    try:
        async for chunk in route_stream(
            model=req.model, messages=safe_messages, system=safe_system,
            max_tokens=req.max_tokens,
            temperature=req.temperature,
        ):
            if chunk.finish_reason:
                finish_reason = chunk.finish_reason
                prompt_toks   = chunk.prompt_tokens
                compl_toks    = chunk.completion_tokens

            if chunk.delta:
                buffer.append(chunk.delta)

                if req.buffer_output:
                    # Buffer mode — don't forward until we have the full response
                    # (guardrails run on complete text)
                    pass
                else:
                    # Passthrough mode — forward immediately, scan async after
                    yield sse_token(chunk.delta, req.model, provider)

    except Exception as e:
        log.error("stream.llm_failed", model=req.model, error=str(e))
        yield sse_error(f"LLM error: {type(e).__name__}: {str(e)[:200]}", "llm_error")
        return

    full_response = "".join(buffer)

    # ── Honey-tool scan on output (v4) ────────────────────────────────────────
    honey_tripped = False
    if pipeline == "v4" and req.agent_id and req.session_id and honey_tools:
        for ht in honey_tools:
            if ht.lower() in full_response.lower():
                is_honey, honey_reason = await check_honey_tool_call(
                    ht, req.session_id, tid, req.agent_id,
                    {}, full_response[:200], 0)
                if is_honey:
                    honey_tripped = True
                    full_response = f"[SESSION TERMINATED: {honey_reason}]"
                    yield sse_blocked(honey_reason, "honey_tool", "honey_tool_trip")
                    break

    # ── Output guardrails ─────────────────────────────────────────────────────
    citation_level = (pipeline == "v4")
    safe_response, guardrail_report = await run_streaming_guardrails(
        full_response, tid, req.agent_id, req.session_id,
        detokenize_pii=req.tokenize_pii,
        check_ground=req.check_grounding and not honey_tripped,
        grounding_threshold=req.grounding_threshold,
        citation_level=citation_level,
    )

    output_blocked = guardrail_report.get("output", {}).get("blocked", False)
    if output_blocked:
        yield sse_blocked(
            reason=guardrail_report.get("output", {}).get("reason", "output blocked"),
            layer=guardrail_report.get("output", {}).get("layer", "output_gate"),
        )
        # Still send done so client knows stream ended
        ms = int((time.monotonic()-start)*1000)
        bg.add_task(_log_model_usage, tid, req.session_id, req.agent_id,
                    req.model, provider, prompt_toks, compl_toks, True, ms, finish_reason, True)
        yield sse_done(req.model, provider, prompt_toks, compl_toks,
                       {"input": input_report, **guardrail_report,
                        "honey_tool_tripped": honey_tripped})
        return

    # ── Stream buffered tokens to client ─────────────────────────────────────
    if req.buffer_output:
        # Send the safe response in chunks of ~20 chars to feel like streaming
        CHUNK_SIZE = 20
        for i in range(0, len(safe_response), CHUNK_SIZE):
            yield sse_token(safe_response[i:i+CHUNK_SIZE], req.model, provider)
            await asyncio.sleep(0)  # yield control between chunks

    # ── Done event ────────────────────────────────────────────────────────────
    ms = int((time.monotonic()-start)*1000)
    LATENCY.labels(endpoint=f"proxy_stream_{pipeline}").observe(ms/1000)

    guardrail_report["input"] = input_report
    if pipeline == "v4":
        guardrail_report["honey_tool_tripped"] = honey_tripped

    yield sse_done(req.model, provider, prompt_toks, compl_toks, guardrail_report)

    # Log async
    bg.add_task(_log_model_usage, tid, req.session_id, req.agent_id,
                req.model, provider, prompt_toks, compl_toks,
                True, ms, finish_reason, False)


@app.post("/proxy/chat/v2/stream")
@limiter.limit("200/minute;20/second")
async def proxy_chat_v2_stream(req: StreamProxyRequest, request: Request,
                                bg: BackgroundTasks, tenant=Depends(get_tenant)):
    """
    Streaming v2: keyword firewall + PII + output gate + binary grounding.
    Supports all providers (Anthropic, OpenAI, Gemini, Groq, Ollama).
    Returns Server-Sent Events stream.
    """
    tid = tenant["id"]
    return StreamingResponse(
        _stream_with_guardrails(req, tid, "v2", bg),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


@app.post("/proxy/chat/v3/stream")
@limiter.limit("200/minute;20/second")
async def proxy_chat_v3_stream(req: StreamProxyRequest, request: Request,
                                bg: BackgroundTasks, tenant=Depends(get_tenant)):
    """
    Streaming v3: full semantic pipeline + all providers.
    keyword + semantic classifier + PII + injection scan + grounding.
    Returns Server-Sent Events stream.
    """
    tid = tenant["id"]
    return StreamingResponse(
        _stream_with_guardrails(req, tid, "v3", bg),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


@app.post("/proxy/chat/v4/stream")
@limiter.limit("200/minute;20/second")
async def proxy_chat_v4_stream(req: StreamProxyRequest, request: Request,
                                bg: BackgroundTasks, tenant=Depends(get_tenant)):
    """
    Streaming v4: complete pipeline + all providers.
    honey injection → semantic → anchor check → citation grounding.
    Returns Server-Sent Events stream.

    SSE Event types:
      token    — {"delta": "...", "model": "...", "provider": "..."}
      done     — {"usage": {...}, "guardrails": {...}}
      blocked  — {"reason": "...", "layer": "..."}
      guardrail — {"event": "input_passed", ...}
      error    — {"message": "..."}
    """
    tid = tenant["id"]
    return StreamingResponse(
        _stream_with_guardrails(req, tid, "v4", bg),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


@app.get("/proxy/stream/stats")
async def stream_stats(tenant=Depends(get_tenant), days: int=30):
    """Streaming session stats."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS total_requests,"
            " COUNT(*) FILTER (WHERE streaming=TRUE) AS streaming_requests,"
            " COUNT(*) FILTER (WHERE streaming=FALSE) AS sync_requests,"
            " SUM(total_tokens) FILTER (WHERE streaming=TRUE) AS streaming_tokens,"
            " COUNT(DISTINCT model) AS unique_models,"
            " COUNT(DISTINCT provider) AS unique_providers"
            " FROM model_usage_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
    return dict(row)



# ══════════════════════════════════════════════════════════════════════════════
# SECURITY MODEL CONFIG + PASSTHROUGH STREAMING v3.5
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/settings/security-model")
async def get_security_model(tenant=Depends(get_tenant)):
    """
    Get the model AgentGuard uses internally for security checks.
    This is NOT the model your agent uses — it's what AgentGuard uses
    for semantic analysis, grounding checks, injection detection, etc.
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT security_model, security_provider FROM tenants WHERE id=$1",
            tenant["id"])
        override = await conn.fetchrow(
            "SELECT * FROM tenant_security_config WHERE tenant_id=$1",
            tenant["id"])

    base_model    = row["security_model"]    if row else "claude-haiku-4-5-20251001"
    base_provider = row["security_provider"] if row else "anthropic"

    supported_models = {
        "anthropic": ["claude-haiku-4-5-20251001", "claude-sonnet-4-6"],
        "openai":    ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"],
        "gemini":    ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash"],
        "groq":      ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
        "ollama":    ["llama3", "mistral", "mixtral", "phi3"],
    }

    return {
        "security_model":    base_model,
        "security_provider": base_provider,
        "per_check_overrides": {
            "semantic_model":   override["semantic_model"]   if override else None,
            "embedding_model":  override["embedding_model"]  if override else None,
            "grounding_model":  override["grounding_model"]  if override else None,
            "drift_model":      override["drift_model"]      if override else None,
            "citation_model":   override["citation_model"]   if override else None,
        } if override else {},
        "supported_models":  supported_models,
        "note": (
            "This configures which model AgentGuard uses for its own internal security "
            "checks (semantic analysis, grounding, drift detection). Your agent's LLM "
            "is unaffected — it stays whatever you've already configured."
        ),
    }

@app.put("/settings/security-model")
async def update_security_model(body: dict, tenant=Depends(get_tenant)):
    """
    Update the model AgentGuard uses internally for security checks.

    Body:
      security_model:    str  — model name e.g. "gpt-4o-mini", "gemini-1.5-flash"
      security_provider: str  — "anthropic" | "openai" | "gemini" | "groq" | "ollama"

    Affects ALL internal AgentGuard checks for this tenant going forward.
    Use /settings/security-model/overrides for per-check granularity.
    """
    model    = body.get("security_model", "claude-haiku-4-5-20251001")
    provider = body.get("security_provider", "anthropic")

    valid_providers = {"anthropic", "openai", "gemini", "groq", "ollama"}
    if provider not in valid_providers:
        raise HTTPException(400, f"provider must be one of: {', '.join(valid_providers)}")

    # Validate the API key exists for the chosen provider
    env_map = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai":    "OPENAI_API_KEY",
        "gemini":    "GEMINI_API_KEY",
        "groq":      "GROQ_API_KEY",
        "ollama":    None,
    }
    env_key = env_map.get(provider)
    if env_key and not os.environ.get(env_key):
        raise HTTPException(400,
            f"Provider '{provider}' requires {env_key} environment variable. "
            f"Set it in your Railway environment variables first.")

    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE tenants SET security_model=$1, security_provider=$2 WHERE id=$3",
            model, provider, tenant["id"])

    # Invalidate cache
    invalidate_security_cache(tenant["id"])

    return {
        "security_model":    model,
        "security_provider": provider,
        "message": f"AgentGuard will now use {model} ({provider}) for all internal security checks.",
    }

@app.put("/settings/security-model/overrides")
async def update_security_model_overrides(body: dict, tenant=Depends(get_tenant)):
    """
    Set per-check model overrides.
    Useful if you want a faster model for semantic checks but a smarter one for grounding.

    Body (all optional — null clears the override and uses the default):
      semantic_model:   str | null  — model for semantic topic classification
      embedding_model:  str | null  — model for embedding (intent anchor, semantic similarity)
      grounding_model:  str | null  — model for grounding checks
      drift_model:      str | null  — model for intent drift scoring (Haiku fallback)
      citation_model:   str | null  — model for citation-level grounding
      ollama_base_url:  str | null  — Ollama endpoint if using local models
      max_tokens_check: int         — max tokens for internal check responses (default 300)
      check_timeout_s:  float       — timeout in seconds for internal checks (default 8.0)
    """
    fields = ["semantic_model", "embedding_model", "grounding_model",
              "drift_model", "citation_model", "ollama_base_url",
              "max_tokens_check", "check_timeout_s"]

    update_vals = {k: body.get(k) for k in fields if k in body}

    if not update_vals:
        raise HTTPException(400, "No valid fields provided. "
                            f"Valid fields: {', '.join(fields)}")

    async with pool.acquire() as conn:
        # Upsert
        await conn.execute(
            "INSERT INTO tenant_security_config (tenant_id) VALUES ($1)"
            " ON CONFLICT (tenant_id) DO NOTHING",
            tenant["id"])

        for field, value in update_vals.items():
            await conn.execute(
                f"UPDATE tenant_security_config SET {field}=$1, updated_at=NOW()"
                f" WHERE tenant_id=$2",
                value, tenant["id"])

    invalidate_security_cache(tenant["id"])

    return {
        "updated":  list(update_vals.keys()),
        "values":   update_vals,
        "message":  "Per-check model overrides updated. Changes take effect immediately.",
    }

@app.delete("/settings/security-model/overrides")
async def clear_security_model_overrides(tenant=Depends(get_tenant)):
    """Clear all per-check model overrides. Revert to the tenant default model."""
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE tenant_security_config"
            " SET semantic_model=NULL, embedding_model=NULL, grounding_model=NULL,"
            "     drift_model=NULL, citation_model=NULL, updated_at=NOW()"
            " WHERE tenant_id=$1",
            tenant["id"])
    invalidate_security_cache(tenant["id"])
    return {"message": "All per-check overrides cleared. Using tenant default model."}

@app.get("/settings/security-model/test")
async def test_security_model(tenant=Depends(get_tenant), check_type: str = "default"):
    """
    Test the configured security model by running a quick check.
    Validates the model is reachable and the API key works.
    check_type: default | semantic | embedding | grounding | drift | citation
    """
    start = time.monotonic()
    model, provider = await get_tenant_security_model(tenant["id"], check_type)
    try:
        result = await call_security_llm(
            prompt='Respond with exactly: {"status":"ok"}',
            tenant_id=tenant["id"],
            check_type=check_type,
            max_tokens=20,
            timeout=10.0,
        )
        ms = int((time.monotonic() - start) * 1000)
        return {
            "reachable":   True,
            "model":       model,
            "provider":    provider,
            "check_type":  check_type,
            "response":    result[:100],
            "duration_ms": ms,
        }
    except Exception as e:
        ms = int((time.monotonic() - start) * 1000)
        return {
            "reachable":   False,
            "model":       model,
            "provider":    provider,
            "check_type":  check_type,
            "error":       str(e),
            "duration_ms": ms,
        }

# ══════════════════════════════════════════════════════════════════════════════
# PASSTHROUGH STREAMING PROXY ENDPOINTS
# These sit in front of the USER's agent and transparently forward
# streaming responses while scanning for injection and running output gate
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/proxy/passthrough")
@limiter.limit("300/minute;30/second")
async def proxy_passthrough(
    req: StreamPassthroughRequest,
    request: Request,
    bg: BackgroundTasks,
    tenant=Depends(get_tenant),
):
    """
    Transparent passthrough proxy to the user's own agent.

    This is what the CLI proxy uses internally. It:
    1. Scans the request for injection before forwarding
    2. Forwards the request to the user's agent (target_url)
    3. Scans each response chunk for injection patterns as they arrive
    4. Buffers the complete response and runs the output gate
    5. Returns clean content — streaming if the agent streams, sync if not

    The user's agent uses ITS OWN LLM. AgentGuard never touches their LLM call.
    AgentGuard only scans what goes in and what comes out.

    Body:
      target_url:   str   — where the user's agent is running (e.g. http://localhost:8080/chat)
      method:       str   — HTTP method (default POST)
      headers:      dict  — headers to forward (sensitive ones stripped automatically)
      body:         dict  — request body to forward
      agent_id:     str   — AgentGuard agent ID for policy + logging
      session_id:   str   — AgentGuard session ID for tracking
      scan_input:   bool  — scan request body for injection (default true)
      scan_output:  bool  — run output gate on response (default true)
      scan_chunks:  bool  — scan each chunk as it arrives (default true)
      buffer_for_gate: bool — buffer full response for output gate (default true)
    """
    tid = tenant["id"]

    # Validate target URL against agent's allowed_hosts
    if req.agent_id:
        async with pool.acquire() as conn:
            agent = await conn.fetchrow(
                "SELECT allowed_hosts FROM agents WHERE id=$1 AND tenant_id=$2",
                req.agent_id, tid)
        if agent:
            from urllib.parse import urlparse
            parsed_host = urlparse(req.target_url).hostname or ""
            allowed     = list(agent["allowed_hosts"] or [])
            # localhost always allowed for development
            local_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
            if allowed and parsed_host not in allowed and parsed_host not in local_hosts:
                raise HTTPException(403,
                    f"Target host '{parsed_host}' not in agent's allowed_hosts. "
                    f"Register it via POST /agents/{req.agent_id}/register-key")

    forward_headers = dict(request.headers)

    return StreamingResponse(
        proxy_stream_generator(
            tenant_id=tid,
            agent_id=req.agent_id,
            session_id=req.session_id,
            target_url=req.target_url,
            method=req.method,
            forward_headers=forward_headers,
            body=req.body,
            scan_input=req.scan_input,
            scan_output=req.scan_output,
            scan_chunks=req.scan_chunks,
            buffer_for_gate=req.buffer_for_gate,
            strip_sensitive_headers=req.strip_sensitive_headers,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
            "X-AgentGuard":      "v3.5",
        },
    )

@app.get("/proxy/passthrough/stats")
async def passthrough_stats(tenant=Depends(get_tenant), days: int=30):
    """Passthrough proxy streaming stats."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS total_requests,"
            " COUNT(*) FILTER (WHERE was_streaming=TRUE) AS streaming_requests,"
            " COUNT(*) FILTER (WHERE injection_found=TRUE) AS injection_blocked,"
            " COUNT(*) FILTER (WHERE output_blocked=TRUE) AS output_blocked,"
            " SUM(chunks_forwarded) AS total_chunks,"
            " SUM(bytes_forwarded) AS total_bytes,"
            " ROUND(AVG(duration_ms)) AS avg_ms"
            " FROM proxy_stream_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
        recent = await conn.fetch(
            "SELECT agent_id, session_id, target_url, status_code,"
            " was_streaming, chunks_forwarded, bytes_forwarded,"
            " injection_found, output_blocked, duration_ms, created_at"
            " FROM proxy_stream_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL"
            " ORDER BY created_at DESC LIMIT 20",
            tenant["id"], str(days))
    return {**dict(row), "recent_sessions": [dict(r) for r in recent]}



# ══════════════════════════════════════════════════════════════════════════════
# DATA PRIVACY + NO-TRAINING ENFORCEMENT v3.6
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/privacy")
async def get_privacy_overview(tenant=Depends(get_tenant)):
    """
    Privacy overview for this tenant.
    Shows what protections are active, provider compliance facts,
    and a compliance score across all providers used.
    """
    config = await get_tenant_privacy_config(tenant["id"])

    providers_status = {}
    for provider, facts in PROVIDER_PRIVACY_FACTS.items():
        no_train_key = f"{provider}_no_train"
        zdr_key      = f"{provider}_zdr"
        no_train     = config.get("enforce_no_training", True) and config.get(no_train_key, True)
        zdr          = config.get("enforce_zdr", False) and config.get(zdr_key, False)

        from app.v3 import _compute_compliance_score
        score = _compute_compliance_score(provider, config, no_train, zdr)

        providers_status[provider] = {
            "no_training_enforced": no_train,
            "zdr_enforced":         zdr,
            "compliance_score":     score,
            "provider_trains_on_api": facts.get("trains_on_api", True),
            "soc2":                 facts.get("soc2", False),
            "gdpr":                 facts.get("gdpr", False),
            "hipaa":                facts.get("hipaa", False),
            "zdr_available":        facts.get("zdr_available", False),
            "zdr_note":             facts.get("zdr_note", ""),
            "policy_source":        facts.get("trains_on_api_source", ""),
        }

    avg_score = int(sum(p["compliance_score"] for p in providers_status.values())
                    / len(providers_status)) if providers_status else 0

    return {
        "tenant_id":           tenant["id"],
        "overall_score":       avg_score,
        "enforce_no_training": config.get("enforce_no_training", True),
        "enforce_zdr":         config.get("enforce_zdr", False),
        "require_soc2":        config.get("require_soc2", False),
        "require_gdpr":        config.get("require_gdpr", False),
        "require_hipaa":       config.get("require_hipaa", False),
        "block_non_compliant": config.get("block_non_compliant", False),
        "providers":           providers_status,
        "summary": (
            f"No-training enforcement is {'ACTIVE' if config.get('enforce_no_training') else 'INACTIVE'}. "
            f"ZDR is {'ACTIVE' if config.get('enforce_zdr') else 'INACTIVE'}. "
            f"Overall privacy score: {avg_score}/100."
        ),
    }

@app.get("/privacy/config")
async def get_privacy_config(tenant=Depends(get_tenant)):
    """Get the full privacy configuration for this tenant."""
    config = await get_tenant_privacy_config(tenant["id"])
    config.pop("_ts", None)
    return config

@app.put("/privacy/config")
async def update_privacy_config(body: DataPrivacyConfig, tenant=Depends(get_tenant)):
    """
    Update privacy configuration.

    Key settings:
      enforce_no_training: true   — inject opt-out headers on every LLM call (default: true)
      enforce_zdr: false          — require ZDR endpoints (needs provider agreement)
      block_non_compliant: false  — block calls to providers missing required certs
      require_soc2: false         — only allow SOC2-certified providers
      require_hipaa: false        — only allow HIPAA-BAA providers (OpenAI + Gemini via Vertex)

    Note: enforce_no_training=true is the default and recommended for all YC startups.
    Setting block_non_compliant=true + require_hipaa=true will restrict you to
    OpenAI (with BAA) and Gemini via Vertex AI only.
    """
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO tenant_privacy_config ("
            "  tenant_id, enforce_no_training, enforce_zdr,"
            "  anthropic_no_train, openai_no_train, openai_zdr,"
            "  gemini_no_train, gemini_use_vertex, groq_acknowledged,"
            "  require_soc2, require_gdpr, require_hipaa,"
            "  block_non_compliant, preferred_data_region"
            ") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)"
            " ON CONFLICT (tenant_id) DO UPDATE SET"
            "  enforce_no_training=$2, enforce_zdr=$3,"
            "  anthropic_no_train=$4, openai_no_train=$5, openai_zdr=$6,"
            "  gemini_no_train=$7, gemini_use_vertex=$8, groq_acknowledged=$9,"
            "  require_soc2=$10, require_gdpr=$11, require_hipaa=$12,"
            "  block_non_compliant=$13, preferred_data_region=$14,"
            "  updated_at=NOW()",
            tenant["id"],
            body.enforce_no_training, body.enforce_zdr,
            body.anthropic_no_train, body.openai_no_train, body.openai_zdr,
            body.gemini_no_train, body.gemini_use_vertex, body.groq_acknowledged,
            body.require_soc2, body.require_gdpr, body.require_hipaa,
            body.block_non_compliant, body.preferred_data_region,
        )

    invalidate_privacy_cache(tenant["id"])
    return {"updated": True, "message": "Privacy configuration updated. Takes effect immediately."}

@app.get("/privacy/providers")
async def list_provider_privacy_facts(tenant=Depends(get_tenant)):
    """
    Full privacy facts for every supported provider.
    Includes whether they train on API data, ZDR availability,
    compliance certifications, and policy source URLs.
    """
    return {
        provider: {
            **facts,
            "agentguard_enforces": True,
            "enforcement_method":  facts.get("opt_out_method", "none"),
        }
        for provider, facts in PROVIDER_PRIVACY_FACTS.items()
    }

@app.get("/privacy/audit")
async def list_privacy_audit(
    tenant=Depends(get_tenant),
    provider: Optional[str] = None,
    days: int = 30,
    limit: int = 100,
):
    """
    Privacy audit log — proof that no-training was enforced on every LLM call.
    Every entry shows which headers were injected, the compliance score, and
    whether the call was blocked for privacy reasons.
    """
    where = "WHERE tenant_id=$1 AND created_at > NOW() - ($2||' days')::INTERVAL"
    vals  = [tenant["id"], str(days)]
    if provider:
        where += " AND provider=$3"; vals.append(provider)
    vals.append(min(limit, 500))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT * FROM privacy_audit_log {where}"
            f" ORDER BY created_at DESC LIMIT ${len(vals)}", *vals)
    return [dict(r) for r in rows]

@app.get("/privacy/audit/stats")
async def privacy_audit_stats(tenant=Depends(get_tenant), days: int=30):
    """
    Privacy audit statistics.
    Shows enforcement rates, compliance scores, and blocked calls by provider.
    Use this as your data privacy compliance dashboard.
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS total_calls,"
            " COUNT(*) FILTER (WHERE no_train_enforced=TRUE) AS no_train_enforced,"
            " COUNT(*) FILTER (WHERE zdr_enforced=TRUE) AS zdr_enforced,"
            " COUNT(*) FILTER (WHERE blocked=TRUE) AS blocked_calls,"
            " ROUND(AVG(compliance_score)) AS avg_compliance_score,"
            " COUNT(DISTINCT provider) AS providers_used"
            " FROM privacy_audit_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL",
            tenant["id"], str(days))
        by_provider = await conn.fetch(
            "SELECT provider,"
            " COUNT(*) AS calls,"
            " COUNT(*) FILTER (WHERE no_train_enforced=TRUE) AS no_train_calls,"
            " COUNT(*) FILTER (WHERE zdr_enforced=TRUE) AS zdr_calls,"
            " ROUND(AVG(compliance_score)) AS avg_score"
            " FROM privacy_audit_log WHERE tenant_id=$1"
            " AND created_at > NOW() - ($2||' days')::INTERVAL"
            " GROUP BY provider ORDER BY calls DESC",
            tenant["id"], str(days))
    return {
        **dict(row),
        "enforcement_rate": (
            round(row["no_train_enforced"] / row["total_calls"] * 100, 1)
            if row["total_calls"] else 0
        ),
        "by_provider": [dict(r) for r in by_provider],
    }

@app.post("/privacy/test")
async def test_privacy_enforcement(body: dict, tenant=Depends(get_tenant)):
    """
    Test privacy enforcement for a specific provider without making a real LLM call.
    Returns exactly which headers would be injected and what compliance score
    would be recorded.

    Body: { "provider": "openai" }
    """
    provider = body.get("provider", "anthropic")
    if provider not in PROVIDER_PRIVACY_FACTS:
        raise HTTPException(400, f"Unknown provider. Valid: {list(PROVIDER_PRIVACY_FACTS.keys())}")

    headers, no_train, zdr, block_reason = await enforce_privacy_headers(
        provider, tenant["id"], session_id=None, agent_id=None)

    config = await get_tenant_privacy_config(tenant["id"])
    from app.v3 import _compute_compliance_score
    score  = _compute_compliance_score(provider, config, no_train, zdr)
    facts  = PROVIDER_PRIVACY_FACTS[provider]

    return {
        "provider":            provider,
        "would_be_blocked":    bool(block_reason),
        "block_reason":        block_reason,
        "headers_injected":    headers,
        "no_train_enforced":   no_train,
        "zdr_enforced":        zdr,
        "compliance_score":    score,
        "provider_facts": {
            "trains_on_api":   facts.get("trains_on_api"),
            "zdr_available":   facts.get("zdr_available"),
            "soc2":            facts.get("soc2"),
            "gdpr":            facts.get("gdpr"),
            "hipaa":           facts.get("hipaa"),
            "policy_source":   facts.get("trains_on_api_source"),
            "note":            facts.get("zdr_note"),
        },
    }


@app.get("/health")
async def health():
    checks = {"postgres": False, "redis": None}
    try:
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        checks["postgres"] = True
    except Exception: pass
    if redis_conn:
        checks["redis"] = await _redis_ok()
    all_ok = checks["postgres"] and checks.get("redis") is not False
    return JSONResponse(status_code=200 if all_ok else 503,
        content={"status":"ok" if all_ok else "degraded",
                 "checks": checks, "env": AGENTGUARD_ENV, "version": "3.6.0"})
