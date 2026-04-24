"""
CODEASTRA WORKSPACE SYSTEM
==========================
Add this entire block to v3.py (or import it).
Then add the endpoints to main.py.

New tables:
  workspaces         — company/hospital accounts
  workspace_members  — staff linked to a workspace
  workspace_api_keys — per-user API keys with roles

New endpoints:
  POST   /workspace/create          — admin creates workspace
  GET    /workspace/me              — get my workspace
  POST   /workspace/invite          — invite a team member
  GET    /workspace/members         — list all members
  POST   /workspace/keys/generate   — generate API key for member
  DELETE /workspace/keys/{key_id}   — revoke a key
  GET    /workspace/keys            — list all keys
  GET    /workspace/usage           — usage stats per member
  POST   /workspace/keys/verify     — verify a key is valid (used by Chrome extension)
"""

import uuid
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
# DATABASE MIGRATIONS
# ══════════════════════════════════════════════════════════════════════════════

WORKSPACE_MIGRATIONS = [

    # Workspaces table
    """CREATE TABLE IF NOT EXISTS workspaces (
        id              TEXT PRIMARY KEY,
        name            TEXT NOT NULL,
        owner_tenant_id TEXT NOT NULL,
        plan            TEXT NOT NULL DEFAULT 'starter',
        industry        TEXT,
        max_members     INTEGER DEFAULT 10,
        max_keys        INTEGER DEFAULT 20,
        credits_total   INTEGER DEFAULT 10000,
        credits_used    INTEGER DEFAULT 0,
        created_at      TIMESTAMPTZ DEFAULT NOW(),
        updated_at      TIMESTAMPTZ DEFAULT NOW()
    )""",

    # Workspace members
    """CREATE TABLE IF NOT EXISTS workspace_members (
        id              TEXT PRIMARY KEY,
        workspace_id    TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        tenant_id       TEXT NOT NULL,
        email           TEXT NOT NULL,
        full_name       TEXT,
        role            TEXT NOT NULL DEFAULT 'member',
        status          TEXT NOT NULL DEFAULT 'pending',
        invited_at      TIMESTAMPTZ DEFAULT NOW(),
        joined_at       TIMESTAMPTZ,
        UNIQUE(workspace_id, email)
    )""",

    # Per-user API keys
    """CREATE TABLE IF NOT EXISTS workspace_api_keys (
        id              TEXT PRIMARY KEY,
        workspace_id    TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        member_id       TEXT NOT NULL REFERENCES workspace_members(id) ON DELETE CASCADE,
        key_hash        TEXT NOT NULL UNIQUE,
        key_prefix      TEXT NOT NULL,
        label           TEXT,
        role            TEXT NOT NULL DEFAULT 'member',
        allowed_actions TEXT[] DEFAULT ARRAY['tokenize','resolve','rag_search'],
        is_active       BOOLEAN DEFAULT TRUE,
        created_at      TIMESTAMPTZ DEFAULT NOW(),
        last_used_at    TIMESTAMPTZ,
        use_count       INTEGER DEFAULT 0,
        revoked_at      TIMESTAMPTZ,
        revoked_reason  TEXT
    )""",

    # Key usage log
    """CREATE TABLE IF NOT EXISTS workspace_key_usage (
        id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        key_id          TEXT NOT NULL,
        workspace_id    TEXT NOT NULL,
        member_id       TEXT NOT NULL,
        action          TEXT NOT NULL,
        endpoint        TEXT,
        created_at      TIMESTAMPTZ DEFAULT NOW()
    )""",

    # Indexes
    """CREATE INDEX IF NOT EXISTS ws_members_workspace_idx
       ON workspace_members(workspace_id)""",

    """CREATE INDEX IF NOT EXISTS ws_keys_workspace_idx
       ON workspace_api_keys(workspace_id)""",

    """CREATE INDEX IF NOT EXISTS ws_keys_hash_idx
       ON workspace_api_keys(key_hash)""",

    """CREATE INDEX IF NOT EXISTS ws_usage_key_idx
       ON workspace_key_usage(key_id, created_at DESC)""",
]


# ══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def _hash_key(raw_key: str) -> str:
    """One-way hash of API key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _generate_workspace_key(workspace_id: str, role: str) -> tuple[str, str]:
    """
    Generate a new workspace API key.
    Returns (raw_key, key_prefix).
    raw_key is shown ONCE to the user — never stored.
    key_prefix is stored for display (e.g. 'sk-ws-4ca4...').
    """
    role_prefix = "adm" if role == "admin" else "mbr"
    raw = f"sk-ws-{role_prefix}-{secrets.token_hex(28)}"
    prefix = raw[:16] + "..."
    return raw, prefix


async def run_workspace_migrations(pool):
    """Run all workspace table migrations."""
    async with pool.acquire() as conn:
        for sql in WORKSPACE_MIGRATIONS:
            try:
                await conn.execute(sql)
            except Exception as e:
                print(f"Workspace migration warning: {e}")


async def verify_workspace_key(pool, raw_key: str) -> Optional[dict]:
    """
    Verify a workspace API key.
    Returns member info if valid, None if invalid/revoked.
    Used by Chrome extension to authenticate.
    """
    key_hash = _hash_key(raw_key)
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT
                wk.id           AS key_id,
                wk.workspace_id,
                wk.member_id,
                wk.role,
                wk.allowed_actions,
                wk.is_active,
                wm.email,
                wm.full_name,
                wm.status,
                w.name          AS workspace_name,
                w.industry,
                w.owner_tenant_id AS tenant_id
            FROM workspace_api_keys wk
            JOIN workspace_members wm ON wm.id = wk.member_id
            JOIN workspaces w ON w.id = wk.workspace_id
            WHERE wk.key_hash = $1
              AND wk.is_active = TRUE
              AND wm.status = 'active'
        """, key_hash)

        if not row:
            return None

        # Update last used
        await conn.execute("""
            UPDATE workspace_api_keys
            SET last_used_at = NOW(), use_count = use_count + 1
            WHERE id = $1
        """, row["key_id"])

        return dict(row)


# ══════════════════════════════════════════════════════════════════════════════
# ENDPOINT HANDLERS
# (These are the async functions — wire them into main.py)
# ══════════════════════════════════════════════════════════════════════════════

async def create_workspace(pool, tenant_id: str, name: str,
                           industry: str = None, plan: str = "starter") -> dict:
    """
    Create a new workspace.
    Called by the hospital admin after signing up.
    """
    ws_id = f"ws_{uuid.uuid4().hex[:16]}"
    member_id = f"mem_{uuid.uuid4().hex[:16]}"

    async with pool.acquire() as conn:
        # Check if tenant already has a workspace
        existing = await conn.fetchrow(
            "SELECT id FROM workspaces WHERE owner_tenant_id = $1", tenant_id
        )
        if existing:
            return {"error": "workspace_exists",
                    "detail": "You already have a workspace.",
                    "workspace_id": existing["id"]}

        # Get tenant email/name
        tenant = await conn.fetchrow(
            "SELECT email, name FROM tenants WHERE id = $1", tenant_id
        )
        if not tenant:
            return {"error": "tenant_not_found"}

        # Create workspace
        await conn.execute("""
            INSERT INTO workspaces
              (id, name, owner_tenant_id, industry, plan)
            VALUES ($1, $2, $3, $4, $5)
        """, ws_id, name, tenant_id, industry, plan)

        # Add owner as first admin member
        await conn.execute("""
            INSERT INTO workspace_members
              (id, workspace_id, tenant_id, email, full_name, role, status, joined_at)
            VALUES ($1, $2, $3, $4, $5, 'admin', 'active', NOW())
        """, member_id, ws_id, tenant_id, tenant["email"], tenant["name"])

        # Generate first API key for the owner
        raw_key, prefix = _generate_workspace_key(ws_id, "admin")
        key_id = f"key_{uuid.uuid4().hex[:16]}"
        await conn.execute("""
            INSERT INTO workspace_api_keys
              (id, workspace_id, member_id, key_hash, key_prefix, label, role)
            VALUES ($1, $2, $3, $4, $5, 'Admin Key', 'admin')
        """, key_id, ws_id, member_id, _hash_key(raw_key), prefix)

    return {
        "workspace_id":   ws_id,
        "workspace_name": name,
        "industry":       industry,
        "plan":           plan,
        "admin_key":      raw_key,   # shown ONCE — user must save it
        "key_prefix":     prefix,
        "message":        "Workspace created. Save your API key — it will not be shown again.",
    }


async def get_workspace(pool, tenant_id: str) -> dict:
    """Get workspace details for the logged-in tenant."""
    async with pool.acquire() as conn:
        ws = await conn.fetchrow("""
            SELECT w.*,
                   COUNT(DISTINCT wm.id) AS member_count,
                   COUNT(DISTINCT wk.id) AS key_count
            FROM workspaces w
            LEFT JOIN workspace_members wm ON wm.workspace_id = w.id
            LEFT JOIN workspace_api_keys wk ON wk.workspace_id = w.id AND wk.is_active = TRUE
            WHERE w.owner_tenant_id = $1
            GROUP BY w.id
        """, tenant_id)

        if not ws:
            return {"error": "no_workspace",
                    "detail": "No workspace found. Create one first."}

        members = await conn.fetch("""
            SELECT wm.id, wm.email, wm.full_name, wm.role, wm.status,
                   wm.invited_at, wm.joined_at,
                   COUNT(wk.id) AS active_keys
            FROM workspace_members wm
            LEFT JOIN workspace_api_keys wk
              ON wk.member_id = wm.id AND wk.is_active = TRUE
            WHERE wm.workspace_id = $1
            GROUP BY wm.id
            ORDER BY wm.joined_at DESC NULLS LAST
        """, ws["id"])

        return {
            "workspace":    dict(ws),
            "members":      [dict(m) for m in members],
        }


async def invite_member(pool, tenant_id: str, email: str,
                        full_name: str, role: str = "member") -> dict:
    """
    Invite a team member to the workspace.
    Generates their API key immediately.
    """
    async with pool.acquire() as conn:
        ws = await conn.fetchrow(
            "SELECT * FROM workspaces WHERE owner_tenant_id = $1", tenant_id
        )
        if not ws:
            return {"error": "no_workspace"}

        # Check member limit
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM workspace_members WHERE workspace_id = $1", ws["id"]
        )
        if count >= ws["max_members"]:
            return {"error": "member_limit",
                    "detail": f"Workspace limit is {ws['max_members']} members."}

        # Check if already invited
        existing = await conn.fetchrow("""
            SELECT id, status FROM workspace_members
            WHERE workspace_id = $1 AND email = $2
        """, ws["id"], email)

        if existing:
            return {"error": "already_invited",
                    "detail": f"{email} is already in this workspace.",
                    "status": existing["status"]}

        # Find or create tenant for this email
        member_tenant = await conn.fetchrow(
            "SELECT id FROM tenants WHERE email = $1", email
        )
        member_tenant_id = member_tenant["id"] if member_tenant else f"pending_{uuid.uuid4().hex[:8]}"

        # Create member record
        member_id = f"mem_{uuid.uuid4().hex[:16]}"
        await conn.execute("""
            INSERT INTO workspace_members
              (id, workspace_id, tenant_id, email, full_name, role, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'active')
        """, member_id, ws["id"], member_tenant_id, email, full_name, role)

        # Generate API key for member immediately
        raw_key, prefix = _generate_workspace_key(ws["id"], role)
        key_id = f"key_{uuid.uuid4().hex[:16]}"
        await conn.execute("""
            INSERT INTO workspace_api_keys
              (id, workspace_id, member_id, key_hash, key_prefix, label, role)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        """, key_id, ws["id"], member_id,
             _hash_key(raw_key), prefix,
             f"Key for {full_name or email}", role)

    return {
        "member_id":    member_id,
        "email":        email,
        "full_name":    full_name,
        "role":         role,
        "api_key":      raw_key,    # shown ONCE — send to member via email
        "key_prefix":   prefix,
        "workspace":    ws["name"],
        "message":      f"Member added. Send this API key to {email} — it will not be shown again.",
    }


async def list_members(pool, tenant_id: str) -> dict:
    """List all workspace members with their key status."""
    async with pool.acquire() as conn:
        ws = await conn.fetchrow(
            "SELECT id, name FROM workspaces WHERE owner_tenant_id = $1", tenant_id
        )
        if not ws:
            return {"error": "no_workspace"}

        members = await conn.fetch("""
            SELECT
                wm.id, wm.email, wm.full_name, wm.role, wm.status,
                wm.invited_at, wm.joined_at,
                wk.id         AS key_id,
                wk.key_prefix AS key_preview,
                wk.is_active  AS key_active,
                wk.last_used_at,
                wk.use_count
            FROM workspace_members wm
            LEFT JOIN workspace_api_keys wk
              ON wk.member_id = wm.id AND wk.is_active = TRUE
            WHERE wm.workspace_id = $1
            ORDER BY wm.role DESC, wm.joined_at ASC NULLS LAST
        """, ws["id"])

    return {
        "workspace_id":   ws["id"],
        "workspace_name": ws["name"],
        "members":        [dict(m) for m in members],
        "total":          len(members),
    }


async def generate_key_for_member(pool, tenant_id: str,
                                   member_email: str, label: str = None) -> dict:
    """Generate a new API key for an existing member."""
    async with pool.acquire() as conn:
        ws = await conn.fetchrow(
            "SELECT * FROM workspaces WHERE owner_tenant_id = $1", tenant_id
        )
        if not ws:
            return {"error": "no_workspace"}

        member = await conn.fetchrow("""
            SELECT * FROM workspace_members
            WHERE workspace_id = $1 AND email = $2
        """, ws["id"], member_email)

        if not member:
            return {"error": "member_not_found",
                    "detail": f"{member_email} is not in this workspace."}

        # Revoke existing active keys for this member
        await conn.execute("""
            UPDATE workspace_api_keys
            SET is_active = FALSE, revoked_at = NOW(),
                revoked_reason = 'replaced'
            WHERE member_id = $1 AND is_active = TRUE
        """, member["id"])

        # Generate new key
        raw_key, prefix = _generate_workspace_key(ws["id"], member["role"])
        key_id = f"key_{uuid.uuid4().hex[:16]}"
        await conn.execute("""
            INSERT INTO workspace_api_keys
              (id, workspace_id, member_id, key_hash, key_prefix, label, role)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        """, key_id, ws["id"], member["id"],
             _hash_key(raw_key), prefix,
             label or f"Key for {member_email}", member["role"])

    return {
        "key_id":     key_id,
        "api_key":    raw_key,    # shown ONCE
        "key_prefix": prefix,
        "member":     member_email,
        "message":    "New key generated. Old key revoked. Send this key to the member.",
    }


async def revoke_key(pool, tenant_id: str, key_id: str, reason: str = "manual") -> dict:
    """Revoke a workspace API key."""
    async with pool.acquire() as conn:
        ws = await conn.fetchrow(
            "SELECT id FROM workspaces WHERE owner_tenant_id = $1", tenant_id
        )
        if not ws:
            return {"error": "no_workspace"}

        result = await conn.execute("""
            UPDATE workspace_api_keys
            SET is_active = FALSE, revoked_at = NOW(), revoked_reason = $1
            WHERE id = $2 AND workspace_id = $3
        """, reason, key_id, ws["id"])

    if result == "UPDATE 0":
        return {"error": "key_not_found"}

    return {"revoked": True, "key_id": key_id, "reason": reason}


async def get_usage_stats(pool, tenant_id: str) -> dict:
    """Get usage stats per member for the workspace."""
    async with pool.acquire() as conn:
        ws = await conn.fetchrow(
            "SELECT * FROM workspaces WHERE owner_tenant_id = $1", tenant_id
        )
        if not ws:
            return {"error": "no_workspace"}

        stats = await conn.fetch("""
            SELECT
                wm.email,
                wm.full_name,
                wm.role,
                COALESCE(SUM(wk.use_count), 0) AS total_calls,
                MAX(wk.last_used_at)            AS last_active,
                COUNT(wk.id) FILTER (WHERE wk.is_active) AS active_keys
            FROM workspace_members wm
            LEFT JOIN workspace_api_keys wk ON wk.member_id = wm.id
            WHERE wm.workspace_id = $1
            GROUP BY wm.id, wm.email, wm.full_name, wm.role
            ORDER BY total_calls DESC
        """, ws["id"])

        vault_stats = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS tokens_this_month,
                COUNT(*) AS tokens_total
            FROM agent_vault
            WHERE tenant_id = $1
        """, ws["owner_tenant_id"])

    return {
        "workspace":    ws["name"],
        "plan":         ws["plan"],
        "credits_used": ws["credits_used"],
        "credits_total": ws["credits_total"],
        "members":      [dict(s) for s in stats],
        "vault": {
            "tokens_this_month": vault_stats["tokens_this_month"] if vault_stats else 0,
            "tokens_total":      vault_stats["tokens_total"] if vault_stats else 0,
        }
    }


# ══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE — verify workspace key for Chrome extension
# ══════════════════════════════════════════════════════════════════════════════

async def get_tenant_from_workspace_key(pool, raw_key: str) -> Optional[dict]:
    """
    Given a workspace API key (sk-ws-xxx),
    returns a tenant-compatible dict for use with existing endpoints.
    This lets workspace keys work with all existing vault/RAG/smart-token endpoints.
    """
    if not raw_key or not raw_key.startswith("sk-ws-"):
        return None

    member_info = await verify_workspace_key(pool, raw_key)
    if not member_info:
        return None

    # Return tenant-compatible dict
    return {
        "id":         member_info["tenant_id"],
        "plan":       "workspace",
        "email":      member_info["email"],
        "name":       member_info["full_name"] or member_info["email"],
        "workspace":  member_info["workspace_name"],
        "role":       member_info["role"],
        "member_id":  member_info["member_id"],
    }
