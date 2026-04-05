"""
AgentGuard SDK v2.0.0

New in v2:
  - Sessions: declare intent upfront, get drift detection + per-tool limits
  - HITL: real async approval with polling + wait_for_hitl()
  - Injection scanning: scan_result() before passing tool output to agent
  - protect() auto-uses /protect/v3 when session_id is active
"""

import asyncio
import json
import os
import time
import uuid
from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import Any, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass
class GuardResult:
    allowed:     bool
    action:      str
    reason:      str
    args:        dict
    redacted:    bool
    policy:      str
    duration_ms: int
    request_id:  str = ""
    session_id:  str = ""
    hitl_id:     str = ""
    result:      Any = None


@dataclass
class HITLStatus:
    hitl_id:    str
    status:     str
    decision:   str
    decided_by: str
    tool:       str
    expires_at: str

    @property
    def approved(self): return self.status == "approved"
    @property
    def rejected(self): return self.status == "rejected"
    @property
    def pending(self):  return self.status == "pending"


class AgentGuardError(Exception): pass
class InjectionDetectedError(AgentGuardError): pass


class AgentGuard:
    def __init__(self, base_url=None, agent_id=None, private_key_b64=None,
                 api_key=None, timeout=15.0):
        self.base_url = (base_url or os.environ.get("AGENTGUARD_URL", "")).rstrip("/")
        self.agent_id = agent_id or os.environ.get("AGENTGUARD_AGENT_ID", "")
        self.api_key  = api_key  or os.environ.get("AGENTGUARD_API_KEY",  "")
        private_key_b64 = private_key_b64 or os.environ.get("AGENTGUARD_PRIVATE_KEY", "")
        self.timeout  = timeout
        self._session_id: Optional[str] = None
        if not all([self.base_url, self.agent_id, private_key_b64]):
            raise AgentGuardError("base_url, agent_id, and private_key_b64 are required")
        self._private_key = Ed25519PrivateKey.from_private_bytes(b64decode(private_key_b64))

    @staticmethod
    def generate_keypair() -> tuple[str, str]:
        pk = Ed25519PrivateKey.generate()
        return (b64encode(pk.private_bytes_raw()).decode(),
                b64encode(pk.public_key().public_bytes_raw()).decode())

    def _sign(self, body: bytes) -> str:
        return b64encode(self._private_key.sign(body)).decode()

    def _headers(self, signed=False, body=None) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["x-api-key"] = self.api_key
        if signed and body:
            h["x-agent-signature"] = self._sign(body)
        return h

    async def _post_signed(self, endpoint, payload, ok=(200, 202, 400, 403)):
        body = json.dumps(payload).encode()
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(f"{self.base_url}{endpoint}", content=body,
                              headers=self._headers(signed=True, body=body))
        if r.status_code not in ok:
            raise AgentGuardError(f"{r.status_code}: {r.text[:200]}")
        return r.json()

    async def _post(self, endpoint, payload, ok=(200, 202)):
        body = json.dumps(payload).encode()
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(f"{self.base_url}{endpoint}", content=body,
                              headers=self._headers())
        if r.status_code not in ok:
            raise AgentGuardError(f"{r.status_code}: {r.text[:200]}")
        return r.json()

    async def _get(self, endpoint):
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(f"{self.base_url}{endpoint}", headers=self._headers())
        if r.status_code not in (200, 404):
            raise AgentGuardError(f"{r.status_code}: {r.text[:200]}")
        return r.json()

    # ── Sessions ───────────────────────────────────────────────────────────────

    async def start_session(self, user_id: str, intent: str, metadata: dict = {}) -> str:
        """
        Start a session. Declare what the agent is trying to do.
        All protect() calls in this session are checked against this intent.

            session_id = await guard.start_session(
                user_id="u_123",
                intent="Summarize Q3 report and email it to the team"
            )
        """
        data = await self._post("/sessions", {
            "agent_id": self.agent_id, "user_id": user_id,
            "intent": intent, "metadata": metadata,
        })
        self._session_id = data["session_id"]
        return self._session_id

    async def end_session(self, session_id: Optional[str] = None, reason: str = None):
        sid = session_id or self._session_id
        if sid:
            await self._post(f"/sessions/{sid}/end", {"session_id": sid, "reason": reason})
            if sid == self._session_id:
                self._session_id = None

    async def get_session(self, session_id: Optional[str] = None) -> dict:
        return await self._get(f"/sessions/{session_id or self._session_id}")

    # ── Protect ────────────────────────────────────────────────────────────────

    async def protect(self, tool: str, args: dict, user_id: str,
                       context: Optional[str] = None,
                       session_id: Optional[str] = None) -> GuardResult:
        """
        Check policy. Uses /protect/v3 when session active (adds drift + rate limits).
        If result.action == 'pending_approval': poll get_hitl_status(result.hitl_id).
        """
        sid      = session_id or self._session_id
        endpoint = "/protect/v3" if sid else "/protect"
        payload  = {
            "tool": tool, "args": args, "agent_id": self.agent_id,
            "user_id": user_id, "context": context,
            "session_id": sid,
            "timestamp": int(time.time()), "nonce": str(uuid.uuid4()),
        }
        data = await self._post_signed(endpoint, payload)
        return GuardResult(
            allowed=data.get("allowed", False), action=data.get("action", ""),
            reason=data.get("reason", ""), args=data.get("args", args),
            redacted=data.get("redacted", False), policy=data.get("policy", ""),
            duration_ms=data.get("duration_ms", 0),
            request_id=data.get("request_id", ""),
            session_id=data.get("session_id", sid or ""),
            hitl_id=data.get("hitl_id", ""),
        )

    # ── HITL ──────────────────────────────────────────────────────────────────

    async def get_hitl_status(self, hitl_id: str) -> HITLStatus:
        """Poll this when protect() returns action='pending_approval'."""
        data = await self._get(f"/hitl/{hitl_id}")
        return HITLStatus(
            hitl_id=data.get("hitl_id", hitl_id),
            status=data.get("status", "unknown"),
            decision=data.get("decision", ""),
            decided_by=data.get("decided_by", ""),
            tool=data.get("tool", ""),
            expires_at=data.get("expires_at", ""),
        )

    async def wait_for_hitl(self, hitl_id: str,
                             poll_interval: float = 3.0,
                             timeout: float = 300.0) -> HITLStatus:
        """
        Block until HITL is decided or expires.

            result = await guard.protect(tool="deploy_to_prod", ...)
            if result.action == "pending_approval":
                hitl = await guard.wait_for_hitl(result.hitl_id)
                if hitl.approved:
                    await deploy()
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            s = await self.get_hitl_status(hitl_id)
            if not s.pending:
                return s
            await asyncio.sleep(poll_interval)
        raise AgentGuardError(f"HITL {hitl_id} timed out after {timeout}s")

    # ── Injection scanning ────────────────────────────────────────────────────

    async def scan_result(self, tool: str, result: Any,
                           session_id: Optional[str] = None) -> bool:
        """
        Scan a tool result for prompt injection. Call this BEFORE passing
        tool output back to the agent/LLM.

            raw = await your_tool(...)
            await guard.scan_result("your_tool", raw)  # raises if injection found
            messages.append({"role": "tool", "content": str(raw)})
        """
        sid  = session_id or self._session_id
        data = await self._post("/scan/injection", {
            "agent_id": self.agent_id, "session_id": sid,
            "tool": tool, "result": result,
        }, ok=(200, 400))
        if not data.get("safe", True):
            raise InjectionDetectedError(
                f"Injection in '{tool}' result: {data.get('reason', '')}"
            )
        return True

    # ── Context manager ────────────────────────────────────────────────────────

    async def __aenter__(self): return self
    async def __aexit__(self, *_): await self.end_session()


# ── Sync wrapper ───────────────────────────────────────────────────────────────

class AgentGuardSync:
    def __init__(self, **kw): self._g = AgentGuard(**kw)
    def start_session(self, user_id, intent, metadata={}):
        return asyncio.run(self._g.start_session(user_id, intent, metadata))
    def protect(self, tool, args, user_id, context=None, session_id=None):
        return asyncio.run(self._g.protect(tool, args, user_id, context, session_id))
    def get_hitl_status(self, hitl_id):
        return asyncio.run(self._g.get_hitl_status(hitl_id))
    def wait_for_hitl(self, hitl_id, poll_interval=3.0, timeout=300.0):
        return asyncio.run(self._g.wait_for_hitl(hitl_id, poll_interval, timeout))
    def scan_result(self, tool, result, session_id=None):
        return asyncio.run(self._g.scan_result(tool, result, session_id))
    def end_session(self, session_id=None, reason=None):
        return asyncio.run(self._g.end_session(session_id, reason))
