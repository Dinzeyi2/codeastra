"""
AgentGuard SDK v1.4.0

Requires: httpx, cryptography
  pip install httpx cryptography

Quickstart:
    # 1. Generate a keypair once and store the private key securely
    private_key_b64, public_key_b64 = AgentGuard.generate_keypair()

    # 2. Register the agent (public key only goes to server)
    # POST /agents  →  get agent_id
    # POST /agents/{agent_id}/register-key  { "public_key": public_key_b64 }

    # 3. Use the guard
    guard = AgentGuard(
        base_url="https://your-app.railway.app",
        agent_id="agent_abc123",
        private_key_b64=private_key_b64,   # never leaves your environment
    )

    result = await guard.protect(tool="read_users", args={"limit": 10}, user_id="u_123")
    if result.allowed:
        data = await your_tool(**result.args)
"""

import hashlib
import json
import os
import time
import uuid
from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import Any, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass
class GuardResult:
    allowed:     bool
    action:      str
    reason:      str
    args:        dict
    redacted:    bool
    policy:      str
    duration_ms: int
    result:      Any = None  # populated by /invoke


class AgentGuardError(Exception):
    pass


class AgentGuard:
    def __init__(
        self,
        base_url:        Optional[str] = None,
        agent_id:        Optional[str] = None,
        private_key_b64: Optional[str] = None,
        timeout:         float = 15.0,
    ):
        self.base_url        = (base_url or os.environ.get("AGENTGUARD_URL", "")).rstrip("/")
        self.agent_id        = agent_id or os.environ.get("AGENTGUARD_AGENT_ID", "")
        private_key_b64      = private_key_b64 or os.environ.get("AGENTGUARD_PRIVATE_KEY", "")
        self.timeout         = timeout

        if not self.base_url:
            raise AgentGuardError("base_url required (or set AGENTGUARD_URL)")
        if not self.agent_id:
            raise AgentGuardError("agent_id required (or set AGENTGUARD_AGENT_ID)")
        if not private_key_b64:
            raise AgentGuardError("private_key_b64 required (or set AGENTGUARD_PRIVATE_KEY)")

        self._private_key = Ed25519PrivateKey.from_private_bytes(b64decode(private_key_b64))

    @staticmethod
    def generate_keypair() -> tuple[str, str]:
        """
        Generate a new Ed25519 keypair.

        Returns (private_key_b64, public_key_b64).

        - Store private_key_b64 securely (env var, secrets manager).
        - Send public_key_b64 to POST /agents/{id}/register-key.
        - The private key never leaves your environment.

        Example:
            priv, pub = AgentGuard.generate_keypair()
            print("Private (store this):", priv)
            print("Public  (send to server):", pub)
        """
        private_key = Ed25519PrivateKey.generate()
        priv_bytes  = private_key.private_bytes_raw()
        pub_bytes   = private_key.public_key().public_bytes_raw()
        return b64encode(priv_bytes).decode(), b64encode(pub_bytes).decode()

    def _sign(self, body: bytes) -> str:
        return b64encode(self._private_key.sign(body)).decode()

    def _build_payload(self, tool, args, user_id, context, extra=None):
        payload = {
            "tool":      tool,
            "args":      args,
            "agent_id":  self.agent_id,
            "user_id":   user_id,
            "context":   context,
            "timestamp": int(time.time()),
            "nonce":     str(uuid.uuid4()),
        }
        if extra:
            payload.update(extra)
        return payload

    async def _post(self, endpoint: str, payload: dict) -> dict:
        body = json.dumps(payload).encode()
        sig  = self._sign(body)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                r = await client.post(
                    f"{self.base_url}{endpoint}",
                    content=body,
                    headers={
                        "Content-Type":      "application/json",
                        "x-agent-signature": sig,
                    },
                )
            except httpx.RequestError as e:
                raise AgentGuardError(f"AgentGuard unreachable: {e}") from e
        data = r.json()
        if r.status_code not in (200, 403):
            raise AgentGuardError(f"AgentGuard error {r.status_code}: {data}")
        return data

    async def protect(self, tool: str, args: dict, user_id: str,
                      context: Optional[str] = None) -> GuardResult:
        """Check policy. Call the tool yourself if result.allowed."""
        data = await self._post("/protect", self._build_payload(tool, args, user_id, context))
        return GuardResult(
            allowed=     data.get("allowed",     False),
            action=      data.get("action",      ""),
            reason=      data.get("reason",      ""),
            args=        data.get("args",        args),
            redacted=    data.get("redacted",    False),
            policy=      data.get("policy",      ""),
            duration_ms= data.get("duration_ms", 0),
        )

    async def invoke(self, tool: str, args: dict, user_id: str, target_url: str,
                     context: Optional[str] = None) -> GuardResult:
        """
        Proxy mode: AgentGuard enforces policy AND calls target_url on your behalf.
        target_url must be in the agent's or server's allowed_hosts list.
        """
        payload = self._build_payload(tool, args, user_id, context, {"target_url": target_url})
        data    = await self._post("/invoke", payload)
        return GuardResult(
            allowed=     data.get("allowed",     False),
            action=      data.get("action",      ""),
            reason=      data.get("reason",      ""),
            args=        data.get("args",        args),
            redacted=    data.get("redacted",    False),
            policy=      data.get("policy",      ""),
            duration_ms= data.get("duration_ms", 0),
            result=      data.get("result"),
        )


# ── Sync wrapper ──────────────────────────────────────────────────────────────
import asyncio

class AgentGuardSync:
    def __init__(self, **kwargs):
        self._g = AgentGuard(**kwargs)

    def protect(self, tool, args, user_id, context=None) -> GuardResult:
        return asyncio.run(self._g.protect(tool, args, user_id, context))

    def invoke(self, tool, args, user_id, target_url, context=None) -> GuardResult:
        return asyncio.run(self._g.invoke(tool, args, user_id, target_url, context))
