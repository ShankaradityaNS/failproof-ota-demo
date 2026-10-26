"""Event adapter: hands simulated sandbox operations to Failproof AI.

Failproof AI observes agent-harness hook events (Claude Code, Codex, ...). It
cannot see a Python method call inside our simulated sandbox, so this adapter
re-expresses each operation as a Claude Code `PreToolUse` hook payload for a
raw tool named `ota_sandbox_access` and pipes it to the installed CLI:

    failproofai --hook PreToolUse --cli claude      (JSON payload on stdin)

That is the same entry point ~/.claude/settings.json already uses. Failproof
then runs its policies, including the project policy
.failproofai/policies/device-hop-policies.mjs, and records the decision in
its hook activity log (forwarded to Failproof Cloud when the daemon is in
cloud mode). A deny comes back on stdout as
{"hookSpecificOutput": {"permissionDecision": "deny", ...}}.

Env:
  FAILPROOF_REPORT=0   skip reporting entirely
  FAILPROOFAI_BIN      path to the failproofai binary (default: from PATH)
"""
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

TOOL_NAME = "ota_sandbox_access"
PROJECT_DIR = Path(__file__).resolve().parent


class FailproofEventAdapter:
    def __init__(self, binary=None, enabled=None, session_id=None, timeout=30):
        self.binary = binary or os.environ.get("FAILPROOFAI_BIN") or shutil.which("failproofai")
        self.enabled = enabled if enabled is not None else os.environ.get("FAILPROOF_REPORT", "1") != "0"
        # One synthetic session per demo run so its events group together in Failproof.
        self.session_id = session_id or str(uuid.uuid4())
        self.timeout = timeout

    def build_payload(self, event):
        tool_input = event.to_dict()
        tool_input.pop("failproof", None)
        return {
            "session_id": self.session_id,
            "cwd": str(PROJECT_DIR),
            "hook_event_name": "PreToolUse",
            "tool_name": TOOL_NAME,
            "tool_input": tool_input,
            "permission_mode": "default",
        }

    @staticmethod
    def parse_decision(stdout):
        """Return ("deny", reason) or ("allow", None) from the hook's stdout."""
        try:
            out = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            return "allow", None
        hso = out.get("hookSpecificOutput") or {}
        if hso.get("permissionDecision") == "deny":
            return "deny", hso.get("permissionDecisionReason")
        return "allow", None

    def report(self, event):
        """Send the event to Failproof; attach the outcome to event.failproof."""
        if not self.enabled:
            event.failproof = {"status": "DISABLED", "detail": "FAILPROOF_REPORT=0, event not sent"}
            return event
        if not self.binary:
            event.failproof = {"status": "UNAVAILABLE", "detail": "failproofai binary not found on PATH"}
            return event

        payload = self.build_payload(event)
        try:
            proc = subprocess.run(
                [self.binary, "--hook", "PreToolUse", "--cli", "claude"],
                input=json.dumps(payload), capture_output=True, text=True, timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            event.failproof = {"status": "UNAVAILABLE", "detail": f"hook call failed: {e}"}
            return event

        fp_decision, fp_reason = self.parse_decision(proc.stdout)
        local = "deny" if event.authorization_decision == "DENY" else "allow"
        status = "AGREES" if fp_decision == local else "MISMATCH"
        detail = (f"Failproof hook decided '{fp_decision}'"
                  + (f": {fp_reason}" if fp_reason else "")
                  + ("" if status == "AGREES" else
                     " (MISMATCH with local detector; is device-hop-policies.mjs installed?)"))
        event.failproof = {
            "status": status,
            "decision": fp_decision,
            "detail": detail,
            "session_id": self.session_id,
            "exit_code": proc.returncode,
        }
        return event
