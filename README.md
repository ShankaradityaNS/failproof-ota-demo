# Device Hop Detector (simulated OTA demo)

Simulated OTA firmware lands in **Sandbox A** and tries to reach **Sandbox B**. The Hopper
Detector checks every operation against the explicit grants in `safety_policy.json`. Each
operation is also reported to Failproof AI through its hook CLI.

| File | Role |
|---|---|
| `agent_pipeline.py` | Demo entry point: the two simulated sandboxes, one normal op, one hop attempt |
| `hop_detector.py` | Firmware id + SHA-256, execution identity, authorization policy, security event, alert |
| `failproof_adapter.py` | Event adapter: turns each event into a Claude Code `PreToolUse` payload (tool `ota_sandbox_access`) and pipes it to `failproofai --hook PreToolUse` |
| `failproof/device-hop-policies.mjs` | Failproof AI custom policy that re-checks the same grants and denies a hop |
| `test_hop_detector.py` | Tests for an authorized op and a detected unauthorized hop |

## What is real and what is simulated

- **Simulated:** the sandboxes, the IPs, the firmware (an inert JSON manifest that is hashed, never executed) and the "attack".
- **Enforced, in-process only:** a denied operation is not performed by the simulator. Nothing is isolated at the OS or network level.
- **Real:** the Failproof AI policy engine evaluates each event. Failproof cannot observe the
  simulated sandbox directly, so the adapter feeds it each event. With the daemon in cloud
  mode, the decision lands in `~/.failproofai/hook-activity/` and is forwarded to Failproof Cloud.

## Run

```bash
# 1. Offline tests (Failproof stubbed; policy file run under node with a stub module)
python3 -m unittest -v

# 2. Install the Failproof policy for this project
mkdir -p .failproofai/policies && cp failproof/device-hop-policies.mjs .failproofai/policies/

# 3. Demo, reporting each event to Failproof AI
python3 agent_pipeline.py

# 4. Live test against the real failproofai hook
FAILPROOF_LIVE=1 python3 -m unittest -v

# Demo without Failproof
FAILPROOF_REPORT=0 python3 agent_pipeline.py
```

In the alert, `Failproof AI: AGREES` means Failproof's hook reached the same decision as the
local detector. `MISMATCH` usually means the policy is not installed: Failproof fails open and
allows the call.
