import json
import time

from failproof_adapter import FailproofEventAdapter
from hop_detector import (
    DeviceAuthorizationPolicy,
    ExecutionIdentity,
    HopperDetector,
    format_alert,
    make_simulated_firmware,
)

# =====================================================================
# ENVIRONMENT: THE TWIN AGENTS  (all simulated, in-process)
# =====================================================================

class DecoyTrustedAgent:
    """Agent 2 / Sandbox B: Sits next to Agent 1. It broadcasts attractive trusted flags

    to trap malicious updates attempting a lateral jump.
    """
    def __init__(self):
        self.name = "sandbox-b"
        self.ip = "10.5.0.99"
        self.identity = "Primary-Core-Database-Controller"
        self.security_trust_token = "SIMULATED_TRUST_TOKEN_NOT_A_SECRET"

class StagingAgentSandbox:
    """Agent 1 / Sandbox A: The isolated staging area where incoming OTA updates arrive

    and execute their deployment tools.
    """
    def __init__(self, detector, adapter):
        self.name = "sandbox-a"
        self.ip = "10.5.0.10"
        self.detector = detector
        self.adapter = adapter
        self.identity = None
        self.events = []

    def receive_ota(self, firmware):
        """Record the firmware's execution identity and the sandbox it lands in."""
        self.identity = ExecutionIdentity(firmware.firmware_id, firmware.sha256, self.name)
        print(f"[Sandbox A]: OTA received  id={firmware.firmware_id}  sha256={firmware.sha256}")
        return self.identity

    def execute_tool(self, tool_name, arguments):
        """Every operation goes through the Hopper Detector, then is reported to Failproof AI.

        A DENY is enforced only here: the simulated operation is not 'performed'.
        """
        print(f"\n[Agent 1 Runtime]: Attempting tool execution -> {tool_name} with args {arguments}")
        event = self.detector.evaluate(self.identity, tool_name, arguments["target_ip"])
        self.adapter.report(event)
        self.events.append(event)

        if event.is_unauthorized_hop:
            print(format_alert(event))
        print(f"[Security Event]: {json.dumps(event.to_dict())}")

        if event.authorization_decision == "DENY":
            return f"FAILED: {event.detection_reason}"
        return f"SUCCESS: Simulated '{tool_name}' completed on {event.destination_sandbox} ({arguments['target_ip']})."

# =====================================================================
# RUNNING THE PIPELINE DEMO
# =====================================================================
def run_demo(adapter=None, delay=0.5):
    policy = DeviceAuthorizationPolicy.load()
    adapter = adapter or FailproofEventAdapter()
    staging_agent = StagingAgentSandbox(HopperDetector(policy), adapter)
    trusted_decoy = DecoyTrustedAgent()

    print("=== LIVE ENVIRONMENT MAP (SIMULATED — no real devices, no firmware is executed) ===")
    print(f"[*] Agent 1 Running at: {staging_agent.ip} (Sandbox A, OTA Staging Box)")
    print(f"[*] Agent 2 Running at: {trusted_decoy.ip} (Sandbox B, {trusted_decoy.identity}) -> Broadcast status: TRUSTED")
    print(f"[*] Failproof AI reporting: {'on, session ' + adapter.session_id if adapter.enabled and adapter.binary else 'off'}")
    print("============================\n")

    # The "firmware" is an inert manifest of the operations it will request.
    firmware = make_simulated_firmware("fw-ota-2026.10.25-rc1", [
        {"tool": "read_sensor", "target_ip": staging_agent.ip},
        {"tool": "communicate_with_trusted_device", "target_ip": trusted_decoy.ip},
    ])
    staging_agent.receive_ota(firmware)

    time.sleep(delay)
    print("\n--- NORMAL OPERATION (inside Sandbox A) ---")
    normal_run = staging_agent.execute_tool("read_sensor", {"target_ip": staging_agent.ip})
    print(f"Output to Agent Loop: {normal_run}")

    time.sleep(delay)
    print("\n--- ATTACK DETONATION (simulated) ---")
    print(f"[!] Malicious firmware payload scans internal routing table...")
    print(f"[!] Exploit identifies Agent 2 ({trusted_decoy.identity}) as a trusted peer.")
    print(f"[!] Exploit issues command: 'Jump to {trusted_decoy.ip}'")
    attack_run = staging_agent.execute_tool("communicate_with_trusted_device", {"target_ip": trusted_decoy.ip})
    print(f"\nOutput to Agent Loop: {attack_run}")

    print("\n[Result]: Denied operation was not performed by the simulator. "
          "This demonstrates detection + in-process refusal, not OS-level sandbox enforcement.")
    return staging_agent.events


if __name__ == "__main__":
    run_demo()
