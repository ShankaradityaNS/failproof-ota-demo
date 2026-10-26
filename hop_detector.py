"""Hopper Detector: catches simulated OTA firmware in Sandbox A reaching for Sandbox B.

Everything here is a SIMULATION. "Firmware" is a data manifest of declared
operations; nothing is executed, and no network or process isolation exists.
The decision is enforced only inside this Python process (the simulated
sandbox refuses to "run" a denied operation). It is not an OS-level control.
"""
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

POLICY_PATH = Path(__file__).with_name("safety_policy.json")


# =====================================================================
# FIRMWARE + IDENTITY
# =====================================================================

@dataclass(frozen=True)
class FirmwareUpdate:
    """A simulated OTA image: an id plus inert bytes we hash. Never executed."""
    firmware_id: str
    image: bytes

    @property
    def sha256(self):
        return hashlib.sha256(self.image).hexdigest()


@dataclass(frozen=True)
class ExecutionIdentity:
    """Who is acting: which firmware, and which sandbox it was loaded into."""
    firmware_id: str
    firmware_sha256: str
    origin_sandbox: str


def make_simulated_firmware(firmware_id, operations):
    """Build an inert image whose bytes are the JSON manifest of its operations."""
    manifest = {"simulated": True, "firmware_id": firmware_id, "operations": operations}
    return FirmwareUpdate(firmware_id, json.dumps(manifest, sort_keys=True).encode())


# =====================================================================
# AUTHORIZATION POLICY + DETECTOR
# =====================================================================

@dataclass
class SecurityEvent:
    timestamp: str
    firmware_id: str
    firmware_sha256: str
    source_sandbox: str
    destination_sandbox: str
    operation: str
    authorization_decision: str  # "ALLOW" | "DENY"
    detection_reason: str
    severity: str = "INFO"
    rule_id: str = ""
    simulated: bool = True
    target_ip: str = ""
    failproof: dict = field(default_factory=dict)  # filled in by the adapter

    @property
    def is_unauthorized_hop(self):
        return self.authorization_decision == "DENY" and self.source_sandbox != self.destination_sandbox

    def to_dict(self):
        return asdict(self)


class DeviceAuthorizationPolicy:
    def __init__(self, policy):
        self.raw = policy
        self.sandboxes = policy["sandboxes"]
        self.grants = policy["device_authorization"]["grants"]
        self.default_decision = policy["device_authorization"]["default_decision"]
        self.hop_rule = policy["rules"][0]

    @classmethod
    def load(cls, path=POLICY_PATH):
        with open(path) as f:
            return cls(json.load(f))

    def sandbox_for_ip(self, ip):
        for name, box in self.sandboxes.items():
            if box["ip"] == ip:
                return name
        return "unknown"

    def find_grant(self, source, destination, operation):
        for grant in self.grants:
            if grant["source"] == source and grant["destination"] == destination and operation in grant["operations"]:
                return grant
        return None


class HopperDetector:
    def __init__(self, policy):
        self.policy = policy

    def evaluate(self, identity, operation, target_ip):
        source = identity.origin_sandbox
        destination = self.policy.sandbox_for_ip(target_ip)
        grant = self.policy.find_grant(source, destination, operation)

        if grant:
            decision, severity, rule_id = "ALLOW", "INFO", ""
            reason = f"Explicit grant: {source} -> {destination} may '{operation}'."
        elif destination != source:
            decision, severity, rule_id = "DENY", self.policy.hop_rule["severity"], self.policy.hop_rule["id"]
            reason = (f"{self.policy.hop_rule['inject_context']['error_code']}: firmware originating in {source} "
                      f"attempted '{operation}' on {destination} ({target_ip}); no grant permits this boundary crossing.")
        else:
            decision, severity, rule_id = self.policy.default_decision, "MEDIUM", "default-deny"
            reason = f"Operation '{operation}' is not granted inside {source} (default {self.policy.default_decision})."

        return SecurityEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            firmware_id=identity.firmware_id,
            firmware_sha256=identity.firmware_sha256,
            source_sandbox=source,
            destination_sandbox=destination,
            operation=operation,
            authorization_decision=decision,
            detection_reason=reason,
            severity=severity,
            rule_id=rule_id,
            target_ip=target_ip,
        )


# =====================================================================
# ALERT
# =====================================================================

def format_alert(event):
    bar = "!" * 72
    lines = [
        bar,
        "  🚨 UNAUTHORIZED DEVICE HOP DETECTED  [SIMULATED EVENT]",
        bar,
        f"  Time        : {event.timestamp}",
        f"  Firmware    : {event.firmware_id}",
        f"  SHA-256     : {event.firmware_sha256}",
        f"  Hop         : {event.source_sandbox} -> {event.destination_sandbox} ({event.target_ip})",
        f"  Operation   : {event.operation}",
        f"  Decision    : {event.authorization_decision}  (severity {event.severity}, rule {event.rule_id})",
        f"  Reason      : {event.detection_reason}",
    ]
    if event.failproof:
        lines.append(f"  Failproof AI: {event.failproof.get('status')} — {event.failproof.get('detail', '')}")
    lines.append(bar)
    return "\n".join(lines)
