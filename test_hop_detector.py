"""Repeatable tests: one authorized operation, one detected unauthorized device hop.

    python3 -m unittest -v                      # offline (Failproof stubbed)
    FAILPROOF_LIVE=1 python3 -m unittest -v     # also calls the real failproofai hook
"""
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from agent_pipeline import run_demo
from failproof_adapter import TOOL_NAME, FailproofEventAdapter
from hop_detector import DeviceAuthorizationPolicy, ExecutionIdentity, HopperDetector, make_simulated_firmware

HERE = Path(__file__).resolve().parent
SANDBOX_A_IP, SANDBOX_B_IP = "10.5.0.10", "10.5.0.99"
EVENT_FIELDS = ["timestamp", "firmware_id", "firmware_sha256", "source_sandbox", "destination_sandbox",
                "operation", "authorization_decision", "detection_reason"]


def make_identity():
    fw = make_simulated_firmware("fw-test-1", [{"tool": "read_sensor"}])
    return fw, ExecutionIdentity(fw.firmware_id, fw.sha256, "sandbox-a")


class HopperDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = HopperDetector(DeviceAuthorizationPolicy.load())
        self.fw, self.identity = make_identity()

    def test_firmware_hash_is_sha256_of_image(self):
        self.assertEqual(self.fw.sha256, hashlib.sha256(self.fw.image).hexdigest())
        self.assertEqual(len(self.fw.sha256), 64)

    def test_authorized_operation_in_sandbox_a_is_allowed(self):
        event = self.detector.evaluate(self.identity, "read_sensor", SANDBOX_A_IP)
        self.assertEqual(event.authorization_decision, "ALLOW")
        self.assertEqual((event.source_sandbox, event.destination_sandbox), ("sandbox-a", "sandbox-a"))
        self.assertFalse(event.is_unauthorized_hop)

    def test_access_to_sandbox_b_is_detected_as_unauthorized_hop(self):
        event = self.detector.evaluate(self.identity, "communicate_with_trusted_device", SANDBOX_B_IP)
        self.assertEqual(event.authorization_decision, "DENY")
        self.assertEqual((event.source_sandbox, event.destination_sandbox), ("sandbox-a", "sandbox-b"))
        self.assertTrue(event.is_unauthorized_hop)
        self.assertIn("ERR_HOOPER_LATERAL_JUMP_DETECTED", event.detection_reason)
        d = event.to_dict()
        for f in EVENT_FIELDS:
            self.assertTrue(d[f], f"missing {f}")
        self.assertEqual(d["firmware_sha256"], self.fw.sha256)
        self.assertTrue(d["simulated"])

    def test_granted_operation_name_does_not_authorize_crossing(self):
        # read_sensor is allowed inside A, but not against B.
        event = self.detector.evaluate(self.identity, "read_sensor", SANDBOX_B_IP)
        self.assertTrue(event.is_unauthorized_hop)

    def test_unknown_destination_is_denied(self):
        event = self.detector.evaluate(self.identity, "read_sensor", "192.0.2.1")
        self.assertEqual((event.destination_sandbox, event.authorization_decision), ("unknown", "DENY"))


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.detector = HopperDetector(DeviceAuthorizationPolicy.load())
        _, self.identity = make_identity()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def fake_failproof(self):
        """A stand-in binary that speaks the documented Claude PreToolUse deny shape."""
        stub = self.tmp / "failproofai"
        stub.write_text(textwrap.dedent(f"""\
            #!{sys.executable}
            import json, sys
            p = json.load(sys.stdin)
            t = p["tool_input"]
            if t["source_sandbox"] != t["destination_sandbox"]:
                print(json.dumps({{"hookSpecificOutput": {{"hookEventName": "PreToolUse",
                    "permissionDecision": "deny", "permissionDecisionReason": "stub deny"}}}}))
            """))
        stub.chmod(0o755)
        return str(stub)

    def test_payload_is_claude_pretooluse_shape(self):
        event = self.detector.evaluate(self.identity, "communicate_with_trusted_device", SANDBOX_B_IP)
        p = FailproofEventAdapter(binary="x", enabled=True).build_payload(event)
        self.assertEqual((p["hook_event_name"], p["tool_name"]), ("PreToolUse", TOOL_NAME))
        for f in EVENT_FIELDS:
            self.assertIn(f, p["tool_input"])

    def test_adapter_reports_both_decisions_through_hook_cli(self):
        adapter = FailproofEventAdapter(binary=self.fake_failproof(), enabled=True)
        ok = adapter.report(self.detector.evaluate(self.identity, "read_sensor", SANDBOX_A_IP))
        hop = adapter.report(self.detector.evaluate(self.identity, "communicate_with_trusted_device", SANDBOX_B_IP))
        self.assertEqual((ok.failproof["status"], ok.failproof["decision"]), ("AGREES", "allow"))
        self.assertEqual((hop.failproof["status"], hop.failproof["decision"]), ("AGREES", "deny"))

    def test_missing_binary_is_reported_honestly(self):
        adapter = FailproofEventAdapter(enabled=True)
        adapter.binary = None
        event = adapter.report(self.detector.evaluate(self.identity, "read_sensor", SANDBOX_A_IP))
        self.assertEqual(event.failproof["status"], "UNAVAILABLE")


@unittest.skipUnless(shutil.which("node"), "node not installed")
class FailproofPolicyFileTests(unittest.TestCase):
    """Runs failproof/device-hop-policies.mjs under node with a stub 'failproofai' module."""

    def test_policy_allows_grant_and_denies_hop(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        stub = tmp / "node_modules" / "failproofai"
        stub.mkdir(parents=True)
        (stub / "package.json").write_text('{"name":"failproofai","type":"module","main":"index.js"}')
        (stub / "index.js").write_text(
            "export const hooks = [];\n"
            "export const customPolicies = { add: (h) => hooks.push(h) };\n"
            "export const allow = (reason) => ({ decision: 'allow', reason });\n"
            "export const deny = (reason) => ({ decision: 'deny', reason });\n")
        shutil.copy(HERE / "failproof" / "device-hop-policies.mjs", tmp / "policy.mjs")
        detector = HopperDetector(DeviceAuthorizationPolicy.load())
        _, identity = make_identity()
        cases = [detector.evaluate(identity, "read_sensor", SANDBOX_A_IP).to_dict(),
                 detector.evaluate(identity, "communicate_with_trusted_device", SANDBOX_B_IP).to_dict()]
        (tmp / "run.mjs").write_text(textwrap.dedent(f"""\
            import "./policy.mjs";
            import {{ hooks }} from "failproofai";
            const cases = {json.dumps(cases)};
            const out = [];
            for (const toolInput of cases)
              out.push(await hooks[0].fn({{ eventType: "PreToolUse", toolName: "{TOOL_NAME}", toolInput,
                                          payload: {{ cwd: {json.dumps(str(HERE))} }} }}));
            out.push(await hooks[0].fn({{ eventType: "PreToolUse", toolName: "Bash", toolInput: {{}}, payload: {{}} }}));
            console.log(JSON.stringify(out));
            """))
        res = subprocess.run(["node", "run.mjs"], cwd=tmp, capture_output=True, text=True, timeout=30)
        self.assertEqual(res.returncode, 0, res.stderr)
        allowed, denied, other = json.loads(res.stdout)
        self.assertEqual(allowed["decision"], "allow")
        self.assertEqual(denied["decision"], "deny")
        self.assertIn("ERR_HOOPER_LATERAL_JUMP_DETECTED", denied["reason"])
        self.assertEqual(other["decision"], "allow")


class EndToEndDemoTests(unittest.TestCase):
    def test_demo_allows_normal_op_and_alerts_on_hop(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            events = run_demo(adapter=FailproofEventAdapter(enabled=False), delay=0)
        self.assertEqual([e.authorization_decision for e in events], ["ALLOW", "DENY"])
        self.assertTrue(events[1].is_unauthorized_hop)
        self.assertIn("UNAUTHORIZED DEVICE HOP DETECTED", buf.getvalue())


@unittest.skipUnless(os.environ.get("FAILPROOF_LIVE") == "1", "set FAILPROOF_LIVE=1 to call the real failproofai hook")
class LiveFailproofTests(unittest.TestCase):
    """Needs .failproofai/policies/device-hop-policies.mjs installed in this project."""

    def test_real_failproof_hook_agrees_with_detector(self):
        self.assertTrue((HERE / ".failproofai" / "policies" / "device-hop-policies.mjs").exists(),
                        "install the policy first: see README")
        detector = HopperDetector(DeviceAuthorizationPolicy.load())
        _, identity = make_identity()
        adapter = FailproofEventAdapter(enabled=True)
        self.assertTrue(adapter.binary, "failproofai not on PATH")
        ok = adapter.report(detector.evaluate(identity, "read_sensor", SANDBOX_A_IP))
        hop = adapter.report(detector.evaluate(identity, "communicate_with_trusted_device", SANDBOX_B_IP))
        self.assertEqual(ok.failproof.get("decision"), "allow", ok.failproof)
        self.assertEqual(hop.failproof.get("decision"), "deny", hop.failproof)


if __name__ == "__main__":
    unittest.main()
