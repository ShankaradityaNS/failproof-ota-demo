// Failproof AI project policy for the SIMULATED OTA demo.
// Install: mkdir -p .failproofai/policies && cp failproof/device-hop-policies.mjs .failproofai/policies/
//
// It only acts on the raw tool `ota_sandbox_access`, which failproof_adapter.py
// emits; every other tool call is allowed untouched. It re-checks the
// event against safety_policy.json rather than trusting the decision the
// Python detector already put in the payload.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { customPolicies, allow, deny } from "failproofai";

customPolicies.add({
  name: "block-ota-device-hop",
  description: "Deny simulated OTA firmware operations that cross from one sandbox to another without an explicit grant",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    if (ctx.toolName !== "ota_sandbox_access") return allow();

    const cwd = ctx.session?.cwd ?? ctx.payload?.cwd;
    const policy = JSON.parse(readFileSync(join(cwd, "safety_policy.json"), "utf8"));
    const { firmware_id, firmware_sha256, source_sandbox, destination_sandbox, operation } = ctx.toolInput ?? {};

    const granted = policy.device_authorization.grants.some(
      (g) => g.source === source_sandbox && g.destination === destination_sandbox && g.operations.includes(operation),
    );
    if (granted) return allow(`ota grant: ${source_sandbox} -> ${destination_sandbox} '${operation}'`);

    const rule = policy.rules[0];
    const what = source_sandbox !== destination_sandbox ? rule.inject_context.error_code : "OPERATION_NOT_GRANTED";
    return deny(
      `[SIMULATED] ${what}: firmware ${firmware_id} (sha256 ${String(firmware_sha256).slice(0, 12)}…) ` +
        `from ${source_sandbox} attempted '${operation}' on ${destination_sandbox}; no grant in safety_policy.json allows it.`,
    );
  },
});
