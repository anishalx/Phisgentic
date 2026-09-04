// Orchestrator veto-calibration regression tests.
//
// Vetoes are type-based and instant-block (score >= 85, conf 0.95), so
// they must ONLY fire on deterministic detections. LLM-suggested signals
// can hallucinate veto-list type names on legitimate sites — this pins
// the origin guard (isVetoSignal) and the veto-list contents so neither
// can silently drift.

import { describe, it, expect } from "vitest";
import { isVetoSignal } from "./orchestrator.js";
import { UrlAgent } from "./url-agent.js";
import { CONFIG } from "../config/index.js";

function signal(type: string, severity: any, origin?: any) {
  return { type, severity, value: "x", description: "test", origin };
}

// Must stay in sync with the README "Critical Veto System" table.
const DOCUMENTED_VETO_SIGNALS = [
  "blocklist_match",
  "known_phishing_domain",
  "typosquatting",
  "homograph",
  "download_attempted",
  "safety_warning",
  "logo_domain_mismatch",
  "cross_origin_password_form",
  "cross_origin_credential_form",
];

describe("isVetoSignal (origin guard)", () => {
  it("lets locally detected veto-type signals block", () => {
    expect(isVetoSignal(signal("typosquatting", "critical", "local"))).toBe(true);
    expect(isVetoSignal(signal("blocklist_match", "critical", "local"))).toBe(true);
    expect(isVetoSignal(signal("homograph", "high", "local"))).toBe(true);
  });

  it("NEVER lets LLM-suggested veto-type signals block", () => {
    expect(isVetoSignal(signal("typosquatting", "critical", "llm"))).toBe(false);
    expect(isVetoSignal(signal("homograph", "low", "llm"))).toBe(false);
    expect(isVetoSignal(signal("cross_origin_password_form", "critical", "llm"))).toBe(false);
  });

  it("trusts synthetic signals from external intel (Safe Browsing)", () => {
    expect(isVetoSignal(signal("known_phishing_domain", "critical", "synthetic"))).toBe(true);
  });

  it("treats legacy inline signals without an origin as trusted", () => {
    expect(isVetoSignal(signal("typosquatting", "critical", undefined))).toBe(true);
  });

  it("does not veto on non-veto types even at critical severity", () => {
    expect(isVetoSignal(signal("ip_address", "critical", "local"))).toBe(false);
    expect(isVetoSignal(signal("external_form_action", "critical", "local"))).toBe(false);
    expect(isVetoSignal(signal("brand_impersonation", "critical", "local"))).toBe(false);
  });
});

describe("veto-list contents stay in sync with the README", () => {
  it("CRITICAL_VETO_SIGNALS matches the documented table exactly", () => {
    expect([...CONFIG.CRITICAL_VETO_SIGNALS].sort()).toEqual(
      [...DOCUMENTED_VETO_SIGNALS].sort(),
    );
  });
});

describe("local detections are stamped as local origin", () => {
  it("url-agent signals from deterministic analysis carry origin local", async () => {
    const agent = new UrlAgent();
    const result = await agent.analyze("http://203.0.113.5/login");
    const signals = result.signals ?? [];
    expect(signals.length).toBeGreaterThan(0);
    for (const s of signals) {
      expect(s.origin).toBe("local");
    }
  });
});
