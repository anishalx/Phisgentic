// Regression tests for the URL agent's ip_address signal severity.
//
// The README signal table documents `ip_address` as **critical** (+25).
// It used to be emitted as "high", which meant a lone public-IP + login URL
// never tripped the orchestrator's allow→warn bump rule (needs 2+ high
// signals OR 1 critical). These tests pin the severity to critical.

import { describe, it, expect } from "vitest";
import { UrlAgent } from "./url-agent.js";

const agent = new UrlAgent();

async function getSignal(url: string, type: string) {
  const result = await agent.analyze(url);
  return (result.signals ?? []).find((s) => s.type === type);
}

describe("UrlAgent ip_address signal", () => {
  it("flags public IP addresses as critical severity", async () => {
    const signal = await getSignal("http://203.0.113.5/login", "ip_address");
    expect(signal).toBeDefined();
    expect(signal!.severity).toBe("critical");
    expect(signal!.value).toBe("203.0.113.5");
  });

  it("flags public IP on non-standard port as critical severity", async () => {
    const signal = await getSignal("https://94.130.14.21:8443/account", "ip_address");
    expect(signal).toBeDefined();
    expect(signal!.severity).toBe("critical");
  });

  it("does NOT flag private/local IP addresses (RFC1918 + localhost)", async () => {
    for (const url of [
      "http://192.168.1.1/admin",
      "http://10.0.0.5/login",
      "http://172.16.0.10/panel",
      "http://172.31.255.254/",
      "http://127.0.0.1:3000/dev",
      "http://localhost:8080/",
    ]) {
      const signal = await getSignal(url, "ip_address");
      expect(signal, `expected no ip_address signal for ${url}`).toBeUndefined();
    }
  });

  it("keeps the +25 score contribution for public IPs", async () => {
    const result = await agent.analyze("http://203.0.113.5/login");
    expect(result.riskScore).toBeGreaterThanOrEqual(25);
  });

  it("does not emit ip_address for normal domains", async () => {
    const signal = await getSignal("https://example.com/login", "ip_address");
    expect(signal).toBeUndefined();
  });
});