// Domain-agent brand-detection regression tests.
//
// brand_impersonation and brand_in_subdomain are instant-block veto
// signals, so precision matters: legitimate domains that merely contain
// a brand name as a substring (amazonaws.com, appleseed.com) must NOT be
// flagged, while true impersonation structures (exact brand labels,
// brand + credential keyword) must be. These tests pin both directions.

import { describe, it, expect } from "vitest";
import { DomainAgent } from "./domain-agent.js";

const agent = new DomainAgent();

async function brandSignals(url: string): Promise<string[]> {
  const result = await agent.analyze(url);
  return (result.signals ?? [])
    .filter((s) => s.type.startsWith("brand"))
    .map((s) => s.type);
}

describe("brand detection false positives (must stay clean)", () => {
  it("does not flag official brand domains", async () => {
    expect(await brandSignals("https://www.paypal.com/")).toEqual([]);
    expect(await brandSignals("https://www.amazon.com/")).toEqual([]);
    expect(await brandSignals("https://www.apple.com/")).toEqual([]);
  });

  it("does not flag official brand subdomains", async () => {
    expect(await brandSignals("https://developer.apple.com/")).toEqual([]);
    expect(await brandSignals("https://accounts.google.com/")).toEqual([]);
  });

  it("does not flag domains that merely contain a brand substring", async () => {
    expect(await brandSignals("https://www.appleseed.com/")).toEqual([]);
    expect(await brandSignals("https://s3.amazonaws.com/bucket")).toEqual([]);
    expect(await brandSignals("https://microsoft365.com/")).toEqual([]);
  });
});

describe("brand detection true positives (veto-class impersonation)", () => {
  it("flags brand as an exact label in an unrelated domain", async () => {
    expect(await brandSignals("https://paypal-login.com/")).toContain(
      "brand_impersonation",
    );
    expect(await brandSignals("https://secure-paypal-login.weebly.com/account")).toContain(
      "brand_impersonation",
    );
  });

  it("flags brand glued to a credential keyword", async () => {
    expect(await brandSignals("https://paypalsecure.com/")).toContain(
      "brand_impersonation",
    );
    expect(await brandSignals("https://securepaypal-verify.net/")).toContain(
      "brand_impersonation",
    );
  });

  it("flags brand label in the subdomain of an unrelated domain", async () => {
    const sigs = await brandSignals(
      "https://accounts.google.com.evil-site.top/signin",
    );
    expect(sigs).toContain("brand_in_subdomain");
  });
});
