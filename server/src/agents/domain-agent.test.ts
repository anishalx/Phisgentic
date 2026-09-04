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
    expect(await brandSignals("https://www.applecare.com/")).toEqual([]);
    expect(await brandSignals("https://googlemail.com/")).toEqual([]);
    expect(await brandSignals("https://login.microsoftonline.com/")).toEqual([]);
    expect(await brandSignals("https://shopify-support.com/")).toEqual([]);
    expect(await brandSignals("https://netflixparty.com/")).toEqual([]);
    expect(await brandSignals("https://instagrammer.com/")).toEqual([]);
  });

  it("does not flag words that merely start with a squat prefix", async () => {
    // No brand involved — "get" + "response" is not "get" + a brand.
    expect(await brandSignals("https://getresponse.com/")).toEqual([]);
    expect(await brandSignals("https://mygov.com/")).toEqual([]);
  });

  it("excludes official brand subdomains at the label boundary", async () => {
    expect(await brandSignals("https://evil.paypal.com/")).toEqual([]);
    expect(await brandSignals("https://secure.amazon.com/")).toEqual([]);
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
    expect(await brandSignals("https://securepaypal.net/")).toContain(
      "brand_impersonation",
    );
  });

  it("flags brand glued to a keyword even on the brand's own TLD", async () => {
    // "securepaypal.com" / "verification-paypal.com" end their STRING with
    // "paypal.com" but are NOT official — the label boundary is the hyphen,
    // not a dot, so they must still be flagged as impersonation.
    expect(await brandSignals("https://securepaypal.com/")).toContain(
      "brand_impersonation",
    );
    expect(await brandSignals("https://verification-paypal.com/")).toContain(
      "brand_impersonation",
    );
    expect(await brandSignals("https://my-paypal.com/")).toContain(
      "brand_impersonation",
    );
  });

  it("flags non-hyphenated my/get/free-style prefix squats", async () => {
    expect(await brandSignals("https://mypaypal.com/")).toContain(
      "brand_impersonation",
    );
    expect(await brandSignals("https://getpaypal.com/")).toContain(
      "brand_impersonation",
    );
    expect(await brandSignals("https://freepaypal.com/")).toContain(
      "brand_impersonation",
    );
    expect(await brandSignals("https://officialamazon.com/")).toContain(
      "brand_impersonation",
    );
    expect(await brandSignals("https://myapple.com/")).toContain(
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
