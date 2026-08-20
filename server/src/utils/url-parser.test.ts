// Tests for URL parser utility functions

import { describe, it, expect } from "vitest";
import {
  parseUrl,
  extractDomain,
  countSubdomains,
  hasEncodedCharacters,
  countSpecialCharacters,
  hasHomoglyphCharacters,
  levenshteinDistance,
  isSimilarToBrand,
} from "./url-parser.js";

describe("parseUrl", () => {
  it("parses a standard HTTPS URL", () => {
    const result = parseUrl("https://www.google.com/search?q=test");
    expect(result).not.toBeNull();
    expect(result!.protocol).toBe("https:");
    expect(result!.hostname).toBe("www.google.com");
    expect(result!.domain).toBe("google.com");
    expect(result!.subdomain).toBe("www");
    expect(result!.tld).toBe(".com");
    expect(result!.pathname).toBe("/search");
    expect(result!.isIP).toBe(false);
    expect(result!.hasNonStandardPort).toBe(false);
  });

  it("parses HTTP URLs", () => {
    const result = parseUrl("http://example.com/page");
    expect(result).not.toBeNull();
    expect(result!.protocol).toBe("http:");
    expect(result!.domain).toBe("example.com");
  });

  it("returns null for invalid URLs", () => {
    expect(parseUrl("not-a-url")).toBeNull();
    expect(parseUrl("")).toBeNull();
    expect(parseUrl("ftp://")).toBeNull();
  });

  it("detects IP addresses", () => {
    const result = parseUrl("http://192.168.1.1/login");
    expect(result).not.toBeNull();
    expect(result!.isIP).toBe(true);
    expect(result!.hostname).toBe("192.168.1.1");
  });

  it("detects non-standard ports", () => {
    const result = parseUrl("https://example.com:8080/page");
    expect(result).not.toBeNull();
    expect(result!.port).toBe("8080");
    expect(result!.hasNonStandardPort).toBe(true);
  });

  it("does not flag standard ports as non-standard", () => {
    const https = parseUrl("https://example.com:443/page");
    expect(https!.hasNonStandardPort).toBe(false);

    const http = parseUrl("http://example.com:80/page");
    expect(http!.hasNonStandardPort).toBe(false);
  });

  it("handles two-part TLDs (.co.uk, .com.au)", () => {
    const uk = parseUrl("https://bbc.co.uk/news");
    expect(uk).not.toBeNull();
    expect(uk!.tld).toBe(".co.uk");
    expect(uk!.domain).toBe("bbc.co.uk");

    const au = parseUrl("https://example.com.au/path");
    expect(au).not.toBeNull();
    expect(au!.tld).toBe(".com.au");
    expect(au!.domain).toBe("example.com.au");
  });

  it("handles URLs with query strings and hash", () => {
    const result = parseUrl("https://example.com/path?a=1&b=2#section");
    expect(result).not.toBeNull();
    expect(result!.search).toBe("?a=1&b=2");
    expect(result!.hash).toBe("#section");
  });

  it("lowercases hostname", () => {
    const result = parseUrl("https://EXAMPLE.COM/Path");
    expect(result!.hostname).toBe("example.com");
  });

  it("handles edge case: single-label domain", () => {
    // This should still parse, domain and tld will be unusual
    const result = parseUrl("http://localhost:3000/api");
    expect(result).not.toBeNull();
    expect(result!.hostname).toBe("localhost");
  });
});

describe("extractDomain", () => {
  it("extracts domain from URL", () => {
    expect(extractDomain("https://www.google.com/search")).toBe("google.com");
  });

  it("returns empty string for invalid URL", () => {
    expect(extractDomain("not-a-url")).toBe("");
  });
});

describe("countSubdomains", () => {
  it("counts subdomains correctly", () => {
    expect(countSubdomains("https://a.b.example.com")).toBe(2);
    expect(countSubdomains("https://example.com")).toBe(0);
    expect(countSubdomains("https://www.example.com")).toBe(1);
  });

  it("returns 0 for IP addresses", () => {
    expect(countSubdomains("http://192.168.1.1")).toBe(0);
  });
});

describe("hasEncodedCharacters", () => {
  it("detects percent-encoded characters", () => {
    expect(hasEncodedCharacters("https://example.com/%E4%B8%AD")).toBe(true);
    expect(hasEncodedCharacters("https://example.com/%20space")).toBe(true);
  });

  it("returns false for normal URLs", () => {
    expect(hasEncodedCharacters("https://example.com/page")).toBe(false);
  });
});

describe("countSpecialCharacters", () => {
  it("counts special characters in pathname", () => {
    expect(countSpecialCharacters("/path@to#page")).toBe(2);
    expect(countSpecialCharacters("/path&to*page#@end")).toBe(4);
    expect(countSpecialCharacters("/simple")).toBe(0);
  });

  it("handles empty strings", () => {
    expect(countSpecialCharacters("")).toBe(0);
  });
});

describe("hasHomoglyphCharacters", () => {
  it("detects Cyrillic characters used in homograph attacks", () => {
    expect(hasHomoglyphCharacters("аpple")).toBe(true); // Cyrillic 'а' instead of Latin 'a'
    expect(hasHomoglyphCharacters("gооgle")).toBe(true); // Cyrillic 'о'
  });

  it("returns false for normal Latin text", () => {
    expect(hasHomoglyphCharacters("apple")).toBe(false);
    expect(hasHomoglyphCharacters("google.com")).toBe(false);
  });
});

describe("levenshteinDistance", () => {
  it("calculates edit distance correctly", () => {
    expect(levenshteinDistance("kitten", "sitting")).toBe(3);
    expect(levenshteinDistance("hello", "hello")).toBe(0);
    expect(levenshteinDistance("abc", "def")).toBe(3);
    expect(levenshteinDistance("", "abc")).toBe(3);
    expect(levenshteinDistance("abc", "")).toBe(3);
  });

  it("handles single character differences", () => {
    expect(levenshteinDistance("paypal", "paypa1")).toBe(1);
    expect(levenshteinDistance("amazon", "amaz0n")).toBe(1);
  });
});

describe("isSimilarToBrand", () => {
  const brands = ["paypal", "amazon", "apple", "microsoft", "google"];

  it("detects typosquatting with character substitution", () => {
    const result = isSimilarToBrand("paypa1.com", brands);
    expect(result.isSimilar).toBe(true);
    expect(result.brand).toBe("paypal");
  });

  it("detects typosquatting with character omission", () => {
    const result = isSimilarToBrand("amazn.com", brands);
    expect(result.isSimilar).toBe(true);
    expect(result.brand).toBe("amazon");
  });

  it("does not flag exact brand matches", () => {
    const result = isSimilarToBrand("paypal.com", brands);
    expect(result.isSimilar).toBe(false);
  });

  it("does not flag unrelated domains", () => {
    const result = isSimilarToBrand("randomsite.com", brands);
    expect(result.isSimilar).toBe(false);
  });

  it("handles short brand names conservatively", () => {
    // "ups" should only match with distance 1
    const shortBrands = ["ups", "dhl"];
    expect(isSimilarToBrand("ups.com", shortBrands).isSimilar).toBe(false);
    // "upss" (distance 1) should match
    expect(isSimilarToBrand("upss.com", shortBrands).isSimilar).toBe(true);
  });
});
