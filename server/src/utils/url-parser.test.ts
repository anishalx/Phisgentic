// Unit tests for URL Parser utilities
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
  it("should parse a standard HTTPS URL correctly", () => {
    const result = parseUrl("https://www.example.com/path?q=1#frag");
    expect(result).not.toBeNull();
    expect(result!.protocol).toBe("https:");
    expect(result!.hostname).toBe("www.example.com");
    expect(result!.pathname).toBe("/path");
    expect(result!.search).toBe("?q=1");
    expect(result!.hash).toBe("#frag");
    expect(result!.domain).toBe("example.com");
    expect(result!.subdomain).toBe("www");
    expect(result!.tld).toBe(".com");
    expect(result!.isIP).toBe(false);
    expect(result!.hasNonStandardPort).toBe(false);
  });

  it("should detect IP addresses", () => {
    const result = parseUrl("http://192.168.1.1/login");
    expect(result).not.toBeNull();
    expect(result!.isIP).toBe(true);
    expect(result!.hostname).toBe("192.168.1.1");
  });

  it("should handle two-part TLDs like .co.uk", () => {
    const result = parseUrl("https://www.bbc.co.uk/news");
    expect(result).not.toBeNull();
    expect(result!.tld).toBe(".co.uk");
    expect(result!.domain).toBe("bbc.co.uk");
    expect(result!.subdomain).toBe("www");
  });

  it("should handle two-part TLDs like .com.au", () => {
    const result = parseUrl("https://shop.example.com.au");
    expect(result).not.toBeNull();
    expect(result!.tld).toBe(".com.au");
    expect(result!.domain).toBe("example.com.au");
    expect(result!.subdomain).toBe("shop");
  });

  it("should handle domains with no subdomain", () => {
    const result = parseUrl("https://example.com");
    expect(result).not.toBeNull();
    expect(result!.domain).toBe("example.com");
    expect(result!.subdomain).toBe("");
    expect(result!.tld).toBe(".com");
  });

  it("should handle deeply nested subdomains", () => {
    const result = parseUrl("https://a.b.c.d.example.com");
    expect(result).not.toBeNull();
    expect(result!.domain).toBe("example.com");
    expect(result!.subdomain).toBe("a.b.c.d");
  });

  it("should detect non-standard ports", () => {
    const result = parseUrl("https://example.com:8443/login");
    expect(result).not.toBeNull();
    expect(result!.hasNonStandardPort).toBe(true);
    expect(result!.port).toBe("8443");
  });

  it("should not flag standard port 443 for HTTPS", () => {
    const result = parseUrl("https://example.com:443/");
    expect(result).not.toBeNull();
    expect(result!.hasNonStandardPort).toBe(false);
  });

  it("should not flag standard port 80 for HTTP", () => {
    const result = parseUrl("http://example.com:80/");
    expect(result).not.toBeNull();
    expect(result!.hasNonStandardPort).toBe(false);
  });

  it("should return null for invalid URLs", () => {
    expect(parseUrl("not-a-url")).toBeNull();
    expect(parseUrl("")).toBeNull();
    expect(parseUrl("://missing-protocol")).toBeNull();
  });

  it("should lowercase the hostname", () => {
    const result = parseUrl("https://WWW.EXAMPLE.COM/PATH");
    expect(result).not.toBeNull();
    expect(result!.hostname).toBe("www.example.com");
    expect(result!.domain).toBe("example.com");
  });
});

describe("extractDomain", () => {
  it("should extract domain from URL", () => {
    expect(extractDomain("https://www.google.com/search")).toBe("google.com");
  });

  it("should extract domain from two-part TLD", () => {
    expect(extractDomain("https://www.bbc.co.uk")).toBe("bbc.co.uk");
  });

  it("should return empty string for invalid URL", () => {
    expect(extractDomain("not-a-url")).toBe("");
  });
});

describe("countSubdomains", () => {
  it("should return 0 for no subdomain", () => {
    expect(countSubdomains("https://example.com")).toBe(0);
  });

  it("should return 1 for www", () => {
    expect(countSubdomains("https://www.example.com")).toBe(1);
  });

  it("should count multiple subdomains", () => {
    expect(countSubdomains("https://a.b.c.example.com")).toBe(3);
  });

  it("should return 0 for IP addresses", () => {
    expect(countSubdomains("http://192.168.1.1")).toBe(0);
  });
});

describe("hasEncodedCharacters", () => {
  it("should detect percent-encoded characters", () => {
    expect(hasEncodedCharacters("https://example.com/path%2Fmore")).toBe(true);
    expect(hasEncodedCharacters("https://example.com/%20space")).toBe(true);
  });

  it("should return false for clean URLs", () => {
    expect(hasEncodedCharacters("https://example.com/clean/path")).toBe(false);
  });
});

describe("countSpecialCharacters", () => {
  it("should count special characters in URL", () => {
    const count = countSpecialCharacters("https://example.com/path?a=1&b=2");
    expect(count).toBeGreaterThan(0);
  });

  it("should return 0 for plain text", () => {
    expect(countSpecialCharacters("simpletext")).toBe(0);
  });
});

describe("hasHomoglyphCharacters", () => {
  it("should detect Cyrillic characters (homoglyphs)", () => {
    // Cyrillic 'а' (U+0430) looks like Latin 'a'
    expect(hasHomoglyphCharacters("pаypal")).toBe(true);
  });

  it("should detect Greek characters", () => {
    // Greek characters are in U+0370-U+03FF range
    expect(hasHomoglyphCharacters("gοοgle")).toBe(true); // Greek 'ο'
  });

  it("should return false for pure ASCII", () => {
    expect(hasHomoglyphCharacters("google")).toBe(false);
    expect(hasHomoglyphCharacters("paypal")).toBe(false);
  });
});

describe("levenshteinDistance", () => {
  it("should return 0 for identical strings", () => {
    expect(levenshteinDistance("abc", "abc")).toBe(0);
  });

  it("should return correct distance for single edit", () => {
    expect(levenshteinDistance("cat", "bat")).toBe(1); // substitution
    expect(levenshteinDistance("cat", "cats")).toBe(1); // insertion
    expect(levenshteinDistance("cats", "cat")).toBe(1); // deletion
  });

  it("should return correct distance for multiple edits", () => {
    expect(levenshteinDistance("kitten", "sitting")).toBe(3);
  });

  it("should handle empty strings", () => {
    expect(levenshteinDistance("", "abc")).toBe(3);
    expect(levenshteinDistance("abc", "")).toBe(3);
    expect(levenshteinDistance("", "")).toBe(0);
  });

  it("should handle paypal typosquatting variants", () => {
    expect(levenshteinDistance("paypal", "paypa1")).toBe(1); // l → 1
    expect(levenshteinDistance("paypal", "paypai")).toBe(1); // l → i
    expect(levenshteinDistance("paypal", "paypol")).toBe(1); // a → o
  });
});

describe("isSimilarToBrand", () => {
  const brands = ["paypal", "google", "amazon", "microsoft", "netflix"];

  it("should detect typosquatting (distance 1)", () => {
    const result = isSimilarToBrand("paypa1.com", brands);
    expect(result.isSimilar).toBe(true);
    expect(result.brand).toBe("paypal");
    expect(result.distance).toBe(1);
  });

  it("should detect typosquatting for longer brands (distance 2)", () => {
    const result = isSimilarToBrand("micr0saft.com", brands);
    expect(result.isSimilar).toBe(true);
    expect(result.brand).toBe("microsoft");
  });

  it("should not flag exact brand domain match (distance 0)", () => {
    const result = isSimilarToBrand("paypal.com", brands);
    expect(result.isSimilar).toBe(false);
  });

  it("should not flag completely different domains", () => {
    const result = isSimilarToBrand("stackblitz.com", brands);
    expect(result.isSimilar).toBe(false);
  });

  it("should skip brands shorter than 3 characters", () => {
    const result = isSimilarToBrand("ab.com", ["ab", ...brands]);
    // "ab" brand should be skipped (length < 3)
    expect(result.isSimilar).toBe(false);
  });

  it("should skip domains shorter than 3 characters", () => {
    const result = isSimilarToBrand("pa.com", brands);
    expect(result.isSimilar).toBe(false);
  });

  it("should use adaptive threshold (1 for short, 2 for long brands)", () => {
    // "ebay" has 4 chars → maxDistance = 1
    const result1 = isSimilarToBrand("eboy.com", ["ebay"]);
    expect(result1.isSimilar).toBe(true);
    expect(result1.distance).toBe(1);

    // "ebyy" → levenshtein("ebyy","ebay") is actually 1 (swap y↔a), so it DOES match
    const result2 = isSimilarToBrand("ebyy.com", ["ebay"]);
    expect(result2.isSimilar).toBe(true);

    // "abay" → levenshtein("abay","ebay") = 1, matches
    // "xyzz" → levenshtein("xyzz","ebay") = 4, should NOT match
    const result3 = isSimilarToBrand("xyzz.com", ["ebay"]);
    expect(result3.isSimilar).toBe(false);
  });

  it("should strip TLD before comparison", () => {
    // "paypa1.com" → domain name is "paypa1", compared to "paypal" → distance 1
    const result = isSimilarToBrand("paypa1.com", brands);
    expect(result.isSimilar).toBe(true);
  });
});
