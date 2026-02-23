// Utility functions for URL parsing and analysis

export interface ParsedUrl {
  full: string;
  protocol: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  domain: string;
  subdomain: string;
  tld: string;
  isIP: boolean;
  hasNonStandardPort: boolean;
}

// Well-known two-part TLDs
const TWO_PART_TLDS = new Set([
  "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in", "co.id", "co.il",
  "com.au", "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.ar", "com.tw",
  "com.hk", "com.my", "com.pk", "com.ph", "com.vn", "com.ng", "com.eg", "com.co",
  "org.uk", "org.au", "org.nz",
  "net.au", "net.br", "net.nz",
  "gov.uk", "gov.au", "gov.in",
  "ac.uk", "ac.jp", "ac.kr",
  "edu.au", "edu.cn",
]);

export function parseUrl(urlString: string): ParsedUrl | null {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();

    // Check if it's an IP address
    const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

    // Extract domain parts
    const parts = hostname.split(".");
    let domain = hostname;
    let subdomain = "";
    let tld = "";

    if (!isIP && parts.length >= 2) {
      // Check for two-part TLDs like .co.uk, .com.au
      const lastTwo = parts.slice(-2).join(".");
      if (parts.length >= 3 && TWO_PART_TLDS.has(lastTwo)) {
        tld = "." + lastTwo;
        domain = parts.slice(-3).join(".");
        subdomain = parts.slice(0, -3).join(".");
      } else {
        tld = "." + parts[parts.length - 1];
        domain = parts.slice(-2).join(".");
        subdomain = parts.slice(0, -2).join(".");
      }
    }

    // Check for non-standard ports
    const isHttps = url.protocol === "https:";
    const isHttp = url.protocol === "http:";
    const standardPort =
      (isHttps && url.port === "443") ||
      (isHttp && url.port === "80") ||
      url.port === "";

    return {
      full: urlString,
      protocol: url.protocol,
      hostname,
      port: url.port,
      pathname: url.pathname,
      search: url.search,
      hash: url.hash,
      domain,
      subdomain,
      tld,
      isIP,
      hasNonStandardPort: !standardPort,
    };
  } catch {
    return null;
  }
}

export function extractDomain(url: string): string {
  const parsed = parseUrl(url);
  return parsed?.domain || "";
}

export function countSubdomains(url: string): number {
  const parsed = parseUrl(url);
  if (!parsed || parsed.isIP) return 0;
  return parsed.subdomain ? parsed.subdomain.split(".").length : 0;
}

export function hasEncodedCharacters(url: string): boolean {
  return /%[0-9A-Fa-f]{2}/.test(url);
}

export function countSpecialCharacters(url: string): number {
  const matches = url.match(/[-@#$%^&*()+=\[\]{}|\\:;"'<>,?]/g);
  return matches ? matches.length : 0;
}

export function hasHomoglyphCharacters(text: string): boolean {
  // Check for common Unicode homoglyphs
  const homoglyphPattern =
    /[\u0430-\u044f\u0400-\u042f\u0370-\u03ff\u1d00-\u1d7f]/;
  return homoglyphPattern.test(text);
}

export function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1,
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

export function isSimilarToBrand(
  domain: string,
  brands: string[],
): { isSimilar: boolean; brand?: string; distance?: number } {
  // Strip TLD from domain before comparing (e.g., "paypa1.com" -> "paypa1")
  const parsed = parseUrl(`https://${domain}`);
  const domainWithoutTld = parsed
    ? domain.replace(new RegExp(`\\${parsed.tld}$`), "").replace(/[^a-z]/gi, "").toLowerCase()
    : domain.replace(/[^a-z]/gi, "").toLowerCase();

  for (const brand of brands) {
    const cleanBrand = brand.replace(/[^a-z]/gi, "").toLowerCase();
    const distance = levenshteinDistance(domainWithoutTld, cleanBrand);

    // Adaptive threshold: short brands (<=4 chars) only allow distance 1
    const maxDistance = cleanBrand.length <= 4 ? 1 : 2;

    // If distance is small but not zero, it might be typosquatting
    if (distance > 0 && distance <= maxDistance && domainWithoutTld !== cleanBrand) {
      return { isSimilar: true, brand, distance };
    }
  }

  return { isSimilar: false };
}
