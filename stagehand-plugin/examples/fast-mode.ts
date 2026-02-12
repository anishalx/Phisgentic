// PhishGuard Stagehand Plugin — Fast Mode Example
// Demonstrates fast mode (URL + Domain agents only, no LLM, ~200-500ms).
// Also shows manual scanner usage without wrapping Stagehand.
//
// Run: npx ts-node examples/fast-mode.ts
//
// Note: This file is excluded from tsconfig compilation.
// It serves as documentation for how to use the plugin.

import { Stagehand } from "@browserbasehq/stagehand";
import { withPhishGuard, createPhishGuardScanner } from "../src/index.js";
import type { PhishGuardResult } from "../src/index.js";
import dotenv from "dotenv";

dotenv.config();

async function demoFastMode() {
  console.log("=== Fast Mode Demo ===\n");

  // 1. Create and initialize Stagehand
  const stagehand = new Stagehand({
    env: "LOCAL",
    verbose: 1,
  });
  await stagehand.init();

  // 2. Wrap with PhishGuard in FAST mode
  //    Fast mode only runs URL + Domain agents (no page analysis, no LLM).
  //    Typical scan time: 200-500ms.
  const guarded = withPhishGuard(
    stagehand as unknown as Record<string, unknown>,
    {
      groqApiKey: "", // Not needed in fast mode
      mode: "fast",
      scanPageLinks: true,
      verbose: true,

      onPhishingDetected: (result: PhishGuardResult) => {
        console.log(`\n[ALERT] ${result.action.toUpperCase()}: ${result.url} (score: ${result.riskScore}/100)`);
        console.log(`  ${result.summary}`);
      },
    },
  );

  const page = (guarded as Record<string, unknown>).page as Stagehand["page"];

  try {
    // Navigate to various URLs — fast scans happen automatically
    console.log("\n--- Testing safe URL ---");
    await page.goto("https://github.com");
    await new Promise((resolve) => setTimeout(resolve, 1000));

    console.log("\n--- Testing another URL ---");
    await page.goto("https://example.com");
    await new Promise((resolve) => setTimeout(resolve, 1000));

    console.log("\n--- Fast mode demo complete ---\n");
  } finally {
    await stagehand.close();
  }
}

async function demoManualScanner() {
  console.log("=== Manual Scanner Demo ===\n");

  // Create a standalone scanner (no Stagehand needed for fast scans)
  const scanner = createPhishGuardScanner({
    groqApiKey: "", // Not needed for fast scans
    mode: "fast",
    verbose: false,
  });

  // Scan a list of URLs
  const testUrls = [
    "https://google.com",
    "https://paypal-secure-login.xyz/verify",
    "https://amaz0n.com/account/verify",
    "https://192.168.1.1/login",
    "https://my-bank-login-secure.tk/account",
    "https://microsoft.com",
    "https://free-iphone-winner.click/claim",
    "https://github.com/login",
  ];

  console.log("Scanning URLs...\n");

  for (const url of testUrls) {
    const result = await scanner.fastScan(url);
    const icon = result.action === "allow" ? "[OK]" : result.action === "warn" ? "[!!]" : "[XX]";
    console.log(
      `${icon} ${result.action.toUpperCase().padEnd(5)} | Score: ${String(result.riskScore).padStart(3)}/100 | ${result.scanTimeMs}ms | ${url}`,
    );
    if (result.action !== "allow") {
      console.log(`       ${result.summary}`);
    }
  }

  // Print stats
  const stats = scanner.getStats();
  console.log("\n--- Scanner Stats ---");
  console.log(`  Total scans: ${stats.totalScans}`);
  console.log(`  Allowed: ${stats.allowedCount}`);
  console.log(`  Warned: ${stats.warnedCount}`);
  console.log(`  Blocked: ${stats.blockedCount}`);
  console.log(`  Avg scan time: ${stats.avgScanTimeMs}ms`);
  console.log(`  Cache size: ${stats.cacheSize}`);
}

async function main() {
  // Run manual scanner demo first (no browser needed)
  await demoManualScanner();

  console.log("\n" + "=".repeat(50) + "\n");

  // Then run Stagehand integration demo
  await demoFastMode();
}

main().catch(console.error);
