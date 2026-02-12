// PhishGuard Stagehand Plugin — Basic Usage Example
// Demonstrates full mode with automatic navigation interception and link scanning.
//
// Run: npx ts-node examples/basic-usage.ts
//
// Note: This file is excluded from tsconfig compilation.
// It serves as documentation for how to use the plugin.

import { Stagehand } from "@browserbasehq/stagehand";
import { withPhishGuard } from "../src/index.js";
import type { PhishGuardResult, LinkScanReport } from "../src/index.js";
import dotenv from "dotenv";

dotenv.config();

async function main() {
  // 1. Create and initialize Stagehand
  const stagehand = new Stagehand({
    env: "LOCAL",
    verbose: 1,
  });
  await stagehand.init();

  // 2. Wrap with PhishGuard (full mode — all 5 agents)
  //    Cast to Record<string, unknown> for the Proxy wrapper.
  //    In practice, the returned object behaves identically to the original.
  const guarded = withPhishGuard(
    stagehand as unknown as Record<string, unknown>,
    {
      groqApiKey: process.env.GROQ_API_KEY || "",
      mode: "full",
      scanPageLinks: true,
      maxLinksToScan: 30,
      linkScanConcurrency: 5,
      verbose: true,

      // Called whenever phishing is detected (warn or block verdict)
      onPhishingDetected: (result: PhishGuardResult) => {
        console.log("\n========================================");
        console.log(`PHISHING ALERT: ${result.url}`);
        console.log(`  Action: ${result.action}`);
        console.log(`  Risk Score: ${result.riskScore}/100`);
        console.log(`  Summary: ${result.summary}`);
        console.log("========================================\n");
      },

      // Called when link scanning completes for a page
      onLinksScanComplete: (report: LinkScanReport) => {
        if (report.suspiciousLinks.length > 0) {
          console.log(`\nFound ${report.suspiciousLinks.length} suspicious links on ${report.pageUrl}`);
          for (const link of report.suspiciousLinks) {
            console.log(`  [${link.riskScore}/100] ${link.url} — ${link.reason}`);
          }
        }
      },

      // Called when each scan starts and completes
      onScanStart: (url: string) => {
        console.log(`\nScanning: ${url}...`);
      },
      onScanComplete: (url: string, result: PhishGuardResult) => {
        console.log(`Scan complete: ${url} — ${result.action} (${result.riskScore}/100, ${result.scanTimeMs}ms)`);
      },
    },
  );

  // Access the guarded page (same API as stagehand.page)
  const page = (guarded as Record<string, unknown>).page as Stagehand["page"];

  try {
    // 3. Navigate — PhishGuard automatically scans each URL
    console.log("\n--- Navigating to a safe site ---");
    await page.goto("https://github.com");

    // Wait a moment for link scanning to complete in background
    await new Promise((resolve) => setTimeout(resolve, 2000));

    console.log("\n--- Navigating to another site ---");
    await page.goto("https://example.com");

    await new Promise((resolve) => setTimeout(resolve, 2000));

    // 4. Use Stagehand AI features — URL changes are monitored
    console.log("\n--- Using act() to click a link ---");
    await page.act("Click the 'More information...' link");

    await new Promise((resolve) => setTimeout(resolve, 2000));

    console.log("\n--- Example complete ---");
  } finally {
    await stagehand.close();
  }
}

main().catch(console.error);
