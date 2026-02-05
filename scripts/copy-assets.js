import { copyFileSync, mkdirSync, existsSync, readdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const root = join(__dirname, "..");
const dist = join(root, "dist");

// Create dist directories
mkdirSync(dist, { recursive: true });
mkdirSync(join(dist, "assets"), { recursive: true });
mkdirSync(join(dist, "ui", "popup"), { recursive: true });

// Copy manifest
copyFileSync(join(root, "manifest.json"), join(dist, "manifest.json"));

// Copy assets
if (existsSync(join(root, "assets"))) {
  const assets = readdirSync(join(root, "assets"));
  for (const asset of assets) {
    copyFileSync(join(root, "assets", asset), join(dist, "assets", asset));
  }
}

// Copy popup HTML and CSS
copyFileSync(
  join(root, "src", "ui", "popup", "popup.html"),
  join(dist, "ui", "popup", "popup.html"),
);
copyFileSync(
  join(root, "src", "ui", "popup", "popup.css"),
  join(dist, "ui", "popup", "popup.css"),
);

console.log("Assets copied successfully!");
