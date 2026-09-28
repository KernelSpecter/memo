// Tiny deterministic "bundler" used by scripts/smoke.ps1: lists src/, reads
// every .js file, burns a fixed amount of CPU (standing in for real compile
// time) and writes dist/bundle.js. Output is identical run to run.
const fs = require("fs");
const path = require("path");

const srcDir = path.join(__dirname, "src");
const distDir = path.join(__dirname, "dist");

const files = fs.readdirSync(srcDir).filter((f) => f.endsWith(".js")).sort();
let bundle = "";
let acc = 0;
for (const f of files) {
  const text = fs.readFileSync(path.join(srcDir, f), "utf8");
  bundle += `// ---- ${f}\n${text}\n`;
  for (let i = 0; i < 40_000_000; i++) acc = (acc * 31 + text.length + i) % 1_000_000_007;
}
fs.mkdirSync(distDir, { recursive: true });
fs.writeFileSync(path.join(distDir, "bundle.js"), bundle);
console.log(`bundled ${files.length} files (${bundle.length} bytes), checksum ${acc}`);
