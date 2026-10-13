// prompt-tests/review.js
// Writes every noted or failed reply from the NEWEST results file to review.txt.
// Run from CMD:
//   cd /d C:\Users\aries\Desktop\AriesAI\prompt-tests
//   node review.js
//   notepad review.txt

const fs = require("fs");
const path = require("path");

const dir = __dirname;
const files = fs.readdirSync(dir)
  .filter(n => /^results-.+-\d+\.json$/.test(n))
  .sort((a, b) => Number(a.match(/-(\d+)\.json$/)[1]) - Number(b.match(/-(\d+)\.json$/)[1]));

if (!files.length) {
  console.error("No results-*.json file found in " + dir + ". Run: node run-prompt-tests.js");
  process.exit(1);
}

const newest = files[files.length - 1];
const results = JSON.parse(fs.readFileSync(path.join(dir, newest), "utf8"));

const lines = [`Review of ${newest}`, ""];
let count = 0;
for (const x of results) {
  if (!x.note && x.ok) continue;
  count++;
  lines.push("=".repeat(70));
  lines.push(`${x.id}  run ${x.run}  ${x.ok ? "PASS" : "FAIL: " + x.reasons.join("; ")}`);
  if (x.note) lines.push(`NOTE: ${x.note}`);
  lines.push(`PROMPT: ${x.prompt}`);
  lines.push(`FINISH: ${x.finish}`);
  lines.push("-".repeat(70));
  lines.push(x.reply || "(empty reply)");
  lines.push("");
}

fs.writeFileSync(path.join(dir, "review.txt"), lines.join("\r\n"));
console.log(`Wrote ${count} replies from ${newest} to review.txt`);