const fs = require("node:fs");
const path = require("node:path");
const solc = require(path.join(process.argv[3], "node_modules", "solc"));
if (process.argv[2] === "--version") {
  fs.writeFileSync(1, solc.version());
} else {
  const input = fs.readFileSync(process.argv[2], "utf8");
  // Only supplied source contents are available; no filesystem or network imports.
  fs.writeFileSync(1, solc.compile(input, { import: () => ({ error: "Import outside supplied sources is disabled" }) }));
}
