#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { loadPolicy, loadRulePack, loadRulePacks } from "../../../packages/rule-loader/src/index.mjs";
import { runEngine } from "../../../packages/engine/src/index.mjs";
import { createNpmPlugin } from "../../../packages/plugin-npm/src/index.mjs";
import { createComposerPlugin } from "../../../packages/plugin-composer/src/index.mjs";
import { formatHuman, formatJson, formatSarif } from "../../../packages/output/src/index.mjs";

const DEFAULT_TOOL_NAME = "omsf";
const DEFAULT_DISPLAY_NAME = "OWASP Module Security Framework";

await main();

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    process.exit(0);
  }

  try {
    const defaults = getDefaults();
    const toolMeta = await readToolMetadata(defaults.packageJsonPath);

    if (args.version) {
      console.log(`${toolMeta.displayName} (${toolMeta.cliName}) ${toolMeta.version}`);
      process.exit(0);
    }

    if (args.listModules) {
      const moduleIds = await listAvailableModules(defaults.modulesDir);
      if (moduleIds.length === 0) {
        console.log("[INFO] No OWASP modules found under rules/modules.");
      } else {
        console.log("Available OWASP modules:");
        for (const moduleId of moduleIds) {
          console.log(`- ${moduleId}`);
        }
      }
      process.exit(0);
    }

    const targetPath = path.resolve(args.path || process.cwd());
    const rulePackPathList = await resolveRulePackPaths(args, defaults);

    const policyPath = path.resolve(args.policy || defaults.defaultPolicyPath);
    const policy = await loadPolicy(policyPath);
    if (Number.isFinite(args.failThreshold)) {
      policy.failThreshold = args.failThreshold;
    }

    const baselineFindings = await loadBaselineFindings(args.baseline);

    // Build composer rule pack path — either explicit override or bundled default
    const composerRulePackPath = args.composerRules
      ? path.resolve(args.composerRules)
      : defaults.defaultComposerRulePackPath;

    // Merge npm + composer rule packs so a single engine pass covers both ecosystems
    const allRulePackPaths = [...new Set([...rulePackPathList, composerRulePackPath])];
    const mergedRulePack = await loadRulePacks(allRulePackPaths);

    const report = await runEngine({
      toolName: toolMeta.cliName,
      toolVersion: toolMeta.version,
      targetPath,
      plugins: [createNpmPlugin(), createComposerPlugin()],
      compiledRulePack: mergedRulePack,
      policy,
      baselineFindings,
      failOnNew: args.failOnNew === true,
      options: {
        hooks: args.hooks
      }
    });

    const rendered = renderReport(report, args.format || "human");
    if (args.out) {
      const outPath = path.resolve(args.out);
      await fs.mkdir(path.dirname(outPath), { recursive: true });
      await fs.writeFile(outPath, rendered, "utf8");
      console.log(`[INFO] Report written to ${outPath}`);
    } else {
      process.stdout.write(ensureTrailingNewline(rendered));
    }

    process.exit(report.decision.status === "fail" ? 1 : 0);
  } catch (err) {
    console.error(`[ERROR] ${err.message}`);
    process.exit(2);
  }
}

function renderReport(report, format) {
  switch (String(format || "").toLowerCase()) {
    case "json":
      return formatJson(report, { pretty: true });
    case "sarif":
      return formatSarif(report);
    case "human":
    default:
      return formatHuman(report);
  }
}

function ensureTrailingNewline(text) {
  return text.endsWith("\n") ? text : `${text}\n`;
}

function parseArgs(argv) {
  const result = {
    hooks: [],
    modules: [],
    rules: []
  };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    switch (token) {
      case "--help":
      case "-h":
        result.help = true;
        break;
      case "--version":
      case "-v":
        result.version = true;
        break;
      case "--list-modules":
        result.listModules = true;
        break;
      case "--path":
        result.path = argv[++i];
        break;
      case "--rules":
        result.rules.push(...splitCsv(argv[++i]));
        break;
      case "--module":
      case "--modules":
        result.modules.push(...splitCsv(argv[++i]));
        break;
      case "--policy":
        result.policy = argv[++i];
        break;
      case "--format":
        result.format = argv[++i];
        break;
      case "--out":
        result.out = argv[++i];
        break;
      case "--baseline":
        result.baseline = argv[++i];
        break;
      case "--fail-on-new":
        result.failOnNew = true;
        break;
      case "--hooks":
        result.hooks = splitCsv(argv[++i]);
        break;
      case "--composer-rules":
        result.composerRules = argv[++i];
        break;
      case "--fail-threshold":
        result.failThreshold = Number(argv[++i]);
        break;
      default:
        throw new Error(`Unknown argument: ${token}. Use --help to list available options.`);
    }
  }
  return result;
}

function splitCsv(value) {
  return String(value || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

function getDefaults() {
  const filename = fileURLToPath(import.meta.url);
  const cliRoot = path.dirname(filename);
  const frameworkRoot = path.resolve(cliRoot, "../../..");
  return {
    frameworkRoot,
    packageJsonPath: path.join(frameworkRoot, "package.json"),
    modulesDir: path.join(frameworkRoot, "rules", "modules"),
    defaultRulePackPath: path.join(frameworkRoot, "rules", "npm-default.rules.json"),
    defaultComposerRulePackPath: path.join(frameworkRoot, "rules", "composer-default.rules.json"),
    defaultPolicyPath: path.join(frameworkRoot, "rules", "policy.default.json")
  };
}

async function readToolMetadata(packageJsonPath) {
  try {
    const raw = await fs.readFile(packageJsonPath, "utf8");
    const pkg = JSON.parse(raw);
    return {
      cliName: DEFAULT_TOOL_NAME,
      displayName: pkg.displayName || DEFAULT_DISPLAY_NAME,
      version: String(pkg.version || "0.0.0")
    };
  } catch {
    return {
      cliName: DEFAULT_TOOL_NAME,
      displayName: DEFAULT_DISPLAY_NAME,
      version: "0.0.0"
    };
  }
}

async function resolveRulePackPaths(args, defaults) {
  if (args.modules.length > 0 && args.rules.length > 0) {
    throw new Error("Use either --rules or --modules, not both in the same run.");
  }

  if (args.rules.length > 0) {
    return args.rules.map((x) => path.resolve(x));
  }

  if (args.modules.length > 0) {
    const modulePaths = [];
    for (const moduleToken of args.modules) {
      modulePaths.push(await resolveModulePath(moduleToken, defaults.modulesDir));
    }
    return modulePaths;
  }

  return [path.resolve(defaults.defaultRulePackPath)];
}

async function resolveModulePath(moduleToken, modulesDir) {
  if (moduleToken.includes("/") || moduleToken.includes("\\") || moduleToken.endsWith(".json")) {
    const candidatePath = path.resolve(moduleToken);
    if (await fileExists(candidatePath)) {
      return candidatePath;
    }
    throw new Error(`Module rule pack path not found: ${moduleToken}`);
  }

  const modulePath = path.join(modulesDir, `${moduleToken}.rules.json`);
  if (await fileExists(modulePath)) {
    return modulePath;
  }

  const knownModules = await listAvailableModules(modulesDir);
  throw new Error(
    `Unknown module '${moduleToken}'. Available modules: ${knownModules.join(", ") || "(none found)"}`
  );
}

async function listAvailableModules(modulesDir) {
  try {
    const entries = await fs.readdir(modulesDir, { withFileTypes: true });
    return entries
      .filter((entry) => entry.isFile() && entry.name.endsWith(".rules.json"))
      .map((entry) => entry.name.replace(/\.rules\.json$/i, ""))
      .sort();
  } catch {
    return [];
  }
}

async function loadBaselineFindings(baselinePath) {
  if (!baselinePath) {
    return [];
  }

  const resolved = path.resolve(baselinePath);
  const raw = await fs.readFile(resolved, "utf8");
  const json = JSON.parse(raw);
  if (Array.isArray(json)) {
    return json;
  }
  if (json && Array.isArray(json.findings)) {
    return json.findings;
  }
  throw new Error("Baseline file must contain a report object with 'findings' or a findings array.");
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function printHelp() {
  console.log(
    [
      `${DEFAULT_DISPLAY_NAME} (${DEFAULT_TOOL_NAME})`,
      "",
      "Usage:",
      "  omsf [options]",
      "  npx @owasp-modules/omsf [options]",
      "",
      "Options:",
      "  --path <dir>                 Target directory to scan (default: current directory)",
      "  --rules <file[,file]>        Explicit npm rule pack JSON path(s)",
      "  --composer-rules <file>      Explicit Composer rule pack JSON path (default: composer-default.rules.json)",
      "  --modules <id[,id]>          OWASP module id(s) from ./rules/modules",
      "  --list-modules               List bundled OWASP modules and exit",
      "  --policy <file>              Policy JSON file (default: ./rules/policy.default.json)",
      "  --baseline <file>            Baseline report JSON for differential runs",
      "  --fail-on-new                Fail only when new findings appear vs baseline",
      "  --format <human|json|sarif>  Output format (default: human)",
      "  --out <file>                 Write output to file instead of stdout",
      "  --hooks <a,b,c>              Override npm lifecycle hooks list",
      "  --fail-threshold <n>         Override policy failThreshold at runtime",
      "  --help, -h                   Show help",
      "  --version, -v                Show version"
    ].join("\n")
  );
}
