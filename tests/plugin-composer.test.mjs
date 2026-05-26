import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { loadRulePack } from "../packages/rule-loader/src/index.mjs";
import { createComposerPlugin } from "../packages/plugin-composer/src/index.mjs";

const testRoot = path.dirname(fileURLToPath(import.meta.url));
const frameworkRoot = path.resolve(testRoot, "..");
const composerRulePackPath = path.join(frameworkRoot, "rules", "composer-default.rules.json");

// ─── Unsafe fixture tests ────────────────────────────────────────────────────

test("composer plugin detects autoload.files injection in unsafe fixture", async () => {
  const compiledRulePack = await loadRulePack(composerRulePackPath);
  const plugin = createComposerPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "composer-unsafe"),
    compiledRulePack,
    options: {}
  });

  assert.ok(findings.length > 0, "Expected findings in unsafe fixture");
  const autoloadFinding = findings.find((f) => f.ruleId === "composer.autoload-files-entry");
  assert.ok(autoloadFinding, "Expected composer.autoload-files-entry finding");
  assert.equal(autoloadFinding.hook, "autoload.files");
  assert.equal(autoloadFinding.severity, "high");
});

test("composer plugin detects autoload-dev.files in unsafe fixture", async () => {
  const compiledRulePack = await loadRulePack(composerRulePackPath);
  const plugin = createComposerPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "composer-unsafe"),
    compiledRulePack,
    options: {}
  });

  const devFinding = findings.find((f) => f.ruleId === "composer.autoload-dev-files-entry");
  assert.ok(devFinding, "Expected composer.autoload-dev-files-entry finding");
  assert.equal(devFinding.hook, "autoload-dev.files");
});

test("composer plugin detects mutable tag-only pinning in unsafe composer.lock", async () => {
  const compiledRulePack = await loadRulePack(composerRulePackPath);
  const plugin = createComposerPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "composer-unsafe"),
    compiledRulePack,
    options: {}
  });

  const tagPinFinding = findings.find((f) => f.ruleId === "composer.lock-tag-only-pin");
  assert.ok(tagPinFinding, "Expected composer.lock-tag-only-pin finding");
  assert.equal(tagPinFinding.severity, "high");
  // The message should mention the compromised packages
  assert.ok(
    tagPinFinding.message.includes("laravel-lang/http-statuses") ||
    tagPinFinding.message.includes("laravel-lang/actions"),
    "Finding message should name the tag-pinned packages"
  );
});

test("composer plugin detects PHP base64 eval dropper in autoloaded file", async () => {
  const compiledRulePack = await loadRulePack(composerRulePackPath);
  const plugin = createComposerPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "composer-unsafe"),
    compiledRulePack,
    options: {}
  });

  const evalFinding = findings.find((f) => f.ruleId === "composer.file.php-base64-eval");
  assert.ok(evalFinding, "Expected composer.file.php-base64-eval finding from helpers.php");
  assert.equal(evalFinding.severity, "critical");
  assert.ok(evalFinding.path.endsWith("helpers.php"), "Finding path should point to helpers.php");
});

test("composer plugin detects remote fetch in autoloaded PHP file", async () => {
  const compiledRulePack = await loadRulePack(composerRulePackPath);
  const plugin = createComposerPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "composer-unsafe"),
    compiledRulePack,
    options: {}
  });

  const fetchFinding = findings.find((f) => f.ruleId === "composer.file.remote-fetch");
  assert.ok(fetchFinding, "Expected composer.file.remote-fetch finding");
  assert.equal(fetchFinding.severity, "critical");
});

test("composer plugin detects credential exfiltration patterns in autoloaded PHP file", async () => {
  const compiledRulePack = await loadRulePack(composerRulePackPath);
  const plugin = createComposerPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "composer-unsafe"),
    compiledRulePack,
    options: {}
  });

  const credFinding = findings.find((f) => f.ruleId === "composer.file.credential-exfil");
  assert.ok(credFinding, "Expected composer.file.credential-exfil finding");
  assert.equal(credFinding.severity, "high");
});

test("composer plugin detects PHP system exec in autoloaded PHP file", async () => {
  const compiledRulePack = await loadRulePack(composerRulePackPath);
  const plugin = createComposerPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "composer-unsafe"),
    compiledRulePack,
    options: {}
  });

  const execFinding = findings.find((f) => f.ruleId === "composer.file.php-system-exec");
  assert.ok(execFinding, "Expected composer.file.php-system-exec finding");
  assert.equal(execFinding.severity, "critical");
});

test("composer plugin detects malicious post-install-cmd script", async () => {
  const compiledRulePack = await loadRulePack(composerRulePackPath);
  const plugin = createComposerPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "composer-unsafe"),
    compiledRulePack,
    options: {}
  });

  const scriptFinding = findings.find((f) => f.ruleId === "composer.script-remote-exec");
  assert.ok(scriptFinding, "Expected composer.script-remote-exec finding for curl|bash hook");
  assert.equal(scriptFinding.hook, "post-install-cmd");
  assert.equal(scriptFinding.severity, "critical");
});

test("composer plugin detects inline php -r exec in lifecycle script", async () => {
  const compiledRulePack = await loadRulePack(composerRulePackPath);
  const plugin = createComposerPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "composer-unsafe"),
    compiledRulePack,
    options: {}
  });

  const phpRFinding = findings.find((f) => f.ruleId === "composer.script-inline-php-exec");
  assert.ok(phpRFinding, "Expected composer.script-inline-php-exec finding for php -r hook");
  assert.equal(phpRFinding.hook, "post-update-cmd");
});

// ─── Safe fixture tests ───────────────────────────────────────────────────────

test("composer plugin produces zero findings for safe fixture", async () => {
  const compiledRulePack = await loadRulePack(composerRulePackPath);
  const plugin = createComposerPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "composer-safe"),
    compiledRulePack,
    options: {}
  });

  assert.equal(
    findings.length,
    0,
    `Expected zero findings for safe fixture but got: ${findings.map((f) => f.ruleId).join(", ")}`
  );
});

// ─── Rule pack validation tests ───────────────────────────────────────────────

test("composer-default.rules.json loads and compiles without errors", async () => {
  const compiledRulePack = await loadRulePack(composerRulePackPath);
  assert.equal(compiledRulePack.id, "composer-default");
  assert.ok(compiledRulePack.rules.length > 0);
  // All rules must have compiled patterns
  for (const rule of compiledRulePack.rules) {
    assert.ok(rule.compiledPattern instanceof RegExp, `Rule ${rule.id} must have a compiled pattern`);
  }
});

test("a03-composer-supply-chain OWASP module loads and compiles without errors", async () => {
  const a03ModulePath = path.join(
    frameworkRoot,
    "rules",
    "modules",
    "a03-composer-supply-chain.rules.json"
  );
  const compiledRulePack = await loadRulePack(a03ModulePath);
  assert.equal(compiledRulePack.id, "owasp-a03-composer-supply-chain");
  assert.ok(compiledRulePack.rules.length >= 5);
});
