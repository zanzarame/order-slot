#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

const PUBLIC_REPOSITORY = "zanzarame/order-slot";
const DEV_REPOSITORY = "zanzarame/order-slot-dev";
const PAGES_BASE_URL = "https://zanzarame.github.io/order-slot";
const REVISION = process.env.HEAD_SHA || "HEAD";
const BASE_REVISION = process.env.BASE_SHA || "";
const HEAD_REF = process.env.HEAD_REF || "";
const EVENT_NAME = process.env.EVENT_NAME || "local";
const MAX_GIT_OUTPUT = 16 * 1024 * 1024;

const SECRET_PATTERNS = [
  { label: "private key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/u },
  { label: "GitHub token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/u },
  { label: "AWS access key", pattern: /\bAKIA[0-9A-Z]{16}\b/u },
  { label: "Google API key", pattern: /\bAIza[0-9A-Za-z_-]{30,}\b/u },
  { label: "OpenAI API key", pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/u },
  { label: "Slack token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/u },
];

function fail(message) {
  throw new Error(message);
}

function runGit(args, encoding = "utf8") {
  return execFileSync("git", args, {
    encoding,
    maxBuffer: MAX_GIT_OUTPUT,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function readAtRevision(path, revision = REVISION) {
  try {
    return runGit(["show", `${revision}:${path}`], null);
  } catch {
    return null;
  }
}

function listAtRevision(prefix, revision = REVISION) {
  const output = runGit(["ls-tree", "-r", "--name-only", "-z", revision, "--", prefix], null);
  return output
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
}

function parseJson(path, revision = REVISION) {
  const bytes = readAtRevision(path, revision);
  if (!bytes) fail(`Required file is missing: ${path}`);
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    fail(`Invalid JSON in ${path}: ${error.message}`);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex").toUpperCase();
}

function gitBlob(path, revision = REVISION) {
  return runGit(["rev-parse", `${revision}:${path}`]).trim();
}

function validatePrivacy(privacy, context) {
  const expected = {
    realParticipantDataIncluded: false,
    diagnosticLogsIncluded: false,
    credentialsIncluded: false,
    unapprovedSecretsIncluded: false,
    reviewed: true,
  };
  for (const [key, value] of Object.entries(expected)) {
    if (privacy?.[key] !== value) fail(`${context} privacy.${key} must be ${value}.`);
  }
}

function scanCredentialPatterns(text, context) {
  for (const { label, pattern } of SECRET_PATTERNS) {
    if (pattern.test(text)) fail(`${context} contains credential-like content (${label}).`);
  }
}

function getInternalVersion(html, context) {
  const version = html.match(/<html\b[^>]*\bdata-app-version="(\d+\.\d+\.\d+)"/u)?.[1];
  if (!version) fail(`${context} has no valid data-app-version.`);
  return version;
}

function validateProduction() {
  const manifest = parseJson("production-manifest.json");
  if (manifest.schemaVersion !== 1 || manifest.kind !== "production-deployment") {
    fail("production-manifest.json has an unsupported schema or kind.");
  }
  if (manifest.source?.repository !== DEV_REPOSITORY) fail("Production source repository is invalid.");
  if (manifest.public?.repository !== PUBLIC_REPOSITORY || manifest.public?.path !== "index.html") {
    fail("Production public target is invalid.");
  }
  if (!/^[0-9a-f]{40}$/u.test(manifest.source?.commit ?? "")) fail("Production source commit must be a full SHA.");
  if (!/^app\/順番スロット_v\d+\.\d+\.\d+\.html$/u.test(manifest.source?.path ?? "")) {
    fail("Production source path is invalid.");
  }
  const rootBytes = readAtRevision("index.html");
  if (!rootBytes) fail("Production root index.html is missing.");
  const rootText = rootBytes.toString("utf8");
  const rootSha = sha256(rootBytes);
  const rootBlob = gitBlob("index.html");
  const version = getInternalVersion(rootText, "Production root");
  for (const section of [manifest.source, manifest.public]) {
    if (section.version && section.version !== version) fail("Production manifest version does not match root.");
    if (section.sha256 !== rootSha || section.bytes !== rootBytes.length || section.gitBlob !== rootBlob) {
      fail("Production manifest hash, byte count, or Git blob does not match root.");
    }
  }
  if (manifest.source.version !== version) fail("Production source version does not match root.");
  validatePrivacy(manifest.privacy, "Production");
  scanCredentialPatterns(rootText, "Production root");
  return { manifest, rootBlob, rootSha, bytes: rootBytes.length, version };
}

function validatePreview(manifestPath, production) {
  const match = manifestPath.match(/^preview\/pr-([1-9]\d*)\/manifest\.json$/u);
  if (!match) fail(`Invalid preview manifest path: ${manifestPath}`);
  const pullRequest = Number(match[1]);
  const directory = `preview/pr-${pullRequest}`;
  const previewPath = `${directory}/index.html`;
  const tracked = listAtRevision(directory);
  const expectedTracked = [previewPath, manifestPath].sort();
  if (JSON.stringify([...tracked].sort()) !== JSON.stringify(expectedTracked)) {
    fail(`${directory} must contain only index.html and manifest.json.`);
  }
  const manifest = parseJson(manifestPath);
  if (manifest.schemaVersion !== 1 || manifest.kind !== "pull-request-preview") {
    fail(`${manifestPath} has an unsupported schema or kind.`);
  }
  if (manifest.source?.repository !== DEV_REPOSITORY || manifest.source?.pullRequest !== pullRequest) {
    fail(`${manifestPath} source repository or Pull Request is invalid.`);
  }
  if (!/^[0-9a-f]{40}$/u.test(manifest.source?.commit ?? "")) fail(`${manifestPath} requires a full source commit SHA.`);
  if (!/^app\/順番スロット_v\d+\.\d+\.\d+\.html$/u.test(manifest.source?.path ?? "")) {
    fail(`${manifestPath} source path is invalid.`);
  }
  if (manifest.preview?.repository !== PUBLIC_REPOSITORY || manifest.preview?.path !== previewPath) {
    fail(`${manifestPath} preview target is invalid.`);
  }
  if (manifest.preview?.url !== `${PAGES_BASE_URL}/${directory}/`) fail(`${manifestPath} URL is invalid.`);
  const previewBytes = readAtRevision(previewPath);
  if (!previewBytes) fail(`${previewPath} is missing.`);
  const previewText = previewBytes.toString("utf8");
  const previewSha = sha256(previewBytes);
  const previewBlob = gitBlob(previewPath);
  const version = getInternalVersion(previewText, previewPath);
  if (manifest.source.version !== version) fail(`${manifestPath} version does not match preview.`);
  if (manifest.source.gitBlob !== previewBlob) fail(`${manifestPath} source Git blob does not match preview blob.`);
  for (const section of [manifest.source, manifest.preview]) {
    if (section.sha256 !== previewSha || section.bytes !== previewBytes.length) {
      fail(`${manifestPath} hash or byte count does not match preview.`);
    }
  }
  const before = manifest.productionRootBefore;
  if (!/^[0-9a-f]{40}$/u.test(before?.gitBlob ?? "") || !/^[0-9A-F]{64}$/u.test(before?.sha256 ?? "") || !Number.isInteger(before?.bytes)) {
    fail(`${manifestPath} has an invalid productionRootBefore snapshot.`);
  }
  validatePrivacy(manifest.privacy, manifestPath);
  scanCredentialPatterns(previewText, previewPath);
  return { path: previewPath, pullRequest, previewBlob, previewSha, bytes: previewBytes.length, version, production };
}

function changedPaths() {
  if (!BASE_REVISION || /^0+$/u.test(BASE_REVISION)) return [];
  return runGit(["diff", "--name-only", "-z", BASE_REVISION, REVISION], null)
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
}

function sameSet(actual, expected) {
  return JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
}

function validatePullRequestScope(paths) {
  if (EVENT_NAME !== "pull_request") return;
  const previewChanges = paths.filter((path) => path.startsWith("preview/"));
  const publish = HEAD_REF.match(/^preview\/pr-([1-9]\d*)-[0-9a-f]{7,40}$/u);
  const cleanup = HEAD_REF.match(/^preview\/cleanup-pr-([1-9]\d*)$/u);
  if (publish) {
    const directory = `preview/pr-${publish[1]}`;
    const expected = [`${directory}/index.html`, `${directory}/manifest.json`];
    if (!sameSet(paths, expected)) fail("Preview publication Pull Request may change only its index.html and manifest.json.");
    if (!readAtRevision(expected[0]) || !readAtRevision(expected[1])) fail("Preview publication files must exist at the Pull Request head.");
  } else if (cleanup) {
    const directory = `preview/pr-${cleanup[1]}`;
    const expected = [`${directory}/index.html`, `${directory}/manifest.json`];
    if (!sameSet(paths, expected)) fail("Preview cleanup Pull Request may delete only its index.html and manifest.json.");
    if (readAtRevision(expected[0]) || readAtRevision(expected[1])) fail("Preview cleanup files must be absent at the Pull Request head.");
  } else if (previewChanges.length) {
    fail("preview/ changes require a preview/pr-N-sourceSHA or preview/cleanup-pr-N branch.");
  }

  const rootChanged = paths.includes("index.html");
  const manifestChanged = paths.includes("production-manifest.json");
  if (rootChanged) {
    const release = HEAD_REF.match(/^release\/v(\d+\.\d+\.\d+)$/u);
    if (!release || !manifestChanged) fail("Production root changes require release/vX.Y.Z and a matching production manifest change.");
    const manifest = parseJson("production-manifest.json");
    if (manifest.source?.version !== release[1]) fail("Release branch version does not match production manifest.");
    if (previewChanges.length) fail("Production and preview changes must not be mixed.");
  }
  if (manifestChanged && !rootChanged) {
    const existedAtBase = readAtRevision("production-manifest.json", BASE_REVISION) !== null;
    if (existedAtBase) fail("Production manifest cannot change without the production root.");
  }
}

try {
  const production = validateProduction();
  const previewManifests = listAtRevision("preview")
    .filter((path) => path.endsWith("/manifest.json"));
  const previews = previewManifests.map((path) => validatePreview(path, production));
  const paths = changedPaths();
  validatePullRequestScope(paths);
  process.stdout.write(`[PASS] production ${production.version}: blob ${production.rootBlob}, ${production.bytes} bytes\n`);
  process.stdout.write(`[PASS] ${previews.length} live preview(s) validated\n`);
  process.stdout.write(`[PASS] deployment policy scope for ${EVENT_NAME} ${HEAD_REF || REVISION}\n`);
} catch (error) {
  process.stderr.write(`[FAIL] ${error.message}\n`);
  process.exitCode = 1;
}
