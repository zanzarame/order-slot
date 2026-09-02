#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

const REVISION = process.env.HEAD_SHA || "HEAD";
const BASE_REVISION = process.env.BASE_SHA || "";
const HEAD_REF = process.env.HEAD_REF || "";
const EVENT_NAME = process.env.EVENT_NAME || "local";

function fail(message) {
  throw new Error(message);
}

function git(args, encoding = "utf8") {
  return execFileSync("git", args, {
    encoding,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function readRevision(filePath, revision = REVISION) {
  try {
    return git(["show", `${revision}:${filePath}`], null);
  } catch {
    return null;
  }
}

function readJson(filePath, revision = REVISION) {
  const bytes = readRevision(filePath, revision);
  if (!bytes) fail(`Required public file is missing: ${filePath}`);
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    fail(`${filePath} is not valid JSON: ${error.message}`);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex").toUpperCase();
}

function listTree(revision = REVISION) {
  return git(["ls-tree", "-r", "--name-only", "-z", revision], null)
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .sort();
}

function validateProduction() {
  const policy = readJson("publication-privacy-policy.json");
  const expectedTree = [...policy.files.treeKinds.production.requiredTipPaths].sort();
  if (JSON.stringify(listTree()) !== JSON.stringify(expectedTree)) {
    fail("Production tree does not match the policy-required paths.");
  }
  const index = readRevision("index.html");
  const manifest = readJson("production-manifest.json");
  const version = index?.toString("utf8")
    .match(/<html(?=[\s>])[^>]*\bdata-app-version="(\d+\.\d+\.\d+)"/u)?.[1];
  if (!version
    || manifest.schemaVersion !== 2
    || manifest.kind !== "production-deployment"
    || manifest.application?.name !== "Turn Order Spinner"
    || manifest.application?.version !== version
    || manifest.artifact?.path !== "index.html"
    || manifest.artifact?.sha256 !== sha256(index)
    || manifest.artifact?.bytes !== index.length) {
    fail("Production manifest does not match index.html.");
  }
  return { version, bytes: index.length, sha256: sha256(index) };
}

function changedPaths() {
  if (!BASE_REVISION || /^0+$/u.test(BASE_REVISION)) return [];
  return git(["diff", "--name-only", "-z", BASE_REVISION, REVISION], null)
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
}

function validatePullRequestScope(production) {
  if (EVENT_NAME !== "pull_request") return;
  const paths = changedPaths();
  if (paths.some((filePath) => filePath.startsWith("preview/"))) {
    fail("Version previews use orphan branches and must not be added to the production tree.");
  }
  const indexChanged = paths.includes("index.html");
  const manifestChanged = paths.includes("production-manifest.json");
  if (indexChanged !== manifestChanged) {
    fail("Production index and manifest must change together.");
  }
  if (!indexChanged) return;
  const match = HEAD_REF.match(/^release\/(?:publish|rollback)-v(\d+)-(\d+)-(\d+)$/u);
  if (!match || `${match[1]}.${match[2]}.${match[3]}` !== production.version) {
    fail("Production changes require the semantic release staging branch for their version.");
  }
}

try {
  const production = validateProduction();
  validatePullRequestScope(production);
  process.stdout.write(`[PASS] production ${production.version}: ${production.bytes} bytes, ${production.sha256}\n`);
  process.stdout.write(`[PASS] deployment policy scope for ${EVENT_NAME} ${HEAD_REF || REVISION}\n`);
} catch (error) {
  process.stderr.write(`[FAIL] ${error.message}\n`);
  process.exitCode = 1;
}
