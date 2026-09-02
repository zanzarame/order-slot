#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const PUBLIC_REPOSITORY = "zanzarame/order-slot";
const PAGES_BASE_URL = "https://zanzarame.github.io/order-slot/";
const PREVIEW_REF_PREFIX = ["refs", "heads", "preview"].join("/") + "/v";
const PREVIEW_REF = /^refs\/heads\/preview\/v(\d+\.\d+\.\d+)$/u;

function fail(message) {
  throw new Error(message);
}

function git(cwd, args, encoding = "utf8") {
  return execFileSync("git", args, {
    cwd,
    encoding,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex").toUpperCase();
}

function readJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
}

function exactKeys(value, keys, label) {
  const actual = Object.keys(value ?? {}).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} keys are outside the public schema.`);
  }
}

function readRevision(repository, revision, filePath) {
  try {
    return git(repository, ["show", `${revision}:${filePath}`], null);
  } catch {
    return null;
  }
}

function listTree(repository, revision) {
  return git(repository, ["ls-tree", "-r", "-z", revision], null)
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .map((entry) => {
      const match = entry.match(/^(\d+) (\w+) ([0-9a-f]{40})\t(.+)$/u);
      if (!match) fail(`Cannot parse Git tree entry: ${entry}`);
      return { mode: match[1], type: match[2], blob: match[3], path: match[4] };
    });
}

function applicationVersion(html, label) {
  const version = html.toString("utf8")
    .match(/<html(?=[\s>])[^>]*\bdata-app-version="(\d+\.\d+\.\d+)"/u)?.[1];
  if (!version) fail(`${label} has no semantic application version.`);
  return version;
}

function validateArtifactManifest(manifest, bytes, kind, label) {
  exactKeys(manifest, ["schemaVersion", "kind", "application", "artifact", ...(kind === "release-preview" ? ["preview"] : [])], label);
  exactKeys(manifest.application, ["name", "version"], `${label}.application`);
  exactKeys(manifest.artifact, ["path", "sha256", "bytes"], `${label}.artifact`);
  const version = applicationVersion(bytes, label);
  if (manifest.schemaVersion !== 2
    || manifest.kind !== kind
    || manifest.application.name !== "Turn Order Spinner"
    || manifest.application.version !== version
    || manifest.artifact.path !== "index.html"
    || manifest.artifact.sha256 !== sha256(bytes)
    || manifest.artifact.bytes !== bytes.length) {
    fail(`${label} does not match its index artifact.`);
  }
  return version;
}

function validateProduction(repository) {
  const index = readRevision(repository, "HEAD", "index.html");
  const manifestBytes = readRevision(repository, "HEAD", "production-manifest.json");
  if (!index || !manifestBytes) fail("Production root files are missing.");
  const manifest = readJson(manifestBytes, "production-manifest.json");
  const version = validateArtifactManifest(manifest, index, "production-deployment", "production-manifest.json");
  return { index, manifestBytes, version, sha256: sha256(index), bytes: index.length };
}

function previewRefs(repository) {
  const output = git(repository, ["ls-remote", "--heads", "origin", `${PREVIEW_REF_PREFIX}*`]).trim();
  if (!output) return [];
  return output.split(/\r?\n/u).map((line) => {
    const [commit, ref] = line.split(/\s+/u);
    const version = ref?.match(PREVIEW_REF)?.[1];
    if (!version || !/^[0-9a-f]{40}$/u.test(commit)) fail(`Unsupported preview ref: ${ref ?? "missing"}`);
    return { commit, ref, version };
  });
}

function validatePreview(repository, preview) {
  git(repository, ["fetch", "--force", "--no-tags", "origin", `${preview.ref}:${preview.ref}`]);
  const commit = git(repository, ["rev-parse", preview.ref]).trim();
  if (commit !== preview.commit) fail(`${preview.ref} changed during artifact assembly.`);
  if (git(repository, ["rev-list", "--parents", "-n", "1", commit]).trim().split(/\s+/u).length !== 1) {
    fail(`${preview.ref} must be an orphan commit.`);
  }
  const tree = listTree(repository, commit);
  if (JSON.stringify(tree.map((entry) => entry.path).sort()) !== JSON.stringify(["index.html", "manifest.json"])) {
    fail(`${preview.ref} must contain exactly index.html and manifest.json.`);
  }
  if (tree.some((entry) => entry.mode !== "100644" || entry.type !== "blob")) {
    fail(`${preview.ref} contains a non-regular file.`);
  }
  const index = readRevision(repository, commit, "index.html");
  const manifest = readJson(readRevision(repository, commit, "manifest.json"), `${preview.ref} manifest`);
  const version = validateArtifactManifest(manifest, index, "release-preview", `${preview.ref} manifest`);
  exactKeys(manifest.preview, ["path", "url"], `${preview.ref}.preview`);
  const directory = `preview/v${version}`;
  if (version !== preview.version
    || manifest.preview.path !== `${directory}/index.html`
    || manifest.preview.url !== `${PAGES_BASE_URL}${directory}/`) {
    fail(`${preview.ref} preview identity is invalid.`);
  }
  return { directory, index, manifest: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`) };
}

export function assemble(repository, staging) {
  const production = validateProduction(repository);
  const previews = previewRefs(repository).map((preview) => validatePreview(repository, preview));
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true });
  writeFileSync(join(staging, "index.html"), production.index);
  writeFileSync(join(staging, "production-manifest.json"), production.manifestBytes);
  for (const preview of previews) {
    const directory = join(staging, ...preview.directory.split("/"));
    mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, "index.html"), preview.index);
    writeFileSync(join(directory, "manifest.json"), preview.manifest);
  }
  const stagedRoot = readFileSync(join(staging, "index.html"));
  if (!stagedRoot.equals(production.index)
    || sha256(stagedRoot) !== production.sha256
    || stagedRoot.length !== production.bytes) {
    fail("Staged production root differs from the verified root.");
  }
  return { ...production, previews: previews.map((preview) => preview.directory) };
}

function productionManifest(index, version) {
  return {
    schemaVersion: 2,
    kind: "production-deployment",
    application: { name: "Turn Order Spinner", version },
    artifact: { path: "index.html", sha256: sha256(index), bytes: index.length },
  };
}

function previewManifest(index, version) {
  const directory = `preview/v${version}`;
  return {
    schemaVersion: 2,
    kind: "release-preview",
    application: { name: "Turn Order Spinner", version },
    artifact: { path: "index.html", sha256: sha256(index), bytes: index.length },
    preview: { path: `${directory}/index.html`, url: `${PAGES_BASE_URL}${directory}/` },
  };
}

async function request(server, requestPath) {
  const localOrigin = ["http:", "", `127.0.0.1:${server.address().port}`].join("/");
  const response = await fetch(`${localOrigin}${requestPath}`);
  return { status: response.status, bytes: Buffer.from(await response.arrayBuffer()) };
}

async function withStaticServer(root, callback) {
  const server = createServer((requestObject, response) => {
    const requested = decodeURIComponent(requestObject.url === "/" ? "/index.html" : requestObject.url);
    const file = resolve(root, `.${requested.endsWith("/") ? `${requested}index.html` : requested}`);
    const rootPrefix = `${resolve(root)}/`;
    if (!file.replaceAll("\\", "/").startsWith(rootPrefix.replaceAll("\\", "/"))) {
      response.writeHead(400).end();
      return;
    }
    try {
      const bytes = readFileSync(file);
      response.writeHead(200).end(bytes);
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  try {
    await callback(server);
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
  }
}

async function selfTest() {
  const root = mkdtempSync(join(tmpdir(), "order-slot-pages-cycle-"));
  const remote = join(root, "remote.git");
  const repository = join(root, "repository");
  const staging = join(root, "staging");
  try {
    git(root, ["init", "--bare", remote]);
    git(root, ["clone", remote, repository]);
    git(repository, ["config", "user.name", "github-actions[bot]"]);
    git(repository, ["config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"]);
    const productionIndex = Buffer.from('<html data-app-version="8.1.0"></html>\n');
    writeFileSync(join(repository, "index.html"), productionIndex);
    writeFileSync(join(repository, "production-manifest.json"), `${JSON.stringify(productionManifest(productionIndex, "8.1.0"), null, 2)}\n`);
    git(repository, ["add", "."]);
    git(repository, ["commit", "-m", "initialize production"]);
    git(repository, ["branch", "-M", "main"]);
    git(repository, ["push", "-u", "origin", "main"]);
    const rootOnly = assemble(repository, staging);
    if (rootOnly.previews.length !== 0) fail("Root-only fixture included a preview.");
    const before = readFileSync(join(staging, "index.html"));

    git(repository, ["switch", "--orphan", "preview/v8.1.1"]);
    rmSync(join(repository, "index.html"), { force: true });
    rmSync(join(repository, "production-manifest.json"), { force: true });
    const previewIndex = Buffer.from('<html data-app-version="8.1.1"></html>\n');
    writeFileSync(join(repository, "index.html"), previewIndex);
    writeFileSync(join(repository, "manifest.json"), `${JSON.stringify(previewManifest(previewIndex, "8.1.1"), null, 2)}\n`);
    git(repository, ["add", "."]);
    git(repository, ["commit", "-m", "publish version preview"]);
    git(repository, ["push", "origin", "preview/v8.1.1"]);
    git(repository, ["switch", "main"]);
    const published = assemble(repository, staging);
    if (!published.previews.includes("preview/v8.1.1") || !readFileSync(join(staging, "index.html")).equals(before)) {
      fail("Preview publication changed production or omitted the preview.");
    }

    git(repository, ["push", "origin", ":preview/v8.1.1"]);
    const cleaned = assemble(repository, staging);
    if (cleaned.previews.length !== 0 || !readFileSync(join(staging, "index.html")).equals(before)) {
      fail("Preview cleanup did not reconstruct a root-only artifact.");
    }
    await withStaticServer(staging, async (server) => {
      const rootResponse = await request(server, "/");
      const previewResponse = await request(server, "/preview/v8.1.1/");
      if (rootResponse.status !== 200 || !rootResponse.bytes.equals(before) || previewResponse.status !== 404) {
        fail("Preview cleanup HTTP cycle failed.");
      }
    });
    console.log("[PASS] production, version preview, cleanup, and HTTP cycle");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const args = process.argv.slice(2);
if (args[0] === "--self-test" && args.length === 1) {
  await selfTest();
} else if (args[0] === "--staging" && args[1] && args.length === 2) {
  const result = assemble(process.cwd(), resolve(args[1]));
  process.stdout.write(`[PASS] staged production ${result.version}: ${result.bytes} bytes; previews: ${result.previews.join(",") || "none"}\n`);
} else {
  console.error("Usage: node scripts/build-pages-site.mjs --staging PATH | --self-test");
  process.exitCode = 2;
}
