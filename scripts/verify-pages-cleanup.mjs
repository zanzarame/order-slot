#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const deletedRef = process.env.DELETED_REF ?? "";
const pageUrl = process.env.PAGE_URL ?? "https://zanzarame.github.io/order-slot/";
const runId = process.env.GITHUB_RUN_ID ?? Date.now().toString();

function fail(message) {
  throw new Error(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex").toUpperCase();
}

function sleep(milliseconds) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, milliseconds));
}

function withCacheBust(url, suffix) {
  const target = new URL(url);
  target.searchParams.set("cleanup-check", `${runId}-${suffix}`);
  return target;
}

const match = deletedRef.match(/^preview\/v(\d+\.\d+\.\d+)$/u);
if (!match) fail(`Unsupported deleted preview ref: ${deletedRef || "missing"}`);

const version = match[1];
const base = new URL(pageUrl.endsWith("/") ? pageUrl : `${pageUrl}/`);
const preview = new URL(`preview/v${version}/`, base);
const expectedRoot = readFileSync(new URL(["..", "index.html"].join("/"), import.meta.url));
const expectedHash = sha256(expectedRoot);

let lastObservation;
for (let attempt = 1; attempt <= 12; attempt += 1) {
  const rootResponse = await fetch(withCacheBust(base, `root-${attempt}`), { cache: "no-store" });
  const rootBytes = Buffer.from(await rootResponse.arrayBuffer());
  const previewResponse = await fetch(withCacheBust(preview, `preview-${attempt}`), {
    cache: "no-store",
    redirect: "manual",
  });
  const rootMatches = rootResponse.status === 200
    && rootBytes.equals(expectedRoot)
    && sha256(rootBytes) === expectedHash;
  const previewGone = previewResponse.status === 404;
  lastObservation = {
    attempt,
    rootStatus: rootResponse.status,
    rootBytes: rootBytes.length,
    rootHash: sha256(rootBytes),
    previewStatus: previewResponse.status,
  };
  if (rootMatches && previewGone) {
    process.stdout.write(`[PASS] preview/v${version} is 404; production root is unchanged (${expectedRoot.length} bytes, ${expectedHash})\n`);
    process.exit(0);
  }
  if (attempt < 12) await sleep(5000);
}

fail(`Pages cleanup verification did not converge: ${JSON.stringify(lastObservation)}`);
