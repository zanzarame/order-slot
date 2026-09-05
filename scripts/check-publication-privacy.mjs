#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { TextDecoder } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
export const defaultPublicationPrivacyPolicyPath = resolve(
  scriptDirectory,
  "..",
  "publication-privacy-policy.json",
);

const MAX_GIT_OUTPUT = 32 * 1024 * 1024;
const MAX_URL_DECODE_PASSES = 4;
const VALID_ROLES = new Set(["author", "committer", "tagger"]);
const VALID_CATEGORIES = new Set(["human", "system", "bot"]);
const SEMVER = /^\d+\.\d+\.\d+$/u;
const SHA256 = /^[0-9A-F]{64}$/u;
const GITHUB_HTTPS_BASE = ["https:", "", "github.com", ""].join("/");
const DATA_SCHEME = ["da", "ta", ":"].join("");
const URL_REFERENCE = /https?:\/\/[^\s"'<>`\\]+/gu;
const DATA_URI_REFERENCE = new RegExp(
  "\\b" + DATA_SCHEME + "[^\\s\"'<>`\\\\)]+",
  "giu",
);
const DATA_URI_PREFIX = new RegExp(
  "\\b" + DATA_SCHEME + "(?=[^\\s\"'<>`\\\\)])",
  "iu",
);
const REFERENCE_SEGMENT_CHARACTER = /[\p{L}\p{M}\p{N}_.-]/u;
const WINDOWS_PATH_REFERENCE = /(?<![\\\p{L}\p{M}\p{N}_.-])(?:[\p{L}\p{M}\p{N}][\p{L}\p{M}\p{N}_.-]*\\)+[\p{L}\p{M}\p{N}][\p{L}\p{M}\p{N}_.-]*/gu;
const EXACT_REPOSITORY_REFERENCE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const MIME_TYPE_REFERENCE = /^(?:application|audio|font|image|message|model|multipart|text|video)\/[A-Za-z0-9!#$&^_.+-]+$/iu;
const CSS_MEASUREMENT_RATIO = /^\d+(?:\.\d+)?\/\d+(?:\.\d+)?(?:cap|ch|cm|em|ex|ic|in|lh|mm|pc|pt|px|q|rem|rlh|vb|vh|vi|vmax|vmin|vw)$/iu;
const REFERENCE_LABEL = /(?:repository|repo|path|source|input|route|url|href|src|ref)\s*[:=]\s*[`"'(\[]?\s*$/iu;
const REPOSITORY_REFERENCE_LABEL = /(?:repository|repo)\s*[:=]\s*[`"'(\[]?\s*$/iu;
const PATH_REFERENCE_LABEL = /(?:path|source|input|route|href|src)\s*[:=]\s*[`"'(\[]?\s*$/iu;
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const PNG_TEXT_CHUNKS = new Set(["iTXt", "tEXt", "zTXt"]);
const MAX_DATA_URI_NESTING = 4;
const APPROVED_INDEX_ARTIFACTS = Object.freeze([
  Object.freeze({
    version: "8.1.0",
    bytes: 716907,
    sha256: "697DC2BF861556C8FE8A9C3BB95800184C18ED8D9E219E8183B0F40DD046A15F",
  }),
  Object.freeze({
    version: "8.1.12",
    bytes: 691793,
    sha256: "2E490062836662B76BE4E1416485972A9FDB2E455C08B6955615A8D75AC1B90B",
  }),
]);

export class PublicationPrivacyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PublicationPrivacyError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PublicationPrivacyError(code, message);
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected, location) {
  if (!isPlainObject(value)) fail("POLICY_SCHEMA", `${location} must be an object.`);
  const actual = Object.keys(value).sort((left, right) => left.localeCompare(right, "en"));
  const wanted = [...expected].sort((left, right) => left.localeCompare(right, "en"));
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail("POLICY_SCHEMA", `${location} keys must be exactly: ${wanted.join(", ")}.`);
  }
}

function requireUniqueStringArray(value, location, { allowEmpty = false } = {}) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    fail("POLICY_SCHEMA", `${location} must be ${allowEmpty ? "an" : "a non-empty"} array.`);
  }
  if (value.some(item => typeof item !== "string" || !item)) {
    fail("POLICY_SCHEMA", `${location} must contain non-empty strings only.`);
  }
  if (new Set(value).size !== value.length) fail("POLICY_SCHEMA", `${location} must not contain duplicates.`);
}

function isSafeRelativePath(value, { directory = false } = {}) {
  if (typeof value !== "string" || !value || value.startsWith("/") || value.includes("\\")) return false;
  if (directory !== value.endsWith("/")) return false;
  const segments = value.replace(/\/$/u, "").split("/");
  return segments.every(segment => (
    segment !== "."
    && segment !== ".."
    && /^[A-Za-z0-9_.-]+$/u.test(segment)
  ));
}

export function validatePublicationPrivacyPolicy(policy) {
  exactKeys(policy, ["schemaVersion", "publicRepository", "publicPagesBaseUrl", "git", "files"], "policy");
  if (policy.schemaVersion !== 2) fail("POLICY_SCHEMA", "policy.schemaVersion must be 2.");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(policy.publicRepository)) {
    fail("POLICY_SCHEMA", "policy.publicRepository must contain an exact owner and repository name.");
  }
  let pagesUrl;
  try {
    pagesUrl = new URL(policy.publicPagesBaseUrl);
  } catch {
    fail("POLICY_SCHEMA", "policy.publicPagesBaseUrl must be an absolute URL.");
  }
  if (pagesUrl.protocol !== "https:" || !policy.publicPagesBaseUrl.endsWith("/")) {
    fail("POLICY_SCHEMA", "policy.publicPagesBaseUrl must be an HTTPS directory URL ending in /.");
  }

  exactKeys(policy.git, ["minimumCommitTimestamp", "requireSingleRoot", "identities"], "policy.git");
  if (Number.isNaN(Date.parse(policy.git.minimumCommitTimestamp))) {
    fail("POLICY_SCHEMA", "policy.git.minimumCommitTimestamp must be an ISO timestamp.");
  }
  if (policy.git.requireSingleRoot !== true) {
    fail("POLICY_SCHEMA", "policy.git.requireSingleRoot must be true for the clean public history.");
  }
  if (!Array.isArray(policy.git.identities) || policy.git.identities.length === 0) {
    fail("POLICY_SCHEMA", "policy.git.identities must be a non-empty array.");
  }
  const identityKeys = new Set();
  for (const [index, identity] of policy.git.identities.entries()) {
    const location = `policy.git.identities[${index}]`;
    exactKeys(identity, ["name", "email", "category", "roles"], location);
    if (typeof identity.name !== "string" || !identity.name.trim()) fail("POLICY_SCHEMA", `${location}.name is invalid.`);
    if (typeof identity.email !== "string" || !/^[^\s@]+@[^\s@]+$/u.test(identity.email)) {
      fail("POLICY_SCHEMA", `${location}.email is invalid.`);
    }
    if (!VALID_CATEGORIES.has(identity.category)) fail("POLICY_SCHEMA", `${location}.category is invalid.`);
    if (identity.category === "human" && !/^\d+\+[A-Za-z0-9_.-]+@users\.noreply\.github\.com$/u.test(identity.email)) {
      fail("POLICY_SCHEMA", `${location} human email must be an explicit GitHub noreply identity.`);
    }
    requireUniqueStringArray(identity.roles, `${location}.roles`);
    if (identity.roles.some(role => !VALID_ROLES.has(role))) fail("POLICY_SCHEMA", `${location}.roles contains an unsupported role.`);
    const key = `${identity.name}\0${identity.email}`;
    if (identityKeys.has(key)) fail("POLICY_SCHEMA", `${location} duplicates an identity pair.`);
    identityKeys.add(key);
  }

  exactKeys(
    policy.files,
    [
      "treeKinds",
      "allowedUrlPrefixes",
      "allowedRepositoryReferences",
      "allowedRepositoryBasenames",
      "allowedPathReferences",
      "allowedPathReferencePrefixes",
      "allowedGitHubActions",
      "manifestSchemas",
    ],
    "policy.files",
  );
  exactKeys(policy.files.treeKinds, ["production", "preview"], "policy.files.treeKinds");
  const publicTreePaths = new Set();
  for (const treeKind of ["production", "preview"]) {
    const tree = policy.files.treeKinds[treeKind];
    exactKeys(tree, ["allowedPaths", "requiredTipPaths"], `policy.files.treeKinds.${treeKind}`);
    requireUniqueStringArray(tree.allowedPaths, `policy.files.treeKinds.${treeKind}.allowedPaths`);
    requireUniqueStringArray(tree.requiredTipPaths, `policy.files.treeKinds.${treeKind}.requiredTipPaths`);
    for (const allowedPath of tree.allowedPaths) {
      if (!isSafeRelativePath(allowedPath)) fail("POLICY_SCHEMA", `${treeKind} contains an invalid allowed path: ${allowedPath}`);
      publicTreePaths.add(allowedPath);
    }
    for (const requiredPath of tree.requiredTipPaths) {
      if (!tree.allowedPaths.includes(requiredPath)) {
        fail("POLICY_SCHEMA", `${treeKind} required path is not allowed: ${requiredPath}`);
      }
    }
  }
  requireUniqueStringArray(policy.files.allowedUrlPrefixes, "policy.files.allowedUrlPrefixes");
  for (const prefix of policy.files.allowedUrlPrefixes) {
    let url;
    try {
      url = new URL(prefix);
    } catch {
      fail("POLICY_SCHEMA", `Invalid allowed URL prefix: ${prefix}`);
    }
    if (url.protocol !== "https:") fail("POLICY_SCHEMA", `Allowed URL prefix must use HTTPS: ${prefix}`);
  }
  requireUniqueStringArray(policy.files.allowedRepositoryReferences, "policy.files.allowedRepositoryReferences");
  if (policy.files.allowedRepositoryReferences.some(reference => !EXACT_REPOSITORY_REFERENCE.test(reference))) {
    fail("POLICY_SCHEMA", "policy.files.allowedRepositoryReferences must contain exact full repository names.");
  }
  if (!policy.files.allowedRepositoryReferences.includes(policy.publicRepository)) {
    fail("POLICY_SCHEMA", "policy.publicRepository must be included in allowedRepositoryReferences.");
  }
  requireUniqueStringArray(
    policy.files.allowedRepositoryBasenames,
    "policy.files.allowedRepositoryBasenames",
    { allowEmpty: true },
  );
  const allowedRepositoryReferenceBasenames = new Set(
    policy.files.allowedRepositoryReferences.map(reference => reference.split("/")[1]),
  );
  for (const basename of policy.files.allowedRepositoryBasenames) {
    if (!/^[A-Za-z0-9_.-]+$/u.test(basename) || !allowedRepositoryReferenceBasenames.has(basename)) {
      fail("POLICY_SCHEMA", `Repository basename is not backed by an allowed full reference: ${basename}`);
    }
  }
  requireUniqueStringArray(policy.files.allowedPathReferences, "policy.files.allowedPathReferences");
  for (const reference of policy.files.allowedPathReferences) {
    if (!isSafeRelativePath(reference) || publicTreePaths.has(reference)) {
      fail("POLICY_SCHEMA", `Explicit path reference is invalid or duplicates a public tree path: ${reference}`);
    }
  }
  requireUniqueStringArray(policy.files.allowedPathReferencePrefixes, "policy.files.allowedPathReferencePrefixes");
  for (const prefix of policy.files.allowedPathReferencePrefixes) {
    if (!isSafeRelativePath(prefix, { directory: true })) {
      fail("POLICY_SCHEMA", `Invalid allowed path reference prefix: ${prefix}`);
    }
  }
  requireUniqueStringArray(policy.files.allowedGitHubActions, "policy.files.allowedGitHubActions");
  exactKeys(policy.files.manifestSchemas, ["production-manifest.json", "manifest.json"], "policy.files.manifestSchemas");
  for (const [filename, schema] of Object.entries(policy.files.manifestSchemas)) {
    exactKeys(schema, ["schemaVersion", "kind", "keys"], `policy.files.manifestSchemas.${filename}`);
    if (!Number.isInteger(schema.schemaVersion) || schema.schemaVersion < 1) {
      fail("POLICY_SCHEMA", `${filename} schemaVersion is invalid.`);
    }
    if (typeof schema.kind !== "string" || !schema.kind) fail("POLICY_SCHEMA", `${filename} kind is invalid.`);
    if (!isPlainObject(schema.keys)) fail("POLICY_SCHEMA", `${filename} keys must be an object.`);
    for (const [objectPath, keys] of Object.entries(schema.keys)) {
      requireUniqueStringArray(keys, `${filename}.keys.${objectPath}`);
    }
  }
  return policy;
}

export function loadPublicationPrivacyPolicy(policyPath = defaultPublicationPrivacyPolicyPath) {
  let policy;
  try {
    policy = JSON.parse(readFileSync(policyPath, "utf8"));
  } catch (error) {
    fail("POLICY_UNAVAILABLE", `Cannot read valid privacy policy ${policyPath}: ${error.message}`);
  }
  return validatePublicationPrivacyPolicy(policy);
}

function normalizeRemote(remote) {
  return remote.trim().replace(/\.git$/u, "").replace(/^git@github\.com:/u, GITHUB_HTTPS_BASE);
}

function runGit(repositoryRoot, args, encoding = "utf8") {
  try {
    return execFileSync("git", args, {
      cwd: repositoryRoot,
      encoding,
      maxBuffer: MAX_GIT_OUTPUT,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    const detail = Buffer.isBuffer(error.stderr) ? error.stderr.toString("utf8") : error.stderr;
    fail("GIT_UNAVAILABLE", `git ${args.join(" ")} failed: ${(detail || error.message).trim()}`);
  }
}

function inspectRepositoryRoot(repositoryRoot, policy) {
  const requested = resolve(repositoryRoot);
  const actual = resolve(runGit(requested, ["rev-parse", "--show-toplevel"]).trim());
  if (actual !== requested) fail("GIT_SCOPE", `--public-repo must be the repository root: ${actual}`);
  const remote = normalizeRemote(runGit(requested, ["remote", "get-url", "origin"]));
  const expected = `${GITHUB_HTTPS_BASE}${policy.publicRepository}`;
  if (remote !== expected) fail("PUBLIC_REPOSITORY", "Public origin does not match the configured public repository.");
  return requested;
}

function identityAllowed(policy, role, name, email) {
  return policy.git.identities.some(identity => (
    identity.name === name
    && identity.email === email
    && identity.roles.includes(role)
  ));
}

function identityPairAllowed(policy, name, email) {
  return policy.git.identities.some(identity => (
    identity.name === name
    && identity.email === email
  ));
}

function identityNameFromTextPrefix(linePrefix) {
  const trimmed = linePrefix.trim();
  const trailer = trimmed.match(/^[A-Za-z0-9][A-Za-z0-9-]*:[ \t]*(.*)$/u);
  return (trailer ? trailer[1] : trimmed).trim();
}

function validateIdentity(policy, role, name, email, objectLabel) {
  if (!identityAllowed(policy, role, name, email)) {
    fail("GIT_IDENTITY", `${objectLabel} ${role} identity is not allowlisted.`);
  }
}

function validateTimestamp(policy, timestamp, objectLabel, field) {
  const instant = Date.parse(timestamp);
  const minimum = Date.parse(policy.git.minimumCommitTimestamp);
  if (Number.isNaN(instant) || instant < minimum) {
    fail("GIT_HISTORY_BOUNDARY", `${objectLabel} ${field} is unavailable or predates the clean-history boundary.`);
  }
}

function sortPaths(paths) {
  return [...paths].sort((left, right) => left.localeCompare(right, "en"));
}

function sameStringSet(left, right) {
  const sortedLeft = sortPaths(left);
  const sortedRight = sortPaths(right);
  return sortedLeft.length === sortedRight.length
    && sortedLeft.every((value, index) => value === sortedRight[index]);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex").toUpperCase();
}

function isApprovedIndexArtifact(bytes) {
  const version = bytes.toString("utf8")
    .match(/<html(?=[\s>])[^>]*\bdata-app-version="(\d+\.\d+\.\d+)"/u)?.[1];
  const digest = sha256(bytes);
  return APPROVED_INDEX_ARTIFACTS.some(artifact => (
    artifact.version === version
    && artifact.bytes === bytes.length
    && artifact.sha256 === digest
  ));
}

function validateManifestKeys(value, schema, filename) {
  for (const [objectPath, keys] of Object.entries(schema.keys)) {
    const target = objectPath === "$" ? value : value?.[objectPath];
    if (!isPlainObject(target)) fail("PUBLIC_MANIFEST_SCHEMA", `${filename}.${objectPath} must be an object.`);
    const actual = Object.keys(target);
    if (!sameStringSet(actual, keys)) {
      fail("PUBLIC_MANIFEST_SCHEMA", `${filename}.${objectPath} keys must be exactly: ${sortPaths(keys).join(", ")}.`);
    }
  }
}

function validateManifest(bytes, filename, policy, indexBytes) {
  const schema = policy.files.manifestSchemas[filename];
  if (!schema) fail("PUBLIC_MANIFEST_SCHEMA", `No manifest schema is configured for ${filename}.`);
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    fail("PUBLIC_MANIFEST_SCHEMA", `${filename} is not valid JSON: ${error.message}`);
  }
  validateManifestKeys(manifest, schema, filename);
  if (manifest.schemaVersion !== schema.schemaVersion || manifest.kind !== schema.kind) {
    fail("PUBLIC_MANIFEST_SCHEMA", `${filename} schemaVersion or kind is not allowlisted.`);
  }
  if (manifest.application.name !== "Turn Order Spinner" || !SEMVER.test(manifest.application.version)) {
    fail("PUBLIC_MANIFEST_SCHEMA", `${filename} application identity is invalid.`);
  }
  if (manifest.artifact.path !== "index.html"
    || !SHA256.test(manifest.artifact.sha256)
    || !Number.isInteger(manifest.artifact.bytes)
    || manifest.artifact.bytes <= 0) {
    fail("PUBLIC_MANIFEST_SCHEMA", `${filename} artifact metadata is invalid.`);
  }
  if (indexBytes) {
    const version = indexBytes.toString("utf8").match(/<html(?=[\s>])[^>]*\bdata-app-version="(\d+\.\d+\.\d+)"/u)?.[1];
    if (version !== manifest.application.version
      || sha256(indexBytes) !== manifest.artifact.sha256
      || indexBytes.length !== manifest.artifact.bytes) {
      fail("PUBLIC_MANIFEST_ARTIFACT", `${filename} does not match index.html version, SHA-256, and bytes.`);
    }
  }
  if (filename === "manifest.json") {
    const directory = `preview/v${manifest.application.version}`;
    if (manifest.preview.path !== `${directory}/index.html`
      || manifest.preview.url !== `${policy.publicPagesBaseUrl}${directory}/`) {
      fail("PUBLIC_MANIFEST_SCHEMA", "manifest.json preview path or URL is not the public version boundary.");
    }
  }
}

function maskReference(value) {
  return value.replace(/[^\n]/gu, " ");
}

function decodeBoundedPercentEncoding(
  value,
  filePath,
  code,
  label,
  { plusAsSpace = false } = {},
) {
  let current = plusAsSpace ? value.replace(/\+/gu, " ") : value;
  for (let pass = 0; pass < MAX_URL_DECODE_PASSES; pass += 1) {
    let decoded;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      fail(code, `${filePath} contains ${label} with invalid percent encoding.`);
    }
    if (decoded === current) return current;
    current = decoded;
  }
  if (/%[0-9A-Fa-f]{2}/u.test(current)) {
    fail(code, `${filePath} contains ${label} encoding beyond the bounded decode limit.`);
  }
  return current;
}

function decodeStrictBase64(payload, filePath) {
  if (!payload || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(payload)) {
    fail("PUBLIC_DATA_URI", `${filePath} contains a data URI with invalid base64 syntax.`);
  }
  const bytes = Buffer.from(payload, "base64");
  if (bytes.toString("base64") !== payload) {
    fail("PUBLIC_DATA_URI", `${filePath} contains a non-canonical base64 data URI.`);
  }
  return bytes;
}

function decodeUtf8(bytes, filePath) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("PUBLIC_DATA_URI", `${filePath} contains a textual data URI that is not valid UTF-8.`);
  }
}

function validateTextualSvg(svg, filePath, policy, dataUriDepth) {
  if (!/^\s*<svg(?:\s|>)/iu.test(svg) || !/<\/svg>\s*$/iu.test(svg)) {
    fail("PUBLIC_DATA_URI", `${filePath} contains a textual SVG data URI without an SVG document boundary.`);
  }
  const withoutStandardNamespace = svg.replace(
    /\bxmlns\s*=\s*(?:"http:\/\/www\.w3\.org\/2000\/svg"|'http:\/\/www\.w3\.org\/2000\/svg')/giu,
    maskReference,
  );
  validateTextReferences(withoutStandardNamespace, `${filePath} textual SVG data URI`, policy, {
    dataUriDepth,
    strictSlashReferences: true,
  });
}

function pngCrc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function validatePngStructure(bytes, filePath) {
  if (bytes.length < PNG_SIGNATURE.length || !bytes.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
    fail("PUBLIC_DATA_URI", `${filePath} contains a data URI without a valid PNG signature.`);
  }

  let offset = PNG_SIGNATURE.length;
  let seenHeader = false;
  let seenImageData = false;
  let seenEnd = false;
  while (offset < bytes.length) {
    if (bytes.length - offset < 12) {
      fail("PUBLIC_DATA_URI", `${filePath} contains a truncated PNG chunk.`);
    }
    const length = bytes.readUInt32BE(offset);
    const typeStart = offset + 4;
    const dataStart = typeStart + 4;
    const dataEnd = dataStart + length;
    const chunkEnd = dataEnd + 4;
    if (dataEnd < dataStart || chunkEnd > bytes.length) {
      fail("PUBLIC_DATA_URI", `${filePath} contains a PNG chunk outside the payload boundary.`);
    }
    const type = bytes.subarray(typeStart, dataStart).toString("ascii");
    if (!/^[A-Za-z]{4}$/u.test(type)) {
      fail("PUBLIC_DATA_URI", `${filePath} contains an invalid PNG chunk type.`);
    }
    const expectedCrc = bytes.readUInt32BE(dataEnd);
    if (pngCrc32(bytes.subarray(typeStart, dataEnd)) !== expectedCrc) {
      fail("PUBLIC_DATA_URI", `${filePath} contains a PNG chunk with an invalid CRC.`);
    }

    if (!seenHeader) {
      if (type !== "IHDR" || length !== 13) {
        fail("PUBLIC_DATA_URI", `${filePath} contains a PNG without a leading IHDR chunk.`);
      }
      const header = bytes.subarray(dataStart, dataEnd);
      if (header.readUInt32BE(0) === 0
        || header.readUInt32BE(4) === 0
        || header[10] !== 0
        || header[11] !== 0
        || header[12] > 1) {
        fail("PUBLIC_DATA_URI", `${filePath} contains invalid PNG IHDR fields.`);
      }
      seenHeader = true;
    } else if (type === "IHDR") {
      fail("PUBLIC_DATA_URI", `${filePath} contains multiple PNG IHDR chunks.`);
    }

    if (PNG_TEXT_CHUNKS.has(type)) {
      fail("PUBLIC_DATA_URI", `${filePath} contains PNG textual metadata that cannot be treated as opaque.`);
    }
    if (type === "IDAT") seenImageData = true;
    if (type === "IEND") {
      if (length !== 0 || !seenImageData || chunkEnd !== bytes.length) {
        fail("PUBLIC_DATA_URI", `${filePath} contains an invalid PNG IEND boundary or trailing bytes.`);
      }
      seenEnd = true;
    } else if (seenEnd) {
      fail("PUBLIC_DATA_URI", `${filePath} contains a PNG chunk after IEND.`);
    }
    offset = chunkEnd;
  }
  if (!seenHeader || !seenImageData || !seenEnd) {
    fail("PUBLIC_DATA_URI", `${filePath} contains an incomplete PNG chunk structure.`);
  }
}

function validateDataUri(candidate, filePath, policy, dataUriDepth) {
  if (dataUriDepth >= MAX_DATA_URI_NESTING) {
    fail("PUBLIC_DATA_URI", `${filePath} exceeds the data URI nesting limit.`);
  }
  const commaIndex = candidate.indexOf(",");
  if (commaIndex < 0) fail("PUBLIC_DATA_URI", `${filePath} contains a malformed data URI.`);
  const metadata = candidate.slice(DATA_SCHEME.length, commaIndex);
  const payload = candidate.slice(commaIndex + 1);
  const [rawMediaType, ...rawParameters] = metadata.split(";");
  const mediaType = rawMediaType.toLowerCase();
  const parameters = rawParameters.map(parameter => parameter.toLowerCase());
  if (!/^[A-Za-z][A-Za-z0-9!#$&^_.+-]*\/[A-Za-z0-9!#$&^_.+-]+$/u.test(rawMediaType)
    || parameters.length > 1
    || (parameters.length === 1 && parameters[0] !== "base64")) {
    fail("PUBLIC_DATA_URI", `${filePath} contains an unsupported data URI media type or parameter.`);
  }
  const isBase64 = parameters[0] === "base64";
  if (mediaType === "image/svg+xml") {
    const svg = isBase64
      ? decodeUtf8(decodeStrictBase64(payload, filePath), filePath)
      : decodeBoundedPercentEncoding(payload, filePath, "PUBLIC_DATA_URI", "a textual data URI");
    validateTextualSvg(svg, filePath, policy, dataUriDepth + 1);
    return;
  }
  if (mediaType === "image/png") {
    if (!isBase64) fail("PUBLIC_DATA_URI", `${filePath} contains a PNG data URI without base64 encoding.`);
    const bytes = decodeStrictBase64(payload, filePath);
    validatePngStructure(bytes, filePath);
    return;
  }
  fail("PUBLIC_DATA_URI", `${filePath} contains an unsupported non-image or opaque data URI.`);
}

function validateAndMaskDataUris(source, filePath, policy, dataUriDepth) {
  const masked = source.replace(DATA_URI_REFERENCE, (candidate) => {
    validateDataUri(candidate, filePath, policy, dataUriDepth);
    return maskReference(candidate);
  });
  if (DATA_URI_PREFIX.test(masked)) {
    fail("PUBLIC_DATA_URI", `${filePath} contains a malformed or unbounded data URI.`);
  }
  return masked;
}

function allowedPublicPathReferences(policy) {
  return new Set([
    ...Object.values(policy.files.treeKinds).flatMap(tree => tree.allowedPaths),
    ...policy.files.allowedPathReferences,
  ]);
}

function repositoryFamilyToken(token, publicBasename) {
  return token === publicBasename
    || ["-", ".", "_"].some(separator => token.startsWith(`${publicBasename}${separator}`));
}

function ownerlessRepositoryReferenceContext(source, match) {
  const start = match.index ?? 0;
  const end = start + match[0].length;
  const before = source.slice(Math.max(0, start - 80), start);
  const after = source.slice(end, end + 1);
  return REFERENCE_LABEL.test(before)
    || /`\s*$/u.test(before)
    || after === "`";
}

function regularExpressionMethodSyntax(source, match, candidate) {
  const segments = candidate.split("/");
  const end = (match.index ?? 0) + match[0].length;
  return segments.length === 2
    && /^\.[A-Za-z_$][A-Za-z0-9_$]*$/u.test(segments[1])
    && source[end] === "(";
}

function referenceLabelKind(source, match) {
  const start = match.index ?? 0;
  const before = source.slice(Math.max(0, start - 80), start);
  if (REPOSITORY_REFERENCE_LABEL.test(before)) return "repository";
  if (PATH_REFERENCE_LABEL.test(before)) return "path";
  if (REFERENCE_LABEL.test(before)) return "reference";
  return null;
}

function quotedReferenceContext(source, match) {
  const start = match.index ?? 0;
  const end = start + match[0].length;
  const before = source.slice(Math.max(0, start - 80), start);
  const after = source.slice(end, end + 1);
  return /[`"']\s*$/u.test(before)
    || /^[`"']/u.test(after);
}

function* slashSeparatedReferenceMatches(source) {
  let coveredUntil = -1;
  for (
    let slashIndex = source.indexOf("/");
    slashIndex >= 0;
    slashIndex = source.indexOf("/", slashIndex + 1)
  ) {
    if (slashIndex < coveredUntil
      || !REFERENCE_SEGMENT_CHARACTER.test(source[slashIndex - 1] ?? "")
      || !REFERENCE_SEGMENT_CHARACTER.test(source[slashIndex + 1] ?? "")) continue;

    let start = slashIndex - 1;
    while (start > 0 && REFERENCE_SEGMENT_CHARACTER.test(source[start - 1])) start -= 1;
    let end = slashIndex + 2;
    while (end < source.length && REFERENCE_SEGMENT_CHARACTER.test(source[end])) end += 1;
    while (source[end] === "/" && REFERENCE_SEGMENT_CHARACTER.test(source[end + 1] ?? "")) {
      end += 2;
      while (end < source.length && REFERENCE_SEGMENT_CHARACTER.test(source[end])) end += 1;
    }
    coveredUntil = end;
    if (source[start - 1] === "\\") continue;
    yield { 0: source.slice(start, end), index: start };
  }
}

function candidateHasReferenceContext(
  source,
  match,
  candidate,
  policy,
  allowedPaths,
  strictSlashReferences,
  labelKind,
) {
  if (allowedPaths.has(candidate)
    || policy.files.allowedPathReferencePrefixes.some(prefix => candidate.startsWith(prefix))
    || policy.files.allowedGitHubActions.includes(candidate)
    || policy.files.allowedRepositoryReferences.includes(candidate)) {
    return true;
  }
  if (strictSlashReferences) return true;
  if (labelKind) return true;
  if (MIME_TYPE_REFERENCE.test(candidate)) return false;
  if (CSS_MEASUREMENT_RATIO.test(candidate)) return false;
  if (quotedReferenceContext(source, match)) return true;
  if (regularExpressionMethodSyntax(source, match, candidate)) return false;
  return true;
}

function validatePathOrRepositoryCandidate(candidate, filePath, policy, allowedPaths, labelKind = null) {
  if (!isSafeRelativePath(candidate)) {
    fail("PUBLIC_SOURCE_PATH", `${filePath} contains an unsafe relative path reference.`);
  }
  const pathAllowed = allowedPaths.has(candidate)
    || policy.files.allowedPathReferencePrefixes.some(prefix => candidate.startsWith(prefix));
  if (pathAllowed
    || policy.files.allowedGitHubActions.includes(candidate)
    || policy.files.allowedRepositoryReferences.includes(candidate)) return;
  if (labelKind === "path") {
    fail("PUBLIC_SOURCE_PATH", `${filePath} contains a path reference outside the public allowlist.`);
  }
  if (labelKind === "repository") {
    fail("PUBLIC_REPOSITORY_REFERENCE", `${filePath} contains a repository reference outside the allowlist.`);
  }
  if (EXACT_REPOSITORY_REFERENCE.test(candidate)) {
    if (!policy.files.allowedRepositoryReferences.includes(candidate)) {
      fail("PUBLIC_REPOSITORY_REFERENCE", `${filePath} contains a repository reference outside the allowlist.`);
    }
    return;
  }
  fail("PUBLIC_SOURCE_PATH", `${filePath} contains a path reference outside the public allowlist.`);
}

function validatePathAndRepositoryReferences(
  source,
  filePath,
  policy,
  { strictSlashReferences = false } = {},
) {
  const allowedPaths = allowedPublicPathReferences(policy);
  for (const match of slashSeparatedReferenceMatches(source)) {
    const candidate = match[0].replace(/[),.;:\]}]+$/u, "");
    const labelKind = referenceLabelKind(source, match);
    if (!candidateHasReferenceContext(
      source,
      match,
      candidate,
      policy,
      allowedPaths,
      strictSlashReferences,
      labelKind,
    )) continue;
    validatePathOrRepositoryCandidate(candidate, filePath, policy, allowedPaths, labelKind);
  }
  for (const match of source.matchAll(WINDOWS_PATH_REFERENCE)) {
    const candidate = match[0].replace(/[),.;:\]}]+$/u, "");
    validatePathOrRepositoryCandidate(candidate, filePath, policy, allowedPaths);
  }

  const publicBasename = policy.publicRepository.split("/")[1];
  for (const match of source.matchAll(/\b[A-Za-z0-9][A-Za-z0-9_.-]*\b/gu)) {
    const token = match[0];
    if (repositoryFamilyToken(token, publicBasename)
      && ownerlessRepositoryReferenceContext(source, match)
      && !policy.files.allowedRepositoryBasenames.includes(token)) {
      fail("PUBLIC_REPOSITORY_REFERENCE", `${filePath} contains an ownerless repository-family reference outside the allowlist.`);
    }
  }
}

function matchingAllowedUrlPrefix(candidate, policy) {
  return [...policy.files.allowedUrlPrefixes]
    .sort((left, right) => right.length - left.length)
    .find(prefix => (
      prefix.endsWith("/")
        ? candidate.startsWith(prefix)
        : candidate === prefix
          || candidate.startsWith(`${prefix}/`)
          || candidate.startsWith(`${prefix}?`)
          || candidate.startsWith(`${prefix}#`)
    ));
}

function decodeUrlReferenceSuffix(value, filePath) {
  return decodeBoundedPercentEncoding(
    value,
    filePath,
    "PUBLIC_URL",
    "a URL",
    { plusAsSpace: true },
  );
}

function validateUrlEmbeddedReferences(candidate, allowedPrefix, filePath, policy) {
  const suffix = candidate.slice(allowedPrefix.length);
  const parameterStart = suffix.search(/[?#]/u);
  const encodedPath = parameterStart === -1 ? suffix : suffix.slice(0, parameterStart);
  const encodedParameters = parameterStart === -1 ? "" : suffix.slice(parameterStart);
  const pathReference = decodeUrlReferenceSuffix(encodedPath, filePath).replace(/^\/+|\/+$/gu, "");
  if (pathReference) {
    validatePathOrRepositoryCandidate(pathReference, filePath, policy, allowedPublicPathReferences(policy));
  }
  const parameterReferences = decodeUrlReferenceSuffix(encodedParameters, filePath);
  if (parameterReferences) {
    validatePathAndRepositoryReferences(parameterReferences, filePath, policy, {
      strictSlashReferences: true,
    });
  }
}

function validateTextReferences(
  source,
  filePath,
  policy,
  { dataUriDepth = 0, strictSlashReferences = false } = {},
) {
  const normalized = source.replace(/\r\n?/gu, "\n");
  const sourceWithoutDataUris = validateAndMaskDataUris(
    normalized,
    filePath,
    policy,
    dataUriDepth,
  );
  for (const match of sourceWithoutDataUris.matchAll(URL_REFERENCE)) {
    const candidate = match[0].replace(/[),.;\]}]+$/u, "");
    let url;
    try {
      url = new URL(candidate);
    } catch {
      fail("PUBLIC_URL", `${filePath} contains an unparseable URL.`);
    }
    const allowedPrefix = matchingAllowedUrlPrefix(candidate, policy);
    if (url.protocol !== "https:" || !allowedPrefix) {
      fail("PUBLIC_URL", `${filePath} contains a URL outside the allowlist.`);
    }
    validateUrlEmbeddedReferences(candidate, allowedPrefix, filePath, policy);
  }
  const sourceWithoutUrls = sourceWithoutDataUris.replace(URL_REFERENCE, maskReference);

  let sourceWithoutAllowedActionPins = sourceWithoutDataUris;
  sourceWithoutAllowedActionPins = sourceWithoutAllowedActionPins.replace(
    /\buses:\s*([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)/gu,
    (full, action, revision) => {
      if (!policy.files.allowedGitHubActions.includes(action)) {
        fail("PUBLIC_ACTION", `${filePath} uses a GitHub Action outside the allowlist.`);
      }
      return `uses: ${action}@${revision.length === 40 ? "PIN" : revision}`;
    },
  );

  for (const match of sourceWithoutDataUris.matchAll(
    /<\s*([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*>/gu,
  )) {
    const matchIndex = match.index ?? 0;
    const lineStart = sourceWithoutDataUris.lastIndexOf("\n", matchIndex - 1) + 1;
    const linePrefix = sourceWithoutDataUris.slice(lineStart, matchIndex).trim();
    const name = identityNameFromTextPrefix(linePrefix);
    const email = match[1];
    if (!name || !identityPairAllowed(policy, name, email)) {
      fail("PUBLIC_IDENTITY_REFERENCE", `${filePath} contains a name and email pair outside the identity allowlist.`);
    }
  }

  const allowedEmails = new Set(policy.git.identities.map(identity => identity.email));
  for (const match of sourceWithoutDataUris.matchAll(/\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gu)) {
    if (!allowedEmails.has(match[0])) fail("PUBLIC_EMAIL", `${filePath} contains an email outside the identity allowlist.`);
  }

  validatePathAndRepositoryReferences(sourceWithoutUrls, filePath, policy, {
    strictSlashReferences,
  });
  if (/(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])/u.test(sourceWithoutAllowedActionPins)) {
    fail("PUBLIC_COMMIT_REFERENCE", `${filePath} contains a commit-like 40-character identifier outside an allowed Action pin.`);
  }
}

function validateTreeSnapshot({ paths, readBytes, policy, treeKind, requireComplete, label }) {
  const tree = policy.files.treeKinds[treeKind];
  if (!tree) fail("PUBLIC_TREE_KIND", `Unknown public tree kind: ${treeKind}`);
  for (const filePath of paths) {
    if (!tree.allowedPaths.includes(filePath)) fail("PUBLIC_PATH", `${label} contains a path outside the ${treeKind} allowlist.`);
  }
  if (requireComplete && !sameStringSet(paths, tree.requiredTipPaths)) {
    fail("PUBLIC_PATH", `${label} must contain exactly the required ${treeKind} paths.`);
  }
  const indexBytes = paths.includes("index.html") ? readBytes("index.html") : null;
  const indexHasAtomicApproval = indexBytes ? isApprovedIndexArtifact(indexBytes) : false;
  for (const filePath of paths) {
    const bytes = filePath === "index.html" && indexBytes ? indexBytes : readBytes(filePath);
    if (bytes.includes(0)) fail("PUBLIC_BINARY", `${label}:${filePath} is not an allowed text file.`);
    if (filePath === "publication-privacy-policy.json" && requireComplete) {
      let publicPolicy;
      try {
        publicPolicy = JSON.parse(bytes.toString("utf8"));
      } catch (error) {
        fail("PUBLIC_POLICY_COPY", `${label}:${filePath} is invalid JSON: ${error.message}`);
      }
      if (JSON.stringify(publicPolicy) !== JSON.stringify(policy)) {
        fail("PUBLIC_POLICY_COPY", `${label}:${filePath} is not the exact consumer policy.`);
      }
    }
    if (filePath === "scripts/check-publication-privacy.mjs" && requireComplete) {
      const checkerBytes = readFileSync(fileURLToPath(import.meta.url));
      if (!bytes.equals(checkerBytes)) {
        fail("PUBLIC_CHECKER_COPY", `${label}:${filePath} is not byte-identical to the consumer checker.`);
      }
    }
    if (Object.hasOwn(policy.files.manifestSchemas, filePath)) validateManifest(bytes, filePath, policy, indexBytes);
    // Exact artifact approval owns the immutable index as a whole; every other text is scanned.
    if (filePath !== "index.html" || !indexHasAtomicApproval) {
      validateTextReferences(bytes.toString("utf8"), filePath, policy);
    }
  }
}

function listWorktreeFiles(root) {
  const files = [];
  const visit = directory => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (directory === root && entry.name === ".git") continue;
      const fullPath = resolve(directory, entry.name);
      const relativePath = relative(root, fullPath).split(sep).join("/");
      const stats = lstatSync(fullPath);
      if (stats.isSymbolicLink()) fail("PUBLIC_PATH", `Public worktree must not contain symbolic links: ${relativePath}`);
      if (stats.isDirectory()) visit(fullPath);
      else if (stats.isFile()) files.push(relativePath);
      else fail("PUBLIC_PATH", `Unsupported public worktree entry: ${relativePath}`);
    }
  };
  visit(root);
  return sortPaths(files);
}

export function validatePublicWorktree({
  repositoryRoot,
  treeKind,
  policy = loadPublicationPrivacyPolicy(),
}) {
  validatePublicationPrivacyPolicy(policy);
  const root = inspectRepositoryRoot(repositoryRoot, policy);
  const paths = listWorktreeFiles(root);
  validateTreeSnapshot({
    paths,
    readBytes: filePath => readFileSync(resolve(root, ...filePath.split("/"))),
    policy,
    treeKind,
    requireComplete: true,
    label: "public worktree",
  });
  return { treeKind, fileCount: paths.length, paths };
}

function parseCommitMetadata(root, commit) {
  const output = runGit(root, [
    "show",
    "-s",
    "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%aI%x00%cI%x00%B",
    commit,
  ]).trimEnd();
  const fields = output.split("\0");
  if (fields.length < 8 || fields.slice(0, 7).some(field => !field)) {
    fail("GIT_METADATA", `Cannot parse complete commit metadata for ${commit}.`);
  }
  return {
    commit: fields[0],
    authorName: fields[1],
    authorEmail: fields[2],
    committerName: fields[3],
    committerEmail: fields[4],
    authorTimestamp: fields[5],
    committerTimestamp: fields[6],
    message: fields.slice(7).join("\0"),
  };
}

function inspectTag(root, tagName, policy, historyCommit) {
  const fullRef = runGit(root, ["rev-parse", "--verify", `refs/tags/${tagName}`]).trim();
  const objectType = runGit(root, ["cat-file", "-t", fullRef]).trim();
  if (objectType !== "tag") fail("GIT_TAG", `Published tag ${tagName} must be annotated.`);
  const tagObject = runGit(root, ["cat-file", "tag", fullRef]);
  const messageSeparator = tagObject.indexOf("\n\n");
  if (messageSeparator < 0) fail("GIT_TAG", `Cannot parse annotated tag message for ${tagName}.`);
  const taggerMatches = [...tagObject.slice(0, messageSeparator).matchAll(/^tagger (.*) <([^<>]+)> (\d+) ([+-]\d{4})$/gmu)];
  if (taggerMatches.length !== 1) fail("GIT_TAG", `Cannot parse annotated tagger metadata for ${tagName}.`);
  const tagger = taggerMatches[0];
  validateIdentity(policy, "tagger", tagger[1], tagger[2], `tag ${tagName}`);
  validateTimestamp(
    policy,
    new Date(Number(tagger[3]) * 1000).toISOString(),
    `tag ${tagName}`,
    "tagger timestamp",
  );
  validateTextReferences(tagObject.slice(messageSeparator + 2), `tag ${tagName} message`, policy);
  const taggedCommit = runGit(root, ["rev-parse", "--verify", `${fullRef}^{commit}`]).trim();
  try {
    execFileSync("git", ["merge-base", "--is-ancestor", taggedCommit, historyCommit], {
      cwd: root,
      stdio: "ignore",
    });
  } catch {
    fail("GIT_TAG", `Published tag ${tagName} is outside the inspected public history.`);
  }
  return { name: tagName, object: fullRef, commit: taggedCommit };
}

function listRepositoryTags(root) {
  return runGit(root, ["for-each-ref", "--format=%(refname:strip=2)", "refs/tags"])
    .trim()
    .split(/\r?\n/u)
    .filter(Boolean);
}

export function validatePublicGitHistory({
  repositoryRoot,
  revision,
  tagNames,
  treeKind,
  policy = loadPublicationPrivacyPolicy(),
}) {
  validatePublicationPrivacyPolicy(policy);
  if (typeof revision !== "string" || !revision) fail("GIT_SCOPE", "A public history revision is required.");
  if (!Array.isArray(tagNames)) fail("GIT_SCOPE", "Published tag scope is required; use an empty array for no tags.");
  if (tagNames.some(tagName => typeof tagName !== "string" || !tagName) || new Set(tagNames).size !== tagNames.length) {
    fail("GIT_SCOPE", "Published tag scope must contain unique non-empty tag names.");
  }
  const root = inspectRepositoryRoot(repositoryRoot, policy);
  if (runGit(root, ["rev-parse", "--is-shallow-repository"]).trim() !== "false") {
    fail("GIT_HISTORY_BOUNDARY", "A shallow repository cannot prove the complete reachable public history.");
  }
  const repositoryTags = listRepositoryTags(root);
  if (!sameStringSet(repositoryTags, tagNames)) {
    fail("GIT_TAG_SCOPE", "Published tag scope does not exactly match refs/tags/* in the public repository.");
  }
  const historyCommit = runGit(root, ["rev-parse", "--verify", `${revision}^{commit}`]).trim();
  const commits = runGit(root, ["rev-list", "--reverse", "--topo-order", historyCommit])
    .trim()
    .split(/\r?\n/u)
    .filter(Boolean);
  if (commits.length === 0) fail("GIT_SCOPE", `No commits were resolved for ${revision}.`);
  const roots = runGit(root, ["rev-list", "--max-parents=0", historyCommit])
    .trim()
    .split(/\r?\n/u)
    .filter(Boolean);
  if (policy.git.requireSingleRoot && roots.length !== 1) {
    fail("GIT_HISTORY_BOUNDARY", `Clean public history must have exactly one root commit; found ${roots.length}.`);
  }

  for (const [index, commit] of commits.entries()) {
    const metadata = parseCommitMetadata(root, commit);
    validateIdentity(policy, "author", metadata.authorName, metadata.authorEmail, `commit ${commit}`);
    validateIdentity(policy, "committer", metadata.committerName, metadata.committerEmail, `commit ${commit}`);
    validateTimestamp(policy, metadata.authorTimestamp, `commit ${commit}`, "author timestamp");
    validateTimestamp(policy, metadata.committerTimestamp, `commit ${commit}`, "committer timestamp");
    validateTextReferences(metadata.message, `commit ${commit} message`, policy);
    const paths = runGit(root, ["ls-tree", "-r", "--name-only", "-z", commit])
      .split("\0")
      .filter(Boolean);
    validateTreeSnapshot({
      paths,
      readBytes: filePath => runGit(root, ["show", `${commit}:${filePath}`], null),
      policy,
      treeKind,
      requireComplete: index === commits.length - 1,
      label: `commit ${commit}`,
    });
  }

  const tags = tagNames.map(tagName => inspectTag(root, tagName, policy, historyCommit));
  return {
    revision: historyCommit,
    treeKind,
    commitCount: commits.length,
    rootCommit: roots[0],
    tags,
  };
}

function parseArguments(argv) {
  const valuedOptions = new Set(["--policy", "--public-repo", "--tree-kind", "--history", "--tags", "--tag"]);
  const flagOptions = new Set(["--policy-only", "--worktree"]);
  const options = new Map();
  const tagNames = [];
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (flagOptions.has(token)) {
      if (options.has(token)) fail("ARGUMENT", `Duplicate option: ${token}`);
      options.set(token, true);
      continue;
    }
    if (!valuedOptions.has(token)) fail("ARGUMENT", `Unknown option: ${token}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) fail("ARGUMENT", `Missing or invalid value for ${token}.`);
    if (token === "--tag") tagNames.push(value);
    else {
      if (options.has(token)) fail("ARGUMENT", `Duplicate option: ${token}`);
      options.set(token, value);
    }
    index += 1;
  }
  if (new Set(tagNames).size !== tagNames.length) fail("ARGUMENT", "Published tags must not be duplicated.");
  return { options, tagNames };
}

function requiredOption(options, name) {
  const value = options.get(name);
  if (!value) fail("ARGUMENT", `Required option is missing: ${name}`);
  return value;
}

function runCli() {
  const { options, tagNames } = parseArguments(process.argv.slice(2));
  const policy = loadPublicationPrivacyPolicy(options.get("--policy") ?? defaultPublicationPrivacyPolicyPath);
  if (options.get("--policy-only")) {
    if (options.size !== 1 && !(options.size === 2 && options.has("--policy"))) {
      fail("ARGUMENT", "--policy-only cannot be combined with repository checks.");
    }
    return { mode: "policy-only", policy: "valid" };
  }

  const repositoryRoot = requiredOption(options, "--public-repo");
  const treeKind = requiredOption(options, "--tree-kind");
  if (options.get("--worktree")) {
    const allowed = new Set(["--policy", "--public-repo", "--tree-kind", "--worktree"]);
    if ([...options.keys()].some(option => !allowed.has(option)) || tagNames.length > 0) {
      fail("ARGUMENT", "--worktree cannot be combined with history or tag options.");
    }
    return { mode: "worktree", ...validatePublicWorktree({ repositoryRoot, treeKind, policy }) };
  }
  const allowed = new Set(["--policy", "--public-repo", "--tree-kind", "--history", "--tags"]);
  if ([...options.keys()].some(option => !allowed.has(option))) fail("ARGUMENT", "History mode contains incompatible options.");
  const tagsOption = options.get("--tags");
  if (tagNames.length === 0 && tagsOption !== "none") {
    fail("ARGUMENT", "Published tag scope is required; use --tags none or repeated --tag.");
  }
  if (tagNames.length > 0 && tagsOption) {
    fail("ARGUMENT", "Use either --tags none or repeated --tag, not both.");
  }
  if (tagsOption && tagsOption !== "none") {
    fail("ARGUMENT", "--tags accepts only `none`; use repeated --tag for published tags.");
  }
  return {
    mode: "history",
    ...validatePublicGitHistory({
      repositoryRoot,
      revision: requiredOption(options, "--history"),
      tagNames,
      treeKind,
      policy,
    }),
  };
}

const isDirectExecution = process.argv[1]
  && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isDirectExecution) {
  try {
    const result = runCli();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    const code = error instanceof PublicationPrivacyError ? error.code : "UNEXPECTED";
    process.stderr.write(`ERROR [${code}]: ${error.message}\n`);
    process.exitCode = 1;
  }
}
