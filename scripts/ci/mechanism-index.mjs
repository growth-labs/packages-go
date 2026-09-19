#!/usr/bin/env node
// scripts/ci/mechanism-index.mjs — propagated by fulcrum-labs/platform-foundations.
// Do not edit in a consumer; fix it upstream.
//
// Generates docs/agent/mechanisms.md, this repository's mechanism index: the
// tables, modules, components, workers, packages, clients and shared
// dependencies that already exist here, so an agent extends the closest one
// instead of adding a parallel implementation (olympus-control-plane
// docs/specs/shared-capability-doctrine.spec.md, interface I6). The index is
// pure over the tree — no timestamps, code-unit sorted output, the file list
// taken from git (tracked plus untracked-but-not-ignored) — so it is
// reproducible in CI. The pr-metadata gate runs `--check --tree <ref>` against
// the pull-request head as git data; `--write` regenerates it locally.
//
//   node scripts/ci/mechanism-index.mjs --write            # regenerate docs/agent/mechanisms.md
//   node scripts/ci/mechanism-index.mjs --check            # exit 1 when the committed index drifts
//   node scripts/ci/mechanism-index.mjs --print            # print the index to stdout
//   node scripts/ci/mechanism-index.mjs --check --tree <ref> [--allow-missing]
//
// Exit codes: 0 ok · 1 drift or missing index · 2 usage or policy error.
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const OUTPUT_PATH = "docs/agent/mechanisms.md";
const POLICY_PATH = ".claude/mechanism-policy.json";
const MAX_LIST = 400;
const USAGE_EXIT = 2;

// Files that carry DDL: every SQL file, plus migration/schema/store sources in
// Go and JavaScript that embed their CREATE TABLE statements.
const DDL_FILE = /(^|\/)(migrations?|schema|store)[^/]*\.(sql|go|ts|js|mjs)$/i;
const CREATE_TABLE =
  /\bCREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:["'`]?[A-Za-z0-9_]+["'`]?\.)?["'`]?[A-Za-z0-9_]+["'`]?)/gi;
// Engine-internal and migration-bookkeeping tables are never mechanisms.
const INTERNAL_TABLE = /^(__new_|_cf_|sqlite_|d1_migrations$)/;
// Top-level directories of a Go module that are never packages to extend.
const GO_TOP_LEVEL_EXCLUDE = new Set([
  "cmd",
  "vendor",
  "testdata",
  "docs",
  "scripts",
  "packaging",
]);

// Code-unit order: the generated artefact must not depend on the machine's locale.
const byCodeUnit = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

class UsageError extends Error {}

function parseArguments(argv) {
  const options = {
    mode: null,
    root: process.cwd(),
    tree: null,
    policy: null,
    allowMissing: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--write" || arg === "--check" || arg === "--print") {
      if (options.mode && options.mode !== arg.slice(2))
        return { error: "choose one of --write, --check, --print" };
      options.mode = arg.slice(2);
    } else if (arg === "--allow-missing") {
      options.allowMissing = true;
    } else if (arg === "--root" || arg === "--tree" || arg === "--policy") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--"))
        return { error: `${arg} requires a value` };
      options[arg.slice(2)] = value;
      index += 1;
    } else {
      return { error: `unknown argument: ${arg}` };
    }
  }
  if (!options.mode)
    return { error: "one of --write, --check, --print is required" };
  if (options.mode === "write" && options.tree)
    return { error: "--write cannot target a git tree" };
  options.root = resolve(options.root);
  return { options };
}

function loadPolicy(root, policyPath) {
  const path = policyPath ? resolve(root, policyPath) : join(root, POLICY_PATH);
  if (!fs.existsSync(path)) {
    throw new UsageError(
      `mechanism policy missing at ${path}; the platform conventions sync propagates it`,
    );
  }
  const parsed = JSON.parse(fs.readFileSync(path, "utf8"));
  if (!parsed || !Array.isArray(parsed.kinds))
    throw new UsageError(`mechanism policy at ${path} is malformed`);
  return parsed;
}

// A policy excludeDirs entry with a leading "/" is anchored at the repository
// root (docs/, scripts/ci/); every other entry matches that directory segment
// anywhere in the tree (node_modules/, dist/, vendor/, ...).
function excludedDir(relDir, policy) {
  if (relDir === ".git" || relDir.endsWith("/.git")) return true;
  const value = `${relDir}/`;
  for (const dir of policy.excludeDirs ?? []) {
    if (dir.startsWith("/")) {
      if (value.startsWith(dir.slice(1))) return true;
    } else if (value === dir || value.endsWith(`/${dir}`)) {
      return true;
    }
  }
  return false;
}

function excludedFile(rel, policy) {
  return (policy.excludeFiles ?? []).some((pattern) =>
    new RegExp(pattern).test(rel),
  );
}

function excludedPath(rel, policy) {
  const segments = rel.split("/");
  for (let depth = 1; depth < segments.length; depth += 1) {
    if (excludedDir(segments.slice(0, depth).join("/"), policy)) return true;
  }
  return excludedFile(rel, policy);
}

function gitOutput(root, args) {
  return execFileSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

// The working-tree file list comes from git — tracked files plus untracked
// files that .gitignore does not exclude — so `--write` and `--check` see the
// same set the pull-request gate reads from the tree, and filenames carry the
// form git stores rather than the filesystem's normalization. Only when git
// is unavailable (not a repository) does the walk below stand in.
function gitListedFiles(root) {
  try {
    return gitOutput(root, [
      "ls-files",
      "-z",
      "--cached",
      "--others",
      "--exclude-standard",
    ])
      .split("\0")
      .filter(Boolean);
  } catch {
    return null;
  }
}

function isRegularFile(path) {
  try {
    return fs.statSync(path).isFile();
  } catch {
    return false;
  }
}

function walkedFiles(root, policy) {
  const files = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(join(root, dir), { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const rel = dir ? `${dir}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (!excludedDir(rel, policy)) walk(rel);
        continue;
      }
      if (!entry.isFile() && !entry.isSymbolicLink()) continue;
      if (entry.isSymbolicLink() && !isRegularFile(join(root, rel))) continue;
      if (!excludedFile(rel, policy)) files.push(rel);
    }
  };
  walk("");
  return files;
}

function filesystemSource(root, policy) {
  const listed = gitListedFiles(root);
  const files = listed
    ? [...new Set(listed)].filter(
        (rel) => !excludedPath(rel, policy) && isRegularFile(join(root, rel)),
      )
    : walkedFiles(root, policy);
  return {
    files: files.sort(byCodeUnit),
    read: (rel) => fs.readFileSync(join(root, rel), "utf8"),
    exists: (rel) => fs.existsSync(join(root, rel)),
  };
}

function gitTreeSource(root, ref, policy) {
  let listed;
  try {
    listed = gitOutput(root, ["ls-tree", "-r", "--name-only", "-z", ref])
      .split("\0")
      .filter(Boolean);
  } catch {
    throw new UsageError(
      `git tree ${ref} could not be read in ${root}; pass a valid --tree ref`,
    );
  }
  const files = listed
    .filter((rel) => !excludedPath(rel, policy))
    .sort(byCodeUnit);
  const known = new Set(listed);
  return {
    files,
    read: (rel) => gitOutput(root, ["show", `${ref}:${rel}`]),
    exists: (rel) => known.has(rel),
  };
}

function patterns(policy, kind) {
  return (policy.kinds ?? [])
    .filter((entry) => entry.kind === kind)
    .flatMap((entry) => entry.added ?? [])
    .map((pattern) => new RegExp(pattern));
}

function matches(rel, regexes) {
  return regexes.some((regex) => regex.test(rel));
}

function safeRead(source, rel) {
  try {
    return source.read(rel);
  } catch {
    return "";
  }
}

// SQL comments never define tables: drop `/* */` blocks and `--` line comments
// before matching, and `//` line comments in the Go/JavaScript sources that
// embed their DDL.
function stripComments(text, rel) {
  let out = text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, "");
  if (/\.(go|ts|js|mjs)$/i.test(rel))
    out = out.replace(/(^|\s)\/\/[^\n]*/g, "$1");
  return out;
}

function tables(source, policy) {
  const migration = patterns(policy, "migration");
  const found = new Map();
  for (const rel of source.files) {
    if (!(/\.sql$/i.test(rel) || DDL_FILE.test(rel) || matches(rel, migration)))
      continue;
    const text = stripComments(safeRead(source, rel), rel);
    for (const match of text.matchAll(CREATE_TABLE)) {
      const name = match[1].replace(/["'`]/g, "");
      const bare = name.slice(name.lastIndexOf(".") + 1);
      if (!bare || INTERNAL_TABLE.test(bare)) continue;
      if (!found.has(name)) found.set(name, new Set());
      found.get(name).add(rel);
    }
  }
  const isMigration = (rel) => matches(rel, migration);
  return [...found.entries()]
    .sort(([a], [b]) => byCodeUnit(a, b))
    .map(([name, paths]) => {
      // Every defining file is listed; migration files first, so a live
      // migration is never hidden behind an archived schema dump.
      const ordered = [...paths]
        .sort(byCodeUnit)
        .sort((a, b) => Number(isMigration(b)) - Number(isMigration(a)));
      return `\`${name}\` — defined in ${ordered.map((rel) => `\`${rel}\``).join(", ")}`;
    });
}

function modules(source, policy) {
  const roots = [
    ...new Set(
      (policy.kinds ?? []).flatMap((entry) => entry.newDirUnder ?? []),
    ),
  ];
  const found = new Set();
  for (const rel of source.files) {
    for (const root of roots) {
      if (!rel.startsWith(root)) continue;
      const rest = rel.slice(root.length);
      const slash = rest.indexOf("/");
      if (slash === -1) continue;
      found.add(`${root}${rest.slice(0, slash)}`);
    }
  }
  // A Go module: every top-level directory holding Go sources is a package
  // tree to extend, unless it is a policy root whose children are listed.
  if (source.exists("go.mod")) {
    for (const rel of source.files) {
      if (!/\.go$/i.test(rel)) continue;
      const slash = rel.indexOf("/");
      if (slash === -1) continue;
      const top = rel.slice(0, slash);
      if (GO_TOP_LEVEL_EXCLUDE.has(top) || roots.includes(`${top}/`)) continue;
      found.add(top);
    }
  }
  return [...found].sort(byCodeUnit).map((dir) => `\`${dir}\``);
}

function listing(source, policy, kind) {
  const regexes = patterns(policy, kind);
  return source.files
    .filter((rel) => matches(rel, regexes))
    .map((rel) => `\`${rel}\``);
}

function workers(source, policy) {
  const regexes = patterns(policy, "worker");
  const entries = [];
  for (const rel of source.files) {
    if (!matches(rel, regexes)) continue;
    let name = null;
    if (/wrangler[^/]*\.(toml|jsonc?)$/.test(rel)) {
      const text = safeRead(source, rel);
      const toml = text.match(/^\s*name\s*=\s*["']([^"']+)["']/m);
      const json = text.match(/"name"\s*:\s*"([^"]+)"/);
      name = toml?.[1] ?? json?.[1] ?? null;
    }
    entries.push(name ? `\`${rel}\` — worker \`${name}\`` : `\`${rel}\``);
  }
  return entries;
}

function packages(source) {
  const entries = [];
  for (const rel of source.files) {
    if (/^packages\/[^/]+\/package\.json$/.test(rel)) {
      let name = null;
      try {
        name = JSON.parse(safeRead(source, rel)).name ?? null;
      } catch {
        name = null;
      }
      entries.push(name ? `\`${name}\` — \`${rel}\`` : `\`${rel}\``);
    } else if (/(^|\/)go\.mod$/.test(rel)) {
      const module =
        safeRead(source, rel).match(/^module\s+(\S+)/m)?.[1] ?? null;
      entries.push(module ? `\`${module}\` — \`${rel}\`` : `\`${rel}\``);
    }
  }
  return entries;
}

function sharedDependencies(source) {
  const entries = new Map();
  for (const rel of source.files) {
    if (/(^|\/)package\.json$/.test(rel)) {
      let manifest;
      try {
        manifest = JSON.parse(safeRead(source, rel));
      } catch {
        continue;
      }
      for (const field of [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
      ]) {
        for (const [name, version] of Object.entries(manifest?.[field] ?? {})) {
          if (!name.startsWith("@growth-labs/")) continue;
          const key = `${name} ${version}`;
          entries.set(key, [...(entries.get(key) ?? []), rel]);
        }
      }
    } else if (/(^|\/)go\.mod$/.test(rel)) {
      for (const match of safeRead(source, rel).matchAll(
        /^\s*(github\.com\/growth-labs\/packages-go\/\S+)\s+(\S+)/gm,
      )) {
        const key = `${match[1]} ${match[2]}`;
        entries.set(key, [...(entries.get(key) ?? []), rel]);
      }
    }
  }
  return [...entries.entries()]
    .sort(([a], [b]) => byCodeUnit(a, b))
    .map(([key, files]) => {
      const [name, version] = key.split(" ");
      return `\`${name}\` ${version} — ${[...new Set(files)]
        .sort(byCodeUnit)
        .map((file) => `\`${file}\``)
        .join(", ")}`;
    });
}

function section(title, items) {
  const lines = [`## ${title} (${items.length})`, ""];
  if (items.length === 0) {
    lines.push("- none");
  } else {
    for (const item of items.slice(0, MAX_LIST)) lines.push(`- ${item}`);
    if (items.length > MAX_LIST)
      lines.push(
        `- … ${items.length - MAX_LIST} more (listing capped at ${MAX_LIST})`,
      );
  }
  lines.push("");
  return lines;
}

export function renderMechanismIndex(source, policy) {
  const lines = [
    "# Mechanism index",
    "",
    "Generated by `scripts/ci/mechanism-index.mjs` from this repository's tree; do not edit by hand. Regenerate with `node scripts/ci/mechanism-index.mjs --write`; the pr-metadata check runs `--check` against every pull request and fails on drift. Read this before adding a table, module, component, worker, package or client, and extend the closest existing mechanism — see `.claude/rules/shared-capabilities.md` and the estate index `docs/agent/shared-capabilities.md`.",
    "",
    `Policy version: ${policy.version ?? "unknown"}`,
    "",
    ...section("Tables", tables(source, policy)),
    ...section("Modules", modules(source, policy)),
    ...section("Components", listing(source, policy, "component")),
    ...section("Workers", workers(source, policy)),
    ...section("Packages", packages(source)),
    ...section("Clients and adapters", listing(source, policy, "client")),
    ...section("Schemas", listing(source, policy, "schema")),
    ...section("Shared dependencies", sharedDependencies(source)),
  ];
  return `${lines.join("\n").trimEnd()}\n`;
}

function main(argv) {
  const parsed = parseArguments(argv);
  if (parsed.error) {
    console.error(`mechanism-index: ${parsed.error}`);
    return USAGE_EXIT;
  }
  const { options } = parsed;
  let policy;
  let source;
  try {
    policy = loadPolicy(options.root, options.policy);
    source = options.tree
      ? gitTreeSource(options.root, options.tree, policy)
      : filesystemSource(options.root, policy);
  } catch (error) {
    console.error(
      `mechanism-index: ${error instanceof Error ? error.message : String(error)}`,
    );
    return USAGE_EXIT;
  }
  const rendered = renderMechanismIndex(source, policy);

  if (options.mode === "print") {
    process.stdout.write(rendered);
    return 0;
  }
  if (options.mode === "write") {
    const target = join(options.root, OUTPUT_PATH);
    fs.mkdirSync(dirname(target), { recursive: true });
    fs.writeFileSync(target, rendered);
    console.log(
      `mechanism-index: wrote ${OUTPUT_PATH} (${source.files.length} files scanned)`,
    );
    return 0;
  }
  if (!source.exists(OUTPUT_PATH)) {
    if (options.allowMissing) {
      console.log(
        `mechanism-index: ${OUTPUT_PATH} is not generated yet; run \`node scripts/ci/mechanism-index.mjs --write\` and commit it`,
      );
      return 0;
    }
    console.error(
      `mechanism-index: ${OUTPUT_PATH} is missing; run \`node scripts/ci/mechanism-index.mjs --write\` and commit it`,
    );
    return 1;
  }
  const committed = safeRead(source, OUTPUT_PATH);
  if (committed === rendered) {
    console.log(`mechanism-index: ${OUTPUT_PATH} is current`);
    return 0;
  }
  console.error(
    `mechanism-index: ${OUTPUT_PATH} drifted from the tree; run \`node scripts/ci/mechanism-index.mjs --write\` and commit the result`,
  );
  return 1;
}

// Runs main only when this file is the entry script: compare real paths so a
// symlinked or percent-containing invocation path still counts.
function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(fs.realpathSync(entry)).href;
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  // `process.exitCode` rather than `process.exit()`: biome's recommended
  // noProcessExit rule flags the latter, and this file is propagated into
  // consumer repositories that run biome over it and are told not to edit it.
  // A generated artifact that trips a recommended rule in its consumer is an
  // upstream defect. Setting exitCode preserves the exit status and lets the
  // process end naturally once stdout has flushed.
  process.exitCode = main(process.argv.slice(2));
}
