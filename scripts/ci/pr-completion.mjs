import { spawnSync } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";

const FAILURE_EXIT_CODE = 2;
const REF_SNAPSHOT_ARGS = [
  "for-each-ref",
  "--format=%(refname)%00%(objectname)",
  "refs/heads",
];
const PRUNE_PREFLIGHT_ARGS = ["worktree", "prune", "--dry-run", "--verbose"];
const COMMAND_TIMEOUT_MS = 20_000;

/**
 * `git worktree remove` deletes the working tree file by file, so its runtime
 * scales with the checkout — not with how long a query takes. The shared 20s
 * budget is right for `rev-parse` and `ls-remote`; it is not enough to delete a
 * multi-thousand-file worktree.
 *
 * When it timed out on the-foundry PR #1534, git had already removed part of
 * the tree. The retry then saw ~1,100 tracked files marked deleted, correctly
 * classified the worktree as dirty, and refused to touch it — stranding the
 * cleanup and, via the campaign rule layered on top, the whole merge queue.
 */
const WORKTREE_REMOVE_TIMEOUT_MS = 300_000;
const COMMAND_MAX_BUFFER_BYTES = 1024 * 1024;

/**
 * @typedef {Object} CommandResult
 * @property {number} exitCode
 * @property {string} stdout
 * @property {string} stderr
 */

/**
 * @typedef {(command: string, args: string[], options: {cwd: string, timeout: number}) =>
 *   CommandResult | Promise<CommandResult>} CommandRunner
 */

/**
 * @param {string} command
 * @param {string[]} args
 * @param {{cwd: string, timeout?: number}} options
 * @returns {CommandResult}
 */
export function runCommand(command, args, options) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: options.timeout ?? COMMAND_TIMEOUT_MS,
    killSignal: "SIGTERM",
    maxBuffer: COMMAND_MAX_BUFFER_BYTES,
  });

  return {
    exitCode: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr || result.error?.message || "",
  };
}

/**
 * @param {string} stage
 * @param {string} error
 * @param {unknown} evidence
 */
function failure(stage, error, evidence) {
  return {
    ok: false,
    exitCode: FAILURE_EXIT_CODE,
    stage,
    error,
    evidence,
  };
}

/**
 * @param {CommandRunner} runner
 * @param {string} command
 * @param {string[]} args
 * @param {string} cwd
 * @returns {Promise<CommandResult>}
 */
/**
 * Finish a worktree removal that a previous attempt left half-done.
 *
 * Reached ONLY after this run has already proven the exact GitHub merge, the
 * absent remote branch, and the owned head — so the sole question left is
 * whether the mess on disk is an interrupted delete or real work.
 *
 * A partially removed worktree has one unmistakable signature: every porcelain
 * entry is a DELETION. Nothing else can appear, because the only actor was git
 * removing tracked files. A modification, an addition, an untracked file, a
 * rename or an unmerged path all mean a human or agent touched this tree, and
 * the normal dirty-worktree protection must still refuse it — that protection
 * is what saved the #1534 worktree's contents in the first place.
 *
 * @returns {Promise<{resumed: boolean, reason?: string}>}
 */
async function resumePartialWorktreeRemoval(runner, root, path) {
  if (!existsSync(path)) {
    // The delete actually finished; only the admin record is left. `prune`
    // below reconciles it, and forcing anything here would be pointless.
    return { resumed: true };
  }

  const status = await execute(
    runner,
    "git",
    ["-C", path, "status", "--porcelain=v1", "-z", "--untracked-files=all"],
    root,
  );
  if (status.exitCode !== 0)
    return { resumed: false, reason: "status-unreadable" };

  const entries = status.stdout.split("\0").filter((entry) => entry !== "");
  if (entries.length === 0)
    return {
      resumed: false,
      reason: "clean-tree-removal-failed-for-another-reason",
    };

  for (const entry of entries) {
    const code = entry.slice(0, 2);
    // Deletions only: ' D' (unstaged) or 'D ' (staged). Anything else is work.
    if (code !== " D" && code !== "D ") {
      return {
        resumed: false,
        reason: `non-deletion-change:${code.trim() || code}`,
      };
    }
  }

  const forced = await execute(
    runner,
    "git",
    ["worktree", "remove", "--force", "--", path],
    root,
    WORKTREE_REMOVE_TIMEOUT_MS,
  );
  if (forced.exitCode !== 0)
    return { resumed: false, reason: "forced-remove-failed" };
  return { resumed: true };
}

async function execute(
  runner,
  command,
  args,
  cwd,
  timeout = COMMAND_TIMEOUT_MS,
) {
  try {
    const result = await runner(command, args, { cwd, timeout });
    if (
      !result ||
      !Number.isInteger(result.exitCode) ||
      typeof result.stdout !== "string" ||
      typeof result.stderr !== "string"
    ) {
      return {
        exitCode: 1,
        stdout: "",
        stderr: "Command runner returned an invalid result.",
      };
    }
    return result;
  } catch (error) {
    return {
      exitCode: 1,
      stdout: "",
      stderr: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * @param {string} stdout
 */
function parseWorktreeList(stdout) {
  if (stdout.trim() === "") return [];

  return stdout
    .trimEnd()
    .split(/\n\n+/)
    .map((raw) => {
      const lines = raw.split("\n");
      const pathLine = lines.find((line) => line.startsWith("worktree "));
      const headLine = lines.find((line) => line.startsWith("HEAD "));
      const branchLine = lines.find((line) =>
        line.startsWith("branch refs/heads/"),
      );
      if (!pathLine || !headLine) {
        throw new Error(`Malformed git worktree record: ${raw}`);
      }

      const listedPath = pathLine.slice("worktree ".length);
      let path;
      try {
        path = realpathSync(listedPath);
      } catch {
        path = listedPath;
      }
      return {
        path,
        head: headLine.slice("HEAD ".length),
        branch: branchLine
          ? branchLine.slice("branch refs/heads/".length)
          : null,
        detached: lines.includes("detached"),
        raw,
      };
    });
}

/**
 * @param {string} stdout
 */
function parseLocalRefs(stdout) {
  const refs = new Map();
  for (const line of stdout.trimEnd().split("\n")) {
    if (line === "") continue;
    const separator = line.indexOf("\0");
    const ref = separator >= 0 ? line.slice(0, separator) : "";
    const objectId = separator >= 0 ? line.slice(separator + 1) : "";
    if (
      !ref.startsWith("refs/heads/") ||
      objectId.length === 0 ||
      refs.has(ref)
    ) {
      throw new Error(
        `Malformed local branch ref record: ${JSON.stringify(line)}`,
      );
    }
    refs.set(ref, objectId);
  }
  return refs;
}

/**
 * @param {CommandRunner} runner
 * @param {string} root
 * @param {'before-proof' | 'before-prune'} phase
 */
async function checkPrunePrecondition(runner, root, phase) {
  const result = await execute(runner, "git", PRUNE_PREFLIGHT_ARGS, root);
  if (result.exitCode !== 0) {
    return failure(
      "prune-precondition",
      "Unable to preflight repository worktree pruning.",
      {
        phase,
        ...result,
      },
    );
  }
  if (result.stdout.length > 0 || result.stderr.length > 0) {
    return failure(
      "prune-precondition",
      "Unrelated worktree prune candidates block exact cleanup.",
      {
        phase,
        stdout: result.stdout,
        stderr: result.stderr,
      },
    );
  }
  return null;
}

/**
 * @param {unknown} value
 */
function mergeCommitOid(value) {
  if (typeof value === "string" && value.length > 0) return value;
  if (
    value &&
    typeof value === "object" &&
    "oid" in value &&
    typeof value.oid === "string" &&
    value.oid.length > 0
  ) {
    return value.oid;
  }
  return null;
}

/**
 * @param {unknown} value
 */
function pullRequestHeadOid(value) {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/**
 * @param {string} stdout
 */
function parseJson(stdout) {
  try {
    return { ok: true, value: JSON.parse(stdout) };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function canonicalizeOwnedWorktree(path, verifyOnly) {
  if (!verifyOnly) return realpathSync(path);

  const normalized = resolve(path);
  if (existsSync(normalized)) return realpathSync(normalized);

  // Cleanup removes the owned worktree directory, not its parent. Requiring
  // that parent to remain lets us realpath every existing symlink component
  // and prevents an unresolved/dangling alias from proving a false absence.
  const parent = dirname(normalized);
  if (!existsSync(parent)) {
    throw new Error(
      `Verify-only cannot identify a missing parent directory: ${parent}`,
    );
  }
  return join(realpathSync(parent), basename(normalized));
}

function containsPath(parent, child) {
  const relativePath = relative(parent, child);
  return (
    relativePath === "" ||
    (relativePath !== ".." &&
      !relativePath.startsWith(`..${sep}`) &&
      !isAbsolute(relativePath))
  );
}

/**
 * Remove only explicitly owned linked worktrees and their exact local branches
 * after two matching GitHub merge proofs and clean-worktree validation.
 *
 * @param {Object} options
 * @param {string} options.cwd
 * @param {number} options.prNumber
 * @param {string} options.headBranch
 * @param {string[]} options.ownedWorktrees
 * @param {string[]} options.ownedBranches
 * @param {boolean} [options.verifyOnly]
 * @param {boolean} [options.allowLinkedControlWorktree]
 * @param {CommandRunner} [options.runCommand]
 */
export async function completePullRequest(options) {
  const {
    cwd,
    prNumber,
    headBranch,
    ownedWorktrees,
    ownedBranches,
    verifyOnly = false,
    allowLinkedControlWorktree = false,
    runCommand: runner = runCommand,
  } = options ?? {};

  if (
    typeof cwd !== "string" ||
    !Number.isInteger(prNumber) ||
    prNumber <= 0 ||
    typeof headBranch !== "string" ||
    headBranch.length === 0 ||
    !Array.isArray(ownedWorktrees) ||
    ownedWorktrees.length === 0 ||
    !ownedWorktrees.every(
      (path) => typeof path === "string" && path.length > 0 && isAbsolute(path),
    ) ||
    !Array.isArray(ownedBranches) ||
    !ownedBranches.every(
      (branch) => typeof branch === "string" && branch.length > 0,
    ) ||
    typeof verifyOnly !== "boolean" ||
    typeof allowLinkedControlWorktree !== "boolean" ||
    typeof runner !== "function"
  ) {
    return failure("input", "Invalid PR completion inputs.", {
      cwd,
      prNumber,
      headBranch,
      ownedWorktrees,
      ownedBranches,
      verifyOnly,
      allowLinkedControlWorktree,
    });
  }

  const commonDirectoryResult = await execute(
    runner,
    "git",
    ["rev-parse", "--path-format=absolute", "--git-common-dir"],
    cwd,
  );
  if (commonDirectoryResult.exitCode !== 0) {
    return failure(
      "repository",
      "Unable to resolve the Git common directory.",
      commonDirectoryResult,
    );
  }

  let commonDirectory;
  try {
    commonDirectory = realpathSync(commonDirectoryResult.stdout.trim());
  } catch (error) {
    return failure(
      "repository",
      "The resolved Git common directory is invalid.",
      {
        commonDirectory: commonDirectoryResult.stdout,
        error: error instanceof Error ? error.message : String(error),
      },
    );
  }

  const rootResult = await execute(
    runner,
    "git",
    ["rev-parse", "--path-format=absolute", "--show-toplevel"],
    cwd,
  );
  if (rootResult.exitCode !== 0) {
    return failure(
      "repository",
      "Unable to resolve the supplied checkout root.",
      rootResult,
    );
  }

  const cwdGitDirectoryResult = await execute(
    runner,
    "git",
    ["rev-parse", "--path-format=absolute", "--absolute-git-dir"],
    cwd,
  );
  if (cwdGitDirectoryResult.exitCode !== 0) {
    return failure(
      "repository",
      "Unable to resolve the supplied checkout Git directory.",
      cwdGitDirectoryResult,
    );
  }

  let root;
  let canonicalCwd;
  let cwdGitDirectory;
  try {
    // Canonicalize the checkout root before every ownership comparison below;
    // callers may supply cwd through a symlink or with redundant path segments.
    root = realpathSync(rootResult.stdout.trim());
    canonicalCwd = realpathSync(cwd);
    cwdGitDirectory = realpathSync(cwdGitDirectoryResult.stdout.trim());
  } catch (error) {
    return failure("repository", "The supplied checkout paths are invalid.", {
      root: rootResult.stdout,
      gitDirectory: cwdGitDirectoryResult.stdout,
      error: error instanceof Error ? error.message : String(error),
    });
  }

  const initialWorktreeResult = await execute(
    runner,
    "git",
    ["worktree", "list", "--porcelain"],
    cwd,
  );
  if (initialWorktreeResult.exitCode !== 0) {
    return failure(
      "repository",
      "Unable to enumerate Git worktrees.",
      initialWorktreeResult,
    );
  }

  let initialWorktrees;
  try {
    initialWorktrees = parseWorktreeList(initialWorktreeResult.stdout);
  } catch (error) {
    return failure(
      "repository",
      "Unable to parse the Git worktree inventory.",
      {
        inventory: initialWorktreeResult.stdout,
        error: error instanceof Error ? error.message : String(error),
      },
    );
  }

  const mainWorktree = initialWorktrees[0];
  if (!mainWorktree) {
    return failure(
      "repository",
      "The Git worktree inventory does not identify a main worktree.",
      {
        worktrees: initialWorktrees,
      },
    );
  }
  // Keep the structured main-worktree guard above every mainWorktree.path use.

  const linkedControlWorktree = cwdGitDirectory !== commonDirectory;
  const controlRecord = initialWorktrees.find(
    (worktree) => worktree.path === root,
  );

  let canonicalOwnedWorktrees;
  try {
    canonicalOwnedWorktrees = ownedWorktrees.map((path) =>
      canonicalizeOwnedWorktree(path, verifyOnly),
    );
  } catch (error) {
    return failure(
      "owned-worktrees",
      "Unable to resolve every exact owned worktree path.",
      {
        ownedWorktrees,
        error: error instanceof Error ? error.message : String(error),
      },
    );
  }

  if (!verifyOnly) {
    const containingWorktree = canonicalOwnedWorktrees.find((path) =>
      containsPath(path, canonicalCwd),
    );
    if (containingWorktree) {
      return failure(
        "owned-worktrees",
        `Refusing to remove ${containingWorktree}: it contains the current working directory. Run finish-pr from the main checkout instead.`,
        { cwd: canonicalCwd, ownedWorktree: containingWorktree },
      );
    }
  }

  if (linkedControlWorktree && !allowLinkedControlWorktree) {
    return failure(
      "repository",
      "The supplied cwd must belong to the main checkout unless --allow-linked-control explicitly selects a clean detached control worktree.",
      {
        root,
        commonDirectory,
        cwdGitDirectory,
        allowLinkedControlWorktree,
      },
    );
  }
  if (
    linkedControlWorktree &&
    (!controlRecord ||
      controlRecord.path === mainWorktree.path ||
      !controlRecord.detached)
  ) {
    return failure(
      "repository",
      "An allowed linked control must be a registered detached worktree in the same common repository.",
      {
        root,
        commonDirectory,
        cwdGitDirectory,
        controlRecord,
        mainWorktree,
      },
    );
  }

  if (
    new Set(canonicalOwnedWorktrees).size !== canonicalOwnedWorktrees.length
  ) {
    return failure("owned-worktrees", "Owned worktree paths must be unique.", {
      ownedWorktrees: canonicalOwnedWorktrees,
    });
  }

  // Both sides are realpath-canonical here: root above and every owned path in
  // canonicalizeOwnedWorktree. Never compare raw argv path spellings.
  if (linkedControlWorktree && canonicalOwnedWorktrees.includes(root)) {
    return failure(
      "owned-worktrees",
      "The linked control worktree must not be listed as an owned worktree.",
      { root, ownedWorktrees: canonicalOwnedWorktrees },
    );
  }

  const initialByPath = new Map(
    initialWorktrees.map((worktree) => [worktree.path, worktree]),
  );
  const invalidOwnedWorktrees = verifyOnly
    ? canonicalOwnedWorktrees.filter(
        (path) =>
          path === root ||
          path === mainWorktree.path ||
          existsSync(path) ||
          initialByPath.has(path),
      )
    : canonicalOwnedWorktrees.filter(
        (path) =>
          path === root ||
          path === mainWorktree.path ||
          !initialByPath.has(path),
      );
  if (invalidOwnedWorktrees.length > 0) {
    return failure(
      "owned-worktrees",
      verifyOnly
        ? "Verify-only requires every exact owned worktree path and registration to be absent."
        : "Owned worktrees must be registered non-root worktrees in the same common repository.",
      { root, verifyOnly, invalidOwnedWorktrees, inventory: initialWorktrees },
    );
  }

  if (new Set(ownedBranches).size !== ownedBranches.length) {
    return failure(
      "owned-branches",
      "Owned local branch names must be unique.",
      { ownedBranches },
    );
  }

  const ownedRecords = verifyOnly
    ? []
    : canonicalOwnedWorktrees.map((path) => initialByPath.get(path));
  if (!verifyOnly) {
    const attachedOwnedBranches = ownedRecords
      .map((worktree) => worktree.branch)
      .filter((branch) => branch !== null);
    const branchesOutsideOwnedWorktrees = ownedBranches.filter(
      (branch) => !attachedOwnedBranches.includes(branch),
    );
    const missingAttachedBranches = attachedOwnedBranches.filter(
      (branch) => !ownedBranches.includes(branch),
    );
    const detachedOwnedWorktrees = ownedRecords
      .filter((worktree) => worktree.detached)
      .map((worktree) => worktree.path);
    if (
      branchesOutsideOwnedWorktrees.length > 0 ||
      missingAttachedBranches.length > 0
    ) {
      return failure(
        "owned-branches",
        detachedOwnedWorktrees.length > 0 &&
          branchesOutsideOwnedWorktrees.length > 0
          ? "An explicit local branch cannot be attributed to a detached worktree. Omit --branch for a branchless detached review worktree, or reattach the exact task branch before cleanup."
          : "Every owned local branch must be attached to an owned worktree, and every attached owned worktree branch must be explicit.",
        {
          branchesOutsideOwnedWorktrees,
          missingAttachedBranches,
          detachedOwnedWorktrees,
          ownedRecords,
        },
      );
    }
  }

  const dirty = [];
  for (const path of verifyOnly ? [root] : [root, ...canonicalOwnedWorktrees]) {
    const statusResult = await execute(
      runner,
      "git",
      ["-C", path, "status", "--porcelain=v1", "--untracked-files=all"],
      root,
    );
    if (statusResult.exitCode !== 0) {
      return failure(
        "dirty-worktrees",
        `Unable to inspect worktree status: ${path}`,
        {
          path,
          result: statusResult,
        },
      );
    }
    if (statusResult.stdout.length > 0) {
      dirty.push({ path, status: statusResult.stdout });
    }
  }

  if (dirty.length > 0) {
    return failure(
      "dirty-worktrees",
      "Root and owned worktrees must have no modified or untracked files before cleanup.",
      { dirty },
    );
  }

  const ownedPathSet = new Set(canonicalOwnedWorktrees);
  const unrelatedSnapshot = initialWorktrees
    .filter((worktree) => !ownedPathSet.has(worktree.path))
    .map((worktree) => ({ path: worktree.path, raw: worktree.raw }));

  const initialRefsResult = await execute(
    runner,
    "git",
    REF_SNAPSHOT_ARGS,
    root,
  );
  if (initialRefsResult.exitCode !== 0) {
    return failure(
      "local-branches",
      "Unable to snapshot local branch refs before cleanup.",
      initialRefsResult,
    );
  }

  let initialRefs;
  try {
    initialRefs = parseLocalRefs(initialRefsResult.stdout);
  } catch (error) {
    return failure(
      "local-branches",
      "Unable to parse local branch refs before cleanup.",
      {
        refs: initialRefsResult.stdout,
        error: error instanceof Error ? error.message : String(error),
      },
    );
  }

  const ownedRefNames = ownedBranches.map((branch) => `refs/heads/${branch}`);
  if (verifyOnly) {
    const remainingOwnedRefs = ownedRefNames.filter((ref) =>
      initialRefs.has(ref),
    );
    if (remainingOwnedRefs.length > 0) {
      return failure(
        "owned-branches",
        "Verify-only requires every exact owned local branch ref to be absent.",
        {
          verifyOnly,
          remainingOwnedRefs,
        },
      );
    }
  } else {
    const missingOwnedRefs = ownedRefNames.filter(
      (ref) => !initialRefs.has(ref),
    );
    if (missingOwnedRefs.length > 0) {
      return failure(
        "owned-branches",
        "Every explicitly owned local branch ref must exist before cleanup.",
        {
          missingOwnedRefs,
        },
      );
    }
  }

  if (!verifyOnly) {
    const beforeProofPruneFailure = await checkPrunePrecondition(
      runner,
      root,
      "before-proof",
    );
    if (beforeProofPruneFailure) return beforeProofPruneFailure;
  }

  const listResult = await execute(
    runner,
    "gh",
    [
      "pr",
      "list",
      "--state",
      "merged",
      "--head",
      headBranch,
      "--json",
      "number,mergedAt,mergeCommit,headRefOid",
    ],
    root,
  );
  if (listResult.exitCode !== 0) {
    return failure(
      "github-evidence",
      "Unable to query merged PRs by exact head branch.",
      listResult,
    );
  }

  const viewResult = await execute(
    runner,
    "gh",
    [
      "pr",
      "view",
      String(prNumber),
      "--json",
      "state,mergedAt,mergeCommit,headRefName,headRefOid",
    ],
    root,
  );
  if (viewResult.exitCode !== 0) {
    return failure(
      "github-evidence",
      "Unable to query the exact PR.",
      viewResult,
    );
  }

  const parsedList = parseJson(listResult.stdout);
  const parsedView = parseJson(viewResult.stdout);
  if (!parsedList.ok || !parsedView.ok) {
    return failure(
      "github-evidence",
      "GitHub merge evidence was not valid JSON.",
      {
        list: parsedList,
        view: parsedView,
      },
    );
  }

  const listEntries = parsedList.value;
  const view = parsedView.value;
  const matchingListEntries = Array.isArray(listEntries)
    ? listEntries.filter((entry) => entry?.number === prNumber)
    : [];
  const listEntry =
    matchingListEntries.length === 1 ? matchingListEntries[0] : null;
  const listCommit = mergeCommitOid(listEntry?.mergeCommit);
  const viewCommit = mergeCommitOid(view?.mergeCommit);
  const listHeadOid = pullRequestHeadOid(listEntry?.headRefOid);
  const viewHeadOid = pullRequestHeadOid(view?.headRefOid);
  const mergedAt =
    typeof listEntry?.mergedAt === "string" && listEntry.mergedAt.length > 0
      ? listEntry.mergedAt
      : null;
  const evidenceMatches =
    listEntry?.number === prNumber &&
    mergedAt !== null &&
    listCommit !== null &&
    view?.state === "MERGED" &&
    view?.mergedAt === mergedAt &&
    viewCommit === listCommit &&
    view?.headRefName === headBranch &&
    listHeadOid !== null &&
    viewHeadOid === listHeadOid;
  if (!evidenceMatches) {
    return failure(
      "github-evidence",
      "The merged PR list and exact PR view do not provide identical merge evidence.",
      { expected: { prNumber, headBranch }, list: listEntries, view },
    );
  }

  if (!verifyOnly) {
    const mismatchedWorktrees = ownedRecords
      .filter((worktree) => worktree.head !== viewHeadOid)
      .map((worktree) => ({
        path: worktree.path,
        actualHeadOid: worktree.head,
      }));
    const mismatchedBranches = ownedBranches
      .map((branch) => ({
        branch,
        actualHeadOid: initialRefs.get(`refs/heads/${branch}`),
      }))
      .filter(({ actualHeadOid }) => actualHeadOid !== viewHeadOid);

    if (mismatchedWorktrees.length > 0 || mismatchedBranches.length > 0) {
      return failure(
        "owned-heads",
        "Every owned worktree and local branch tip must equal the exact GitHub PR head before cleanup.",
        {
          expectedHeadOid: viewHeadOid,
          mismatchedWorktrees,
          mismatchedBranches,
        },
      );
    }
  }

  const remoteResult = await execute(
    runner,
    "git",
    [
      "ls-remote",
      "--exit-code",
      "--heads",
      "origin",
      `refs/heads/${headBranch}`,
    ],
    root,
  );
  if (remoteResult.exitCode !== 2) {
    const error =
      remoteResult.exitCode === 0
        ? "The exact remote PR head branch still exists."
        : "Unable to verify absence of the exact remote PR head branch.";
    return failure("remote-head", error, {
      headBranch,
      ...remoteResult,
    });
  }

  if (!verifyOnly) {
    for (const path of canonicalOwnedWorktrees) {
      const headResult = await execute(
        runner,
        "git",
        ["-C", path, "rev-parse", "--verify", "HEAD"],
        root,
      );
      const actualHeadOid =
        headResult.exitCode === 0 ? headResult.stdout.trim() : null;
      if (actualHeadOid !== viewHeadOid) {
        return failure(
          "owned-heads",
          `The owned worktree moved after proof and was preserved: ${path}`,
          {
            expectedHeadOid: viewHeadOid,
            mismatchedWorktrees: [{ path, actualHeadOid }],
            result: headResult,
            phase: "before-remove",
          },
        );
      }

      const removeResult = await execute(
        runner,
        "git",
        ["worktree", "remove", "--", path],
        root,
        WORKTREE_REMOVE_TIMEOUT_MS,
      );
      if (removeResult.exitCode !== 0) {
        const resumed = await resumePartialWorktreeRemoval(runner, root, path);
        if (!resumed.resumed) {
          return failure(
            "remove-worktree",
            `Unable to remove the exact owned worktree: ${path}`,
            {
              path,
              result: removeResult,
              resumeRefusedBecause: resumed.reason,
            },
          );
        }
      }
    }

    const beforePruneFailure = await checkPrunePrecondition(
      runner,
      root,
      "before-prune",
    );
    if (beforePruneFailure) return beforePruneFailure;

    const pruneResult = await execute(
      runner,
      "git",
      ["worktree", "prune"],
      root,
    );
    if (pruneResult.exitCode !== 0) {
      return failure(
        "prune-worktrees",
        "Unable to prune removed worktree metadata.",
        pruneResult,
      );
    }

    for (const branch of ownedBranches) {
      const branchRef = `refs/heads/${branch}`;
      const deleteResult = await execute(
        runner,
        "git",
        ["update-ref", "-d", branchRef, viewHeadOid],
        root,
      );
      if (deleteResult.exitCode !== 0) {
        return failure(
          "delete-branch",
          `The exact owned local branch moved after proof or could not be deleted: ${branch}`,
          {
            branch,
            branchRef,
            expectedHeadOid: viewHeadOid,
            result: deleteResult,
          },
        );
      }
    }
  }

  const finalWorktreeResult = await execute(
    runner,
    "git",
    ["worktree", "list", "--porcelain"],
    root,
  );
  if (finalWorktreeResult.exitCode !== 0) {
    return failure(
      "postcondition-worktrees",
      "Unable to enumerate final Git worktrees.",
      finalWorktreeResult,
    );
  }

  let finalWorktrees;
  try {
    finalWorktrees = parseWorktreeList(finalWorktreeResult.stdout);
  } catch (error) {
    return failure(
      "postcondition-worktrees",
      "Unable to parse the final Git worktree inventory.",
      {
        inventory: finalWorktreeResult.stdout,
        error: error instanceof Error ? error.message : String(error),
      },
    );
  }

  const finalByPath = new Map(
    finalWorktrees.map((worktree) => [worktree.path, worktree]),
  );
  const remainingOwnedWorktrees = canonicalOwnedWorktrees.filter((path) =>
    finalByPath.has(path),
  );
  const changedUnrelatedWorktrees = unrelatedSnapshot.filter(
    (before) => finalByPath.get(before.path)?.raw !== before.raw,
  );
  const unexpectedWorktrees = finalWorktrees.filter(
    (worktree) =>
      !unrelatedSnapshot.some((before) => before.path === worktree.path),
  );
  if (
    remainingOwnedWorktrees.length > 0 ||
    changedUnrelatedWorktrees.length > 0 ||
    unexpectedWorktrees.length > 0
  ) {
    return failure(
      "postcondition-worktrees",
      "Final worktree inventory did not match exact cleanup ownership.",
      {
        remainingOwnedWorktrees,
        changedUnrelatedWorktrees,
        unexpectedWorktrees,
        before: unrelatedSnapshot,
        after: finalWorktrees,
      },
    );
  }

  const finalRefsResult = await execute(runner, "git", REF_SNAPSHOT_ARGS, root);
  if (finalRefsResult.exitCode !== 0) {
    return failure(
      "postcondition-branches",
      "Unable to snapshot local branch refs after cleanup.",
      finalRefsResult,
    );
  }

  let finalRefs;
  try {
    finalRefs = parseLocalRefs(finalRefsResult.stdout);
  } catch (error) {
    return failure(
      "postcondition-branches",
      "Unable to parse local branch refs after cleanup.",
      {
        refs: finalRefsResult.stdout,
        error: error instanceof Error ? error.message : String(error),
      },
    );
  }

  const remainingOwnedBranches = [];
  for (const branch of ownedBranches) {
    const branchResult = await execute(
      runner,
      "git",
      ["branch", "--list", branch, "--format=%(refname:short)"],
      root,
    );
    if (branchResult.exitCode !== 0) {
      return failure(
        "postcondition-branches",
        `Unable to verify the exact local branch: ${branch}`,
        {
          branch,
          result: branchResult,
        },
      );
    }
    if (branchResult.stdout.trim().length > 0) {
      remainingOwnedBranches.push({ branch, output: branchResult.stdout });
    }
  }

  const ownedRefSet = new Set(ownedRefNames);
  const expectedUnrelatedRefs = new Map(
    [...initialRefs].filter(([ref]) => !ownedRefSet.has(ref)),
  );
  const added = [...finalRefs]
    .filter(([ref]) => !ownedRefSet.has(ref) && !expectedUnrelatedRefs.has(ref))
    .map(([ref, objectId]) => ({ ref, objectId }));
  const deleted = [...expectedUnrelatedRefs]
    .filter(([ref]) => !finalRefs.has(ref))
    .map(([ref, objectId]) => ({ ref, objectId }));
  const moved = [...expectedUnrelatedRefs]
    .filter(
      ([ref, objectId]) =>
        finalRefs.has(ref) && finalRefs.get(ref) !== objectId,
    )
    .map(([ref, before]) => ({ ref, before, after: finalRefs.get(ref) }));
  const remainingOwnedRefs = ownedRefNames
    .filter((ref) => finalRefs.has(ref))
    .map((ref) => ({ ref, objectId: finalRefs.get(ref) }));

  if (
    remainingOwnedBranches.length > 0 ||
    remainingOwnedRefs.length > 0 ||
    added.length > 0 ||
    deleted.length > 0 ||
    moved.length > 0
  ) {
    return failure(
      "postcondition-branches",
      "Final local branch refs did not match exact cleanup ownership.",
      {
        remainingOwnedBranches,
        remainingOwnedRefs,
        added,
        deleted,
        moved,
      },
    );
  }

  return {
    ok: true,
    exitCode: 0,
    mergeEvidence: {
      prNumber,
      headBranch,
      headRefOid: viewHeadOid,
      mergedAt,
      mergeCommit: listCommit,
    },
    cleanup: verifyOnly
      ? {
          confirmedAbsentWorktrees: canonicalOwnedWorktrees,
          confirmedAbsentBranches: [...ownedBranches],
          remoteHeadAbsent: true,
          verifyOnly: true,
        }
      : {
          removedWorktrees: canonicalOwnedWorktrees,
          removedBranches: [...ownedBranches],
          remoteHeadAbsent: true,
        },
  };
}
