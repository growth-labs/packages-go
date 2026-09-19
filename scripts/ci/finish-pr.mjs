#!/usr/bin/env node
import { isAbsolute } from "node:path";
import { completePullRequest } from "./pr-completion.mjs";

const INPUT_FAILURE_EXIT_CODE = 2;

function inputFailure(error) {
  return {
    ok: false,
    exitCode: INPUT_FAILURE_EXIT_CODE,
    stage: "input",
    error,
    evidence: { argv: process.argv.slice(2) },
  };
}

function parseArguments(argv) {
  const values = {
    prNumber: null,
    headBranch: null,
    ownedWorktrees: [],
    ownedBranches: [],
    verifyOnly: false,
    allowLinkedControlWorktree: false,
  };

  for (let index = 0; index < argv.length; ) {
    const flag = argv[index];
    if (flag === "--verify-only") {
      if (values.verifyOnly)
        throw new Error("--verify-only may be supplied at most once.");
      values.verifyOnly = true;
      index += 1;
      continue;
    }
    if (flag === "--allow-linked-control") {
      if (values.allowLinkedControlWorktree) {
        throw new Error("--allow-linked-control may be supplied at most once.");
      }
      values.allowLinkedControlWorktree = true;
      index += 1;
      continue;
    }
    const value = argv[index + 1];
    if (!["--pr", "--head", "--worktree", "--branch"].includes(flag)) {
      throw new Error(`Unknown argument: ${flag ?? "<missing>"}`);
    }
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.startsWith("--")
    ) {
      throw new Error(`Missing value for ${flag}.`);
    }

    if (flag === "--pr") {
      if (values.prNumber !== null || !/^[1-9]\d*$/.test(value)) {
        throw new Error("--pr must be supplied once as a positive integer.");
      }
      values.prNumber = Number(value);
    } else if (flag === "--head") {
      if (values.headBranch !== null || value.startsWith("-")) {
        throw new Error(
          "--head must be supplied once as an exact branch name.",
        );
      }
      values.headBranch = value;
    } else if (flag === "--worktree") {
      if (!isAbsolute(value)) {
        throw new Error("--worktree ownership paths must be absolute.");
      }
      values.ownedWorktrees.push(value);
    } else {
      if (value.startsWith("-") || value.startsWith("refs/")) {
        throw new Error(
          "--branch must be an exact local branch name, not a ref or option.",
        );
      }
      values.ownedBranches.push(value);
    }
    index += 2;
  }

  if (
    values.prNumber === null ||
    values.headBranch === null ||
    values.ownedWorktrees.length === 0
  ) {
    throw new Error(
      "Required inputs: --pr, --head, and at least one absolute --worktree.",
    );
  }
  return values;
}

async function main() {
  let inputs;
  try {
    inputs = parseArguments(process.argv.slice(2));
  } catch (error) {
    const result = inputFailure(
      error instanceof Error ? error.message : String(error),
    );
    process.stderr.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.exitCode;
    return;
  }

  const result = await completePullRequest({
    cwd: process.cwd(),
    ...inputs,
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.exitCode;
}

main().catch((error) => {
  const result = inputFailure(
    error instanceof Error ? error.message : String(error),
  );
  process.stderr.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.exitCode;
});
