/**
 * Safe git execution.
 *
 * - Every git command is run with `execFile` and an argument array: no shell,
 *   so branch names, URLs and paths are never interpreted by a shell.
 * - Errors are rebuilt with redacted messages so tokens and credential-bearing
 *   URLs never reach logs, events or callers.
 * - Credentials are supplied per command through an ephemeral credential
 *   helper that lives in a private temp directory outside the workspace and is
 *   passed with top-level `git -c` options, which git never persists.
 */

import { execFile } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  assertSafeToken,
  isDangerousRepoConfigKey,
  redactSecrets,
  shellQuote,
} from './git-security';

/**
 * Error thrown when a git command fails. `message` and `stderr` are redacted.
 */
export class GitCommandError extends Error {
  readonly exitCode: number | null;
  readonly stderr: string;
  /** The git subcommand that failed (e.g. `clone`, `push`) */
  readonly subcommand: string;

  constructor(
    subcommand: string,
    exitCode: number | null,
    stderr: string,
    message: string
  ) {
    super(message);
    this.name = 'GitCommandError';
    this.subcommand = subcommand;
    this.exitCode = exitCode;
    this.stderr = stderr;
  }
}

export interface RunGitOptions {
  cwd: string;
  /** Extra environment variables for this command */
  env?: Record<string, string>;
  /** Values that must be redacted from any error output */
  secrets?: ReadonlyArray<string | undefined>;
  /** Timeout in milliseconds (default: none) */
  timeoutMs?: number;
}

export interface RunGitResult {
  stdout: string;
  stderr: string;
}

const MAX_BUFFER = 64 * 1024 * 1024;
const MAX_ERROR_STDERR = 4000;

/**
 * Find the git subcommand in an argument list (skipping leading `-c k=v`).
 */
function findSubcommand(args: readonly string[]): string {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '-c' || a === '-C') {
      i++;
      continue;
    }
    if (!a.startsWith('-')) return a;
  }
  return 'git';
}

/**
 * Run git with an argument array (never through a shell).
 */
export function runGit(
  args: readonly string[],
  options: RunGitOptions
): Promise<RunGitResult> {
  const secrets = options.secrets ?? [];
  return new Promise((resolve, reject) => {
    execFile(
      'git',
      args as string[],
      {
        cwd: options.cwd,
        env: {
          ...process.env,
          // Never block on an interactive username/password prompt
          GIT_TERMINAL_PROMPT: '0',
          ...options.env,
        },
        maxBuffer: MAX_BUFFER,
        timeout: options.timeoutMs,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        const out = String(stdout ?? '');
        const err = String(stderr ?? '');
        if (!error) {
          resolve({ stdout: out, stderr: err });
          return;
        }
        const subcommand = findSubcommand(args);
        const code =
          typeof (error as NodeJS.ErrnoException).code === 'number'
            ? ((error as unknown as { code: number }).code as number)
            : null;
        const safeStderr = redactSecrets(err, secrets).trim();
        const detail =
          safeStderr.length > 0
            ? safeStderr.slice(0, MAX_ERROR_STDERR)
            : redactSecrets(error.message, secrets);
        reject(
          new GitCommandError(
            subcommand,
            code,
            safeStderr,
            `git ${subcommand} failed${code !== null ? ` (exit ${code})` : ''}: ${detail}`
          )
        );
      }
    );
  });
}

/**
 * `-c` options applied to every command the service runs inside an existing
 * (possibly agent-modified) repository while a credential is available:
 * hooks and fsmonitor are disabled so no repository-controlled code runs while
 * the credential helper is reachable.
 */
export function hardeningConfigArgs(): string[] {
  return ['-c', `core.hooksPath=${os.devNull}`, '-c', 'core.fsmonitor=false'];
}

export interface EphemeralCredentialHelper {
  /** Private directory holding the helper script and token file */
  readonly dir: string;
  /** Top-level git `-c` arguments that enable the helper for one command */
  readonly configArgs: string[];
  /** Remove the helper directory. Safe to call more than once. */
  dispose(): Promise<void>;
}

export interface EphemeralCredentialHelperOptions {
  token: string;
  /** Host (with optional `:port`) the token may be sent to */
  host: string;
  /** Username to present (default `x-access-token`) */
  username?: string;
  /** Parent directory for the private temp dir (default `os.tmpdir()`) */
  parentDir?: string;
}

/**
 * Create a single-use credential helper outside the workspace.
 *
 * Layout (directory is mode 0700, created with mkdtemp):
 *   <parentDir>/gws-cred-XXXXXX/token    mode 0600, the raw token
 *   <parentDir>/gws-cred-XXXXXX/helper   mode 0700, POSIX sh script
 *
 * The helper only answers `get` requests for `protocol=https` and the exact
 * expected host, so a rewritten URL (`url.*.insteadOf`) or redirect to another
 * host never receives the token. `store`/`erase` are ignored.
 *
 * The returned `configArgs` first reset `credential.helper` to an empty list,
 * which discards any helper configured in system/global/repository config, so
 * no other helper sees (or stores) the token, then add this one.
 */
export async function createEphemeralCredentialHelper(
  options: EphemeralCredentialHelperOptions
): Promise<EphemeralCredentialHelper> {
  assertSafeToken(options.token);
  const username = options.username ?? 'x-access-token';
  if (!/^[A-Za-z0-9._-]+$/.test(username)) {
    throw new Error('Invalid credential username');
  }
  if (!/^[a-z0-9.-]+(:[0-9]{1,5})?$/.test(options.host)) {
    throw new Error('Invalid credential host');
  }

  const parentDir = options.parentDir ?? os.tmpdir();
  await fs.mkdir(parentDir, { recursive: true });
  const dir = await fs.mkdtemp(path.join(parentDir, 'gws-cred-'));
  let disposed = false;
  const dispose = async () => {
    if (disposed) return;
    disposed = true;
    await fs.rm(dir, { recursive: true, force: true });
  };

  try {
    await fs.chmod(dir, 0o700);
    const tokenPath = path.join(dir, 'token');
    const helperPath = path.join(dir, 'helper');

    await fs.writeFile(tokenPath, options.token, { mode: 0o600, flag: 'wx' });

    const script = [
      '#!/bin/sh',
      '# git-workspace-service: single-use credential helper (deleted after use)',
      '[ "$1" = "get" ] || exit 0',
      'proto=',
      'host=',
      'while IFS= read -r line; do',
      '  [ -z "$line" ] && break',
      '  case "$line" in',
      // biome-ignore lint/suspicious/noTemplateCurlyInString: shell parameter expansion
      '    protocol=*) proto=${line#protocol=} ;;',
      // biome-ignore lint/suspicious/noTemplateCurlyInString: shell parameter expansion
      '    host=*) host=${line#host=} ;;',
      '  esac',
      'done',
      `[ "$proto" = "https" ] && [ "$host" = ${shellQuote(options.host)} ] || exit 0`,
      `printf 'username=%s\\n' ${shellQuote(username)}`,
      `printf 'password=%s\\n' "$(cat ${shellQuote(tokenPath)})"`,
      '',
    ].join('\n');
    await fs.writeFile(helperPath, script, { mode: 0o700, flag: 'wx' });

    return {
      dir,
      configArgs: [
        '-c',
        'credential.helper=',
        '-c',
        `credential.helper=!${shellQuote(helperPath)}`,
        '-c',
        'credential.useHttpPath=false',
      ],
      dispose,
    };
  } catch (error) {
    await dispose().catch(() => undefined);
    throw error;
  }
}

/**
 * Read the repository-scoped (local and worktree) config keys of a repo.
 */
export async function readRepoScopedConfigKeys(cwd: string): Promise<string[]> {
  const { stdout } = await runGit(
    ['config', '--list', '--show-scope', '--includes', '-z'],
    { cwd }
  );
  // Format: scope NUL key [LF value] NUL scope NUL key [LF value] NUL ...
  const fields = stdout.split('\0');
  const keys: string[] = [];
  for (let i = 0; i + 1 < fields.length; i += 2) {
    const scope = fields[i];
    const key = fields[i + 1].split('\n', 1)[0];
    if (scope === 'local' || scope === 'worktree') keys.push(key);
  }
  return keys;
}

/**
 * Throw if the repository's own config sets anything that could redirect or
 * capture credentials (see {@link isDangerousRepoConfigKey}).
 */
export async function assertRepoConfigSafe(cwd: string): Promise<void> {
  const keys = await readRepoScopedConfigKeys(cwd);
  const bad = [...new Set(keys.filter(isDangerousRepoConfigKey))];
  if (bad.length > 0) {
    throw new Error(
      `Refusing to run an authenticated git command: the workspace's git config sets ${bad
        .map((k) => `"${k}"`)
        .join(', ')}, which could redirect or expose credentials. ` +
        'Remove these settings from the repository config and retry.'
    );
  }
}
