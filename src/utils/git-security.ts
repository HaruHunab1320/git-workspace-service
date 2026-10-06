/**
 * Git input validation and secret redaction.
 *
 * Everything that ends up as an argument to a git command (branch names,
 * refs, repository URLs) is validated here before use, and everything that
 * ends up in a log line or error message can be passed through the redaction
 * helpers so credentials never leak.
 */

// ─────────────────────────────────────────────────────────────
// Ref names
// ─────────────────────────────────────────────────────────────

/**
 * Characters allowed in branch/ref names. This is deliberately stricter than
 * `git check-ref-format`: it keeps names safe to pass to any downstream tool,
 * including ones that (wrongly) interpolate them into a shell.
 */
const REF_ALLOWED_CHARS = /^[A-Za-z0-9._/+@-]+$/;

const MAX_REF_LENGTH = 255;

/**
 * Validate a branch or ref name.
 *
 * Applies the `git check-ref-format --branch` rules (no `..`, no `@{`, no
 * component starting with `.` or ending in `.lock`, no empty components, no
 * trailing `.` or `/`, not `@`) plus:
 * - a conservative character allow-list: letters, digits, `.`, `_`, `/`, `+`,
 *   `@` and `-` (so no whitespace, shell metacharacters or control characters)
 * - no leading `-`, so a name can never be parsed as a command-line option
 */
export function isValidRefName(name: unknown): name is string {
  if (typeof name !== 'string') return false;
  if (name.length === 0 || name.length > MAX_REF_LENGTH) return false;
  if (!REF_ALLOWED_CHARS.test(name)) return false;
  if (name.startsWith('-') || name.startsWith('/') || name.endsWith('/')) {
    return false;
  }
  if (name.endsWith('.')) return false;
  if (name === '@') return false;
  if (name.includes('..') || name.includes('@{') || name.includes('//')) {
    return false;
  }
  for (const component of name.split('/')) {
    if (component.startsWith('.') || component.endsWith('.lock')) {
      return false;
    }
  }
  return true;
}

/**
 * Throw if `name` is not a valid ref name (see {@link isValidRefName}).
 */
export function assertValidRefName(name: unknown, label = 'branch'): string {
  if (!isValidRefName(name)) {
    throw new Error(
      `Invalid ${label} name: ${JSON.stringify(redactSecrets(String(name)))}. ` +
        'Branch names may contain only letters, digits, ".", "_", "/", "+", "@" and "-", ' +
        'must not start with "-", and must satisfy git check-ref-format rules.'
    );
  }
  return name;
}

// ─────────────────────────────────────────────────────────────
// Repository URLs
// ─────────────────────────────────────────────────────────────

export interface ParsedRepoUrl {
  /** Transport the URL uses as given */
  protocol: 'https' | 'ssh';
  /** Lowercased host, including `:port` when one was given */
  host: string;
  /** Repository path without leading slash or trailing `.git`, e.g. `owner/repo` */
  path: string;
  /** Canonical credential-free HTTPS clone URL: `https://host/path.git` */
  httpsUrl: string;
  /**
   * The URL to use for SSH transport (only set when the input was an SSH URL),
   * normalised to end in `.git`.
   */
  sshUrl?: string;
}

const HOST_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$/;
const SSH_USER_RE = /^[A-Za-z0-9._-]+$/;
const PATH_SEGMENT_RE =
  /^[A-Za-z0-9_][A-Za-z0-9._-]*$|^\.[A-Za-z0-9_-][A-Za-z0-9._-]*$/;

function normalisePath(rawPath: string): string | null {
  let p = rawPath.replace(/\/+$/, '');
  if (p.endsWith('.git')) p = p.slice(0, -4);
  const segments = p.split('/');
  if (segments.length < 2) return null;
  for (const seg of segments) {
    if (!PATH_SEGMENT_RE.test(seg) || seg === '.' || seg === '..') return null;
  }
  return segments.join('/');
}

function normaliseHost(rawHost: string): string | null {
  const host = rawHost.toLowerCase();
  return HOST_RE.test(host) ? host : null;
}

function invalidRepo(repo: string, reason: string): Error {
  return new Error(
    `Invalid repository URL ${JSON.stringify(redactSecrets(repo))}: ${reason}. ` +
      'Expected https://host/owner/repo(.git), git@host:owner/repo(.git), ' +
      'ssh://[user@]host[:port]/owner/repo(.git), host/owner/repo or owner/repo (GitHub).'
  );
}

/**
 * Parse and validate a repository reference.
 *
 * Accepted forms:
 * - `https://host[:port]/owner/repo[.git]`
 * - `git@host:owner/repo[.git]` (scp-like SSH)
 * - `ssh://[user@]host[:port]/owner/repo[.git]`
 * - `host.tld/owner/repo[.git]` (treated as HTTPS)
 * - `owner/repo` (treated as `https://github.com/owner/repo.git`)
 *
 * Rejected: any other scheme (`http://`, `file://`, `ext::`, ...), URLs with
 * embedded credentials (`https://user:token@...`), query strings, fragments,
 * whitespace, and path segments that are `.`/`..` or start with `-`.
 */
export function parseRepoUrl(repo: unknown): ParsedRepoUrl {
  if (typeof repo !== 'string' || repo.length === 0) {
    throw invalidRepo(String(repo), 'must be a non-empty string');
  }
  if (repo.length > 2048) {
    throw invalidRepo(repo.slice(0, 64), 'too long');
  }
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
  if (/[\s\x00-\x1f\x7f]/.test(repo)) {
    throw invalidRepo(
      repo,
      'must not contain whitespace or control characters'
    );
  }
  if (/[?#]/.test(repo)) {
    throw invalidRepo(repo, 'must not contain a query string or fragment');
  }

  const build = (
    protocol: 'https' | 'ssh',
    rawHost: string,
    rawPath: string,
    sshUrl?: (host: string, path: string) => string
  ): ParsedRepoUrl => {
    const host = normaliseHost(rawHost);
    if (!host) throw invalidRepo(repo, 'invalid host');
    const path = normalisePath(rawPath);
    if (!path) throw invalidRepo(repo, 'invalid repository path');
    return {
      protocol,
      host,
      path,
      httpsUrl: `https://${host}/${path}.git`,
      sshUrl: sshUrl ? sshUrl(host, path) : undefined,
    };
  };

  // https://host/owner/repo
  let m = /^https:\/\/([^/]*)\/(.+)$/i.exec(repo);
  if (m) {
    if (m[1].includes('@')) {
      throw invalidRepo(
        repo,
        'must not embed credentials; pass them via userCredentials or a credential service'
      );
    }
    return build('https', m[1], m[2]);
  }

  // ssh://[user@]host[:port]/owner/repo
  m = /^ssh:\/\/(?:([^@/]+)@)?([^/@]+)\/(.+)$/i.exec(repo);
  if (m) {
    const user = m[1];
    if (user !== undefined && !SSH_USER_RE.test(user)) {
      throw invalidRepo(repo, 'invalid SSH user');
    }
    return build('ssh', m[2], m[3], (host, path) =>
      user ? `ssh://${user}@${host}/${path}.git` : `ssh://${host}/${path}.git`
    );
  }

  // Any other scheme is rejected (http://, file://, git://, ext::, fd::, ...)
  if (
    /^[a-z][a-z0-9+.-]*:\/\//i.test(repo) ||
    /^[a-z][a-z0-9+.-]*::/i.test(repo)
  ) {
    throw invalidRepo(repo, 'only https:// and SSH URLs are supported');
  }

  // git@host:owner/repo (scp-like)
  m = /^([^@/:]+)@([^/:]+):(.+)$/.exec(repo);
  if (m) {
    const user = m[1];
    if (!SSH_USER_RE.test(user)) throw invalidRepo(repo, 'invalid SSH user');
    if (m[3].startsWith('/')) {
      throw invalidRepo(repo, 'absolute SSH paths are not supported');
    }
    return build(
      'ssh',
      m[2],
      m[3],
      (host, path) => `${user}@${host}:${path}.git`
    );
  }

  if (repo.includes('@') || repo.includes(':')) {
    throw invalidRepo(repo, 'unrecognised URL form');
  }

  // host.tld/owner/repo
  const parts = repo.replace(/\/+$/, '').split('/');
  if (
    parts.length >= 3 &&
    (parts[0].includes('.') || parts[0] === 'localhost')
  ) {
    return build('https', parts[0], parts.slice(1).join('/'));
  }

  // owner/repo shorthand -> GitHub
  if (parts.length === 2) {
    return build('https', 'github.com', parts.join('/'));
  }

  throw invalidRepo(repo, 'unrecognised URL form');
}

// ─────────────────────────────────────────────────────────────
// Tokens
// ─────────────────────────────────────────────────────────────

/**
 * Tokens are written to a file and echoed by the credential helper in git's
 * line-based credential protocol, so they must not contain whitespace or
 * control characters (a newline would allow injecting protocol fields).
 */
export function assertSafeToken(token: string): void {
  if (!/^[\x21-\x7e]+$/.test(token)) {
    throw new Error(
      'Credential token contains whitespace, control or non-ASCII characters and cannot be used'
    );
  }
}

// ─────────────────────────────────────────────────────────────
// Redaction
// ─────────────────────────────────────────────────────────────

const REDACTED = '***';

/**
 * Redact userinfo from any URL in `text` (`https://user:pass@host` ->
 * `https://***@host`), plus any well-known token formats, plus every string in
 * `secrets`. Safe to call on arbitrary log/error text.
 */
export function redactSecrets(
  text: string,
  secrets: ReadonlyArray<string | undefined | null> = []
): string {
  let out = text;
  for (const secret of secrets) {
    // Very short strings would redact unrelated text; real tokens are long.
    if (secret && secret.length >= 4) {
      out = out.split(secret).join(REDACTED);
    }
  }
  // scheme://userinfo@host  — leave plain `ssh://git@host` alone.
  out = out.replace(
    /\b([a-z][a-z0-9+.-]*:\/\/)([^\s/@]+)@/gi,
    (match, scheme: string, userinfo: string) =>
      /^ssh:\/\/$/i.test(scheme) && SSH_USER_RE.test(userinfo)
        ? match
        : `${scheme}${REDACTED}@`
  );
  // Well-known token shapes (GitHub, GitLab), in case one slips through
  out = out.replace(
    /\b(gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,})\b/g,
    REDACTED
  );
  // HTTP auth headers
  out = out.replace(
    /\b(authorization:\s*(?:basic|bearer|token)\s+)[^\s'"]+/gi,
    `$1${REDACTED}`
  );
  return out;
}

// ─────────────────────────────────────────────────────────────
// Repository config inspection
// ─────────────────────────────────────────────────────────────

/**
 * Config keys that, when set in a workspace's own (local/worktree) config,
 * could redirect an authenticated request, intercept the credential, or run
 * arbitrary code while the service's credential is available. The service
 * refuses to run authenticated commands in a repository with any of these.
 *
 * `core.hooksPath` and `core.fsmonitor` are not listed because the service
 * overrides them on the command line for every authenticated command.
 */
export function isDangerousRepoConfigKey(key: string): boolean {
  const k = key.toLowerCase();
  if (
    k.startsWith('credential.') ||
    k.startsWith('url.') ||
    k.startsWith('http.') ||
    k.startsWith('include.') ||
    k.startsWith('includeif.') ||
    k.startsWith('protocol.')
  ) {
    return true;
  }
  if (
    k === 'core.sshcommand' ||
    k === 'core.askpass' ||
    k === 'core.gitproxy'
  ) {
    return true;
  }
  if (/^remote\..+\.(proxy|vcs|pushurl)$/.test(k)) {
    return true;
  }
  return false;
}

/**
 * Quote a string for safe inclusion in a POSIX shell command.
 */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}
