# Changelog

## 0.5.0 - 2026-10-06

Security release: workspaces no longer contain credentials. Callers pass the same config as before. The behaviour changes are listed below; most callers need no code changes.

### Security
- **Token no longer in the clone URL or `.git/config`.** Previously `cloneRepo` cloned `https://x-access-token:<token>@host/...`, which persisted the token as `origin`'s URL in `.git/config`, where it was readable by anything in the workspace and could leak into git error messages. Repositories are now cloned from a plain `https://host/owner/repo.git` URL.
- **No in-workspace credential helper.** Previously the token was written to `<workspace>/.git-workspace/credential-context.json`, and a helper script registered in the workspace's `.git/config`. Credentials are now supplied per command by a single-use helper. It lives in a private `0700` temp directory outside the workspace, is passed with top-level `git -c` options (never persisted), only answers for the repository's host, and is deleted when the command finishes (or fails) and on `cleanup()`.
- **No shell interpolation.** Every git command now runs through `execFile` with an argument array. Previously branch names and URLs were interpolated into shell strings (`git clone --branch ${base} ${url} .`), which allowed command injection.
- **Input validation.** Branch, base-branch and custom `branchName` values are validated (`git check-ref-format` rules plus a strict allow-list). Repository URLs must be HTTPS or SSH. URLs with embedded credentials, `http://`, `file://` and `ext::` are rejected.
- **Redaction.** Errors, events, progress messages and logs are redacted: tokens, URL userinfo and `Authorization` headers. Git errors are rethrown as `GitCommandError` with redacted `message`/`stderr`.
- **Hardened authenticated commands.** Push and fetch in an existing workspace refuse to run if its git config could redirect or capture the credential (`credential.*`, `url.*`, `http.*`, `include*`, `protocol.*`, `core.sshCommand`, ...) or if `origin` was changed. Hooks and fsmonitor are disabled for those commands.
- Other credential helpers (system, global or repository) are reset for authenticated commands, so they no longer receive or store the workspace token. For example, macOS `osxkeychain` no longer stores the token.

### Added
- `WorkspaceService.push(workspaceId, { force?, setUpstream? })` and `WorkspaceService.fetch(workspaceId, refs?)` run authenticated push and fetch without exposing the token to the workspace.
- `WorkspaceServiceConfig.credentialHelperDir` (optional) sets the parent directory for the single-use helpers. It defaults to `os.tmpdir()` and must be outside `baseDir`.
- New exports: `runGit`, `GitCommandError`, `createEphemeralCredentialHelper`, `parseRepoUrl`, `isValidRefName`, `assertValidRefName`, `redactSecrets`.

### Changed (behaviour)
- **Agents can no longer push or fetch private repositories from inside a workspace** using credentials the service provided, because the workspace no longer contains them. Callers that ran `git push` themselves in the workspace and relied on the stored credential must call `workspaceService.push(id)` (or `finalize({ push: true })`) instead. Ambient credentials (SSH agent, system helpers) still work as before.
- Provisioning no longer creates `.git-workspace/` or appends `.git-workspace/` to the workspace's `.gitignore`, so the working tree stays clean. `cleanup()` still removes a legacy `.git-workspace/` directory if one exists.
- Branch names containing characters outside `A-Z a-z 0-9 . _ / + @ -`, or starting with `-`, are now rejected. Repository URLs in unsupported forms are rejected up front, where before they failed later during clone.
- The `owner/repo` shorthand now clones `https://github.com/owner/repo.git`. Before, it produced an invalid URL.
- Clone URLs are normalised to end in `.git`.
- Requires git 2.26 or later (for `git config --show-scope`).

### Deprecated
- `configureCredentialHelper`, `updateCredentials`, `getGitCredentialConfig`, `createShellCredentialHelperScript`, `createNodeCredentialHelperScript` and `outputCredentials` store credentials inside the workspace, so the service no longer uses them. They remain exported for compatibility and will be removed in a future release.

## 0.4.6 - 2026-05-26

### Changed
- Repository extracted from the parallax monorepo into its own standalone repo at `github.com/HaruHunab1320/git-workspace-service`. Package metadata (`repository`, `homepage`, `bugs`) updated accordingly. No source code changes.

## 0.4.5 - 2026-03-30

### Fixed
- **Credential service made optional** — `WorkspaceService` now works without a `credentialService` (PAT-only mode). All credential service calls are null-safe, with direct PAT credential creation when no credential service is configured.

### Changed
- **Debug logging migrated to Pino** — `git-credential-helper.ts` and `device-flow.ts` now use structured Pino logging for debug/status output. `console.log` preserved for git credential protocol output (stdout) and interactive OAuth prompts.
- Biome linter applied (formatting normalization across all source files).

## 0.4.4

### Fixed

- Remove `--depth 1` from git clone commands in both `tryUnauthenticatedClone()` and `cloneRepo()`. Shallow clones caused "refusing to merge unrelated histories" errors when agents tried to merge or rebase, because the single-commit clone had no common ancestor with branches that had diverged. Workspaces now get full history so git operations (merge, rebase, cherry-pick) work correctly.

## 0.4.3 and earlier

- Initial releases (no changelog maintained).
