/**
 * End-to-end credential isolation tests.
 *
 * Runs the real WorkspaceService (real git, no mocks) against a local HTTPS
 * git server that requires HTTP Basic auth, and checks that the token is used
 * for clone/fetch/push but is never readable from inside the workspace, never
 * appears in process arguments, and never appears in errors.
 */

import { execFile, execFileSync } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { promisify } from 'node:util';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { WorkspaceConfig, WorkspaceEvent } from '../src/types';
import { WorkspaceService } from '../src/workspace-service';
import {
  canRunHttpsGitServer,
  type HttpsGitServer,
  startHttpsGitServer,
} from './helpers/https-git-server';

const execFileAsync = promisify(execFile);

const TOKEN = 'ghp_TESTtoken0123456789abcdefSECRET';
const WRONG_TOKEN = 'ghp_WRONGtoken0123456789abcdefSECRET';

const describeIfSupported =
  process.platform !== 'win32' && canRunHttpsGitServer()
    ? describe
    : describe.skip;

async function listFilesRecursive(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await listFilesRecursive(full)));
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

/** Every file under `dir` whose bytes contain `needle`. */
async function filesContaining(dir: string, needle: string): Promise<string[]> {
  const hits: string[] = [];
  for (const file of await listFilesRecursive(dir)) {
    const content = await fs.readFile(file);
    if (content.includes(needle)) hits.push(file);
  }
  return hits;
}

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

describeIfSupported('credential isolation (real git over HTTPS)', () => {
  let root: string;
  let projectRoot: string;
  let baseDir: string;
  let helperDir: string;
  let server: HttpsGitServer;
  let repoUrl: string;
  let bareRepo: string;
  const savedEnv: Record<string, string | undefined> = {};

  const setEnv = (key: string, value: string) => {
    if (!(key in savedEnv)) savedEnv[key] = process.env[key];
    process.env[key] = value;
  };

  beforeAll(async () => {
    root = await fs.realpath(
      await fs.mkdtemp(path.join(os.tmpdir(), 'gws-cred-it-'))
    );
    projectRoot = path.join(root, 'project');
    baseDir = path.join(root, 'workspaces');
    helperDir = path.join(root, 'helpers');
    await fs.mkdir(projectRoot, { recursive: true });
    await fs.mkdir(helperDir, { recursive: true });

    // Isolate from the developer's global/system git config (credential
    // helpers, url rewrites, ...), and trust the throwaway server cert.
    setEnv('GIT_CONFIG_NOSYSTEM', '1');
    setEnv('GIT_CONFIG_GLOBAL', os.devNull);
    setEnv('GIT_AUTHOR_NAME', 'Test');
    setEnv('GIT_AUTHOR_EMAIL', 'test@example.com');
    setEnv('GIT_COMMITTER_NAME', 'Test');
    setEnv('GIT_COMMITTER_EMAIL', 'test@example.com');

    // Seed a bare repository: owner/repo.git with a main branch
    bareRepo = path.join(projectRoot, 'owner', 'repo.git');
    await fs.mkdir(bareRepo, { recursive: true });
    git(bareRepo, ['init', '--bare', '--initial-branch=main', '.']);
    const seed = path.join(root, 'seed');
    await fs.mkdir(seed);
    git(seed, ['init', '--initial-branch=main', '.']);
    await fs.writeFile(path.join(seed, 'README.md'), '# test repo\n');
    git(seed, ['add', '.']);
    git(seed, ['commit', '-m', 'initial']);
    git(seed, ['push', bareRepo, 'main']);

    server = await startHttpsGitServer({
      projectRoot,
      workDir: root,
      credentials: `x-access-token:${TOKEN}`,
    });
    setEnv('GIT_SSL_CAINFO', server.certPath);
    repoUrl = `${server.origin}/owner/repo`;
  }, 60_000);

  afterAll(async () => {
    await server?.close();
    for (const [key, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await fs.rm(root, { recursive: true, force: true });
  });

  let service: WorkspaceService;
  let events: WorkspaceEvent[];

  beforeEach(async () => {
    server.requests.length = 0;
    server.onAuthorizedRequest = undefined;
    service = new WorkspaceService({
      config: { baseDir, credentialHelperDir: helperDir },
    });
    await service.initialize();
    events = [];
    service.onEvent((e) => {
      events.push(e);
    });
  });

  const config = (
    overrides: Partial<WorkspaceConfig> = {}
  ): WorkspaceConfig => ({
    repo: repoUrl,
    branchStrategy: 'feature_branch',
    baseBranch: 'main',
    execution: {
      id: `exec-${Math.random().toString(36).slice(2, 8)}`,
      patternName: 'it',
    },
    task: { id: 'task-1', role: 'engineer' },
    userCredentials: { type: 'pat', token: TOKEN },
    ...overrides,
  });

  it('clones with the token but leaves no trace of it in the workspace', async () => {
    const helperDirsSeen: string[] = [];
    let psOutput = '';
    server.onAuthorizedRequest = async () => {
      // While git is talking to the server, the helper exists outside the
      // workspace and the token is not in any process's arguments.
      helperDirsSeen.push(...(await fs.readdir(helperDir)));
      psOutput += execFileSync('ps', ['-axww', '-o', 'args'], {
        encoding: 'utf8',
      });
    };

    const workspace = await service.provision(config());

    expect(workspace.status).toBe('ready');
    // The token was really used: the server saw authenticated requests
    expect(server.requests.some((r) => r.authorized)).toBe(true);
    expect(helperDirsSeen.length).toBeGreaterThan(0);
    expect(helperDirsSeen.every((d) => d.startsWith('gws-cred-'))).toBe(true);
    expect(psOutput).toContain('remote-https'); // ps saw the live git process
    expect(psOutput).not.toContain(TOKEN);

    // Nothing under the workspace (including .git/config) contains the token
    expect(await filesContaining(workspace.path, TOKEN)).toEqual([]);

    const gitConfig = await fs.readFile(
      path.join(workspace.path, '.git', 'config'),
      'utf8'
    );
    expect(gitConfig).not.toContain(TOKEN);
    expect(gitConfig).not.toContain('x-access-token');
    expect(gitConfig).not.toMatch(/credential/i);
    expect(gitConfig).not.toContain(helperDir);
    expect(gitConfig).toContain(`url = ${server.origin}/owner/repo.git`);

    // No helper is reachable from inside the workspace
    const configList = git(workspace.path, ['config', '--list']);
    expect(configList).not.toMatch(/credential\./i);
    await expect(
      fs.access(path.join(workspace.path, '.git-workspace'))
    ).rejects.toThrow();

    // The working tree is untouched (no .gitignore edits)
    expect(git(workspace.path, ['status', '--porcelain'])).toBe('');

    // The helper directory is gone after the command
    expect(await fs.readdir(helperDir)).toEqual([]);

    // From inside the workspace, git cannot authenticate on its own.
    // (Async: the server runs in this process, so a sync call would deadlock.)
    await expect(
      execFileAsync('git', ['fetch', 'origin'], {
        cwd: workspace.path,
        env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
      })
    ).rejects.toThrow(/terminal prompts disabled|Authentication failed/);

    // Nothing in events or progress carries the token
    expect(JSON.stringify(events)).not.toContain(TOKEN);
    expect(JSON.stringify(workspace.progress)).not.toContain(TOKEN);
  });

  it('pushes during finalize using a helper scoped to that command', async () => {
    const workspace = await service.provision(config());
    await fs.writeFile(path.join(workspace.path, 'change.txt'), 'hello\n');
    git(workspace.path, ['add', 'change.txt']);
    git(workspace.path, ['commit', '-m', 'change']);

    // A hook planted by an agent must not run during the authenticated push
    const marker = path.join(root, 'hook-ran');
    const hook = path.join(workspace.path, '.git', 'hooks', 'pre-push');
    await fs.writeFile(hook, `#!/bin/sh\nenv > '${marker}'\n`, { mode: 0o755 });

    server.requests.length = 0;
    await service.finalize(workspace.id, {
      push: true,
      createPr: false,
      cleanup: false,
    });

    expect(
      server.requests.some(
        (r) => r.authorized && r.url.includes('git-receive-pack')
      )
    ).toBe(true);
    expect(
      git(bareRepo, [
        'rev-parse',
        '--verify',
        `refs/heads/${workspace.branch.name}`,
      ]).trim()
    ).toMatch(/^[0-9a-f]{40}$/);
    await expect(fs.access(marker)).rejects.toThrow();
    expect(await fs.readdir(helperDir)).toEqual([]);
    expect(await filesContaining(workspace.path, TOKEN)).toEqual([]);

    // Upstream tracking is set up as before
    expect(
      git(workspace.path, [
        'config',
        `branch.${workspace.branch.name}.remote`,
      ]).trim()
    ).toBe('origin');
  });

  it('supports push() and fetch() on demand', async () => {
    const workspace = await service.provision(config());
    await fs.writeFile(path.join(workspace.path, 'more.txt'), 'more\n');
    git(workspace.path, ['add', 'more.txt']);
    git(workspace.path, ['commit', '-m', 'more']);

    await service.push(workspace.id);
    await service.fetch(workspace.id, ['main']);

    expect(
      git(bareRepo, ['rev-parse', `refs/heads/${workspace.branch.name}`]).trim()
    ).toBe(git(workspace.path, ['rev-parse', 'HEAD']).trim());
    expect(await fs.readdir(helperDir)).toEqual([]);
    await expect(
      service.fetch(workspace.id, ['main; rm -rf /'])
    ).rejects.toThrow(/Invalid ref name/);
  });

  it('provisions authenticated worktrees without leaking the token', async () => {
    const parent = await service.provision(config());
    const worktree = await service.addWorktree(parent.id, {
      branch: 'main',
      execution: { id: parent.branch.executionId, patternName: 'it' },
      task: { id: 'task-2', role: 'reviewer' },
    });

    expect(worktree.status).toBe('ready');
    expect(await filesContaining(parent.path, TOKEN)).toEqual([]);
    expect(await filesContaining(worktree.path, TOKEN)).toEqual([]);
    expect(await fs.readdir(helperDir)).toEqual([]);
  });

  it('refuses authenticated commands after the repo config is tampered with', async () => {
    const workspace = await service.provision(config());

    // Redirect via insteadOf
    git(workspace.path, [
      'config',
      `url.https://evil.example/.insteadOf`,
      `${server.origin}/`,
    ]);
    await expect(service.push(workspace.id)).rejects.toThrow(
      /url\.https:\/\/evil\.example\/\.insteadof/i
    );
    git(workspace.path, [
      'config',
      '--remove-section',
      'url.https://evil.example/',
    ]);

    // Capture via a repository-level credential helper
    git(workspace.path, ['config', 'credential.helper', 'store']);
    await expect(service.push(workspace.id)).rejects.toThrow(
      /credential\.helper/
    );
    git(workspace.path, ['config', '--unset', 'credential.helper']);

    // Point origin elsewhere
    git(workspace.path, [
      'remote',
      'set-url',
      'origin',
      'https://evil.example/x.git',
    ]);
    await expect(service.push(workspace.id)).rejects.toThrow(/does not match/);

    expect(
      server.requests.filter((r) => r.url.includes('receive-pack'))
    ).toEqual([]);
    expect(await fs.readdir(helperDir)).toEqual([]);
  });

  it('keeps the token out of errors, events and progress when auth fails', async () => {
    const promise = service.provision(
      config({ userCredentials: { type: 'pat', token: WRONG_TOKEN } })
    );
    const error = (await promise.then(
      () => new Error('expected provision to fail'),
      (e: unknown) => e
    )) as Error;

    expect(error).toBeInstanceOf(Error);
    expect(error.message).toMatch(/git clone failed/);
    expect(error.message).not.toContain(WRONG_TOKEN);
    expect(String(error.stack)).not.toContain(WRONG_TOKEN);
    expect(JSON.stringify(events)).not.toContain(WRONG_TOKEN);
    const failed = service
      .getForExecution(events[0].executionId)
      .find((w) => w.status === 'error');
    expect(failed?.progress?.message).not.toContain(WRONG_TOKEN);

    // Helper files are removed on failure too
    expect(await fs.readdir(helperDir)).toEqual([]);
  });

  it('cleanup removes helper files of an in-flight command', async () => {
    const workspace = await service.provision(config());
    await fs.writeFile(path.join(workspace.path, 'x.txt'), 'x\n');
    git(workspace.path, ['add', 'x.txt']);
    git(workspace.path, ['commit', '-m', 'x']);

    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let reachedServer!: () => void;
    const reached = new Promise<void>((resolve) => {
      reachedServer = resolve;
    });
    server.onAuthorizedRequest = async () => {
      reachedServer();
      await gate;
    };

    const push = service.push(workspace.id).catch(() => undefined);
    await reached;
    expect((await fs.readdir(helperDir)).length).toBe(1);

    await service.cleanup(workspace.id);
    expect(await fs.readdir(helperDir)).toEqual([]);

    release();
    await push;
  });

  it('removes the legacy in-workspace credential directory on cleanup', async () => {
    const workspace = await service.provision(config());
    const legacy = path.join(workspace.path, '.git-workspace');
    await fs.mkdir(legacy);
    await fs.writeFile(path.join(legacy, 'credential-context.json'), '{}');

    await service.cleanup(workspace.id);
    await expect(fs.access(legacy)).rejects.toThrow();
  });
});
