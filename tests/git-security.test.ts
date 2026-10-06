/**
 * Git input validation, redaction and credential helper tests
 */

import { execFile } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createEphemeralCredentialHelper, runGit } from '../src/utils/git-exec';
import {
  assertValidRefName,
  isDangerousRepoConfigKey,
  isValidRefName,
  parseRepoUrl,
  redactSecrets,
} from '../src/utils/git-security';
import { WorkspaceService } from '../src/workspace-service';

describe('isValidRefName', () => {
  it.each([
    'main',
    'develop',
    'release/1.2.3',
    'parallax/exec-123/engineer-auth-feature',
    'test/claude-nonce-abc123',
    'feature/JIRA-42_fix+thing',
    'user@feature',
    'v1.0',
  ])('accepts %s', (name) => {
    expect(isValidRefName(name)).toBe(true);
  });

  it.each([
    '',
    'main; rm -rf /',
    'main && curl evil',
    '$(whoami)',
    '`id`',
    'a|b',
    'a b',
    'a\nb',
    'a\tb',
    '-b',
    '--upload-pack=touch /tmp/pwned',
    'a..b',
    'a@{1}',
    '@',
    '/main',
    'main/',
    'a//b',
    'main.',
    'feature/.hidden',
    'feature/x.lock',
    'a~1',
    'a^',
    'a:b',
    'a?b',
    'a*b',
    'a[b',
    'a\\b',
    'ünïcode',
    'x'.repeat(256),
  ])('rejects %j', (name) => {
    expect(isValidRefName(name)).toBe(false);
  });

  it('rejects non-strings', () => {
    expect(isValidRefName(undefined)).toBe(false);
    expect(isValidRefName(42)).toBe(false);
  });

  it('assertValidRefName throws a descriptive error', () => {
    expect(() => assertValidRefName('main; rm -rf /', 'base branch')).toThrow(
      /Invalid base branch name: "main; rm -rf \/"/
    );
  });
});

describe('parseRepoUrl', () => {
  it.each([
    ['https://github.com/owner/repo', 'https', 'github.com', 'owner/repo'],
    ['https://github.com/owner/repo.git', 'https', 'github.com', 'owner/repo'],
    ['https://github.com/owner/repo/', 'https', 'github.com', 'owner/repo'],
    ['https://GitHub.com/Owner/Repo', 'https', 'github.com', 'Owner/Repo'],
    [
      'https://gitlab.example.com/group/sub/repo.git',
      'https',
      'gitlab.example.com',
      'group/sub/repo',
    ],
    [
      'https://localhost:8443/owner/repo.git',
      'https',
      'localhost:8443',
      'owner/repo',
    ],
    ['github.com/owner/repo', 'https', 'github.com', 'owner/repo'],
    ['owner/repo', 'https', 'github.com', 'owner/repo'],
    ['owner/.github', 'https', 'github.com', 'owner/.github'],
    ['git@github.com:owner/repo.git', 'ssh', 'github.com', 'owner/repo'],
    ['git@github.com:owner/repo', 'ssh', 'github.com', 'owner/repo'],
    ['ssh://git@github.com/owner/repo.git', 'ssh', 'github.com', 'owner/repo'],
    [
      'ssh://git@example.com:2222/owner/repo',
      'ssh',
      'example.com:2222',
      'owner/repo',
    ],
  ])('parses %s', (input, protocol, host, repoPath) => {
    const parsed = parseRepoUrl(input);
    expect(parsed.protocol).toBe(protocol);
    expect(parsed.host).toBe(host);
    expect(parsed.path).toBe(repoPath);
    expect(parsed.httpsUrl).toBe(`https://${host}/${repoPath}.git`);
  });

  it('keeps an SSH URL for SSH transport', () => {
    expect(parseRepoUrl('git@github.com:owner/repo').sshUrl).toBe(
      'git@github.com:owner/repo.git'
    );
    expect(
      parseRepoUrl('https://github.com/owner/repo').sshUrl
    ).toBeUndefined();
  });

  it.each([
    'http://github.com/owner/repo',
    'file:///tmp/repo.git',
    'git://github.com/owner/repo',
    'ext::sh -c touch% /tmp/pwned',
    'fd::17',
    'https://github.com/owner',
    'https://github.com/owner/repo?x=1',
    'https://github.com/owner/repo#frag',
    'https://github.com/owner/../repo',
    'https://github.com/owner/-repo',
    'https://github.com/owner/repo name',
    'https://github.com/owner/repo;rm -rf /',
    'https://github.com/owner/$(id)',
    'git@github.com:/abs/path.git',
    'git@github.com:owner/repo;id',
    '-uconfig/owner/repo',
    'repo',
    '',
  ])('rejects %j', (input) => {
    expect(() => parseRepoUrl(input)).toThrow(/Invalid repository URL/);
  });

  it('rejects embedded credentials without echoing them', () => {
    const secret = 'ghp_abcdefghijklmnopqrstuvwxyz0123';
    let message = '';
    try {
      parseRepoUrl(`https://x-access-token:${secret}@github.com/owner/repo`);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/must not embed credentials/);
    expect(message).not.toContain(secret);
  });
});

describe('redactSecrets', () => {
  it('redacts URL userinfo', () => {
    expect(
      redactSecrets(
        "fatal: unable to access 'https://x-access-token:abc123@github.com/o/r.git/'"
      )
    ).toBe("fatal: unable to access 'https://***@github.com/o/r.git/'");
    expect(redactSecrets('https://user@host/x')).toBe('https://***@host/x');
  });

  it('keeps plain ssh users', () => {
    expect(redactSecrets('ssh://git@github.com/o/r.git')).toBe(
      'ssh://git@github.com/o/r.git'
    );
  });

  it('redacts explicit secrets and well-known token shapes', () => {
    expect(redactSecrets('token is s3cr3t-value', ['s3cr3t-value'])).toBe(
      'token is ***'
    );
    expect(redactSecrets('ghp_0123456789abcdefABCDEF here')).toBe('*** here');
    expect(redactSecrets('github_pat_11ABCDEFG0123456789_abcdefghij')).toBe(
      '***'
    );
    expect(redactSecrets('Authorization: Basic eC1hY2Nlc3M=')).toBe(
      'Authorization: Basic ***'
    );
  });
});

describe('isDangerousRepoConfigKey', () => {
  it.each([
    'credential.helper',
    'credential.https://github.com.helper',
    'url.https://evil/.insteadof',
    'url.https://evil/.pushinsteadof',
    'http.proxy',
    'http.sslverify',
    'http.https://github.com/.extraheader',
    'include.path',
    'includeif.gitdir:/x/.path',
    'protocol.ext.allow',
    'core.sshcommand',
    'core.askpass',
    'remote.origin.proxy',
    'remote.origin.pushurl',
    'remote.origin.vcs',
  ])('flags %s', (key) => {
    expect(isDangerousRepoConfigKey(key)).toBe(true);
  });

  it.each([
    'user.name',
    'user.email',
    'core.bare',
    'core.hookspath', // overridden on the command line instead
    'remote.origin.url',
    'remote.origin.fetch',
    'branch.main.remote',
  ])('allows %s', (key) => {
    expect(isDangerousRepoConfigKey(key)).toBe(false);
  });
});

describe('createEphemeralCredentialHelper', () => {
  let parentDir: string;

  beforeEach(async () => {
    parentDir = await fs.mkdtemp(path.join(os.tmpdir(), 'gws-helper-test-'));
  });

  afterEach(async () => {
    await fs.rm(parentDir, { recursive: true, force: true });
  });

  const runHelper = async (
    helperArg: string,
    action: string,
    input: string
  ): Promise<string> => {
    // helper config value is "!'<path>'"; git runs it via sh with the action appended
    const command = `${helperArg.slice('credential.helper=!'.length)} ${action}`;
    return new Promise((resolve, reject) => {
      const child = execFile('sh', ['-c', command], (err, stdout) =>
        err ? reject(err) : resolve(stdout)
      );
      child.stdin?.end(input);
    });
  };

  it('writes private files, answers only for the expected host, and disposes', async () => {
    const helper = await createEphemeralCredentialHelper({
      token: 'tok_ABC123',
      host: 'github.com',
      parentDir,
    });

    expect(path.dirname(helper.dir)).toBe(parentDir);
    expect(path.basename(helper.dir)).toMatch(/^gws-cred-/);
    const dirStat = await fs.stat(helper.dir);
    expect(dirStat.mode & 0o777).toBe(0o700);
    const tokenStat = await fs.stat(path.join(helper.dir, 'token'));
    expect(tokenStat.mode & 0o777).toBe(0o600);

    // Token never appears in the git arguments
    expect(helper.configArgs.join(' ')).not.toContain('tok_ABC123');
    expect(helper.configArgs.slice(0, 2)).toEqual(['-c', 'credential.helper=']);
    const helperArg = helper.configArgs[3];

    expect(
      await runHelper(helperArg, 'get', 'protocol=https\nhost=github.com\n\n')
    ).toBe('username=x-access-token\npassword=tok_ABC123\n');

    // Wrong host, wrong protocol, and non-get actions get nothing
    expect(
      await runHelper(helperArg, 'get', 'protocol=https\nhost=evil.example\n\n')
    ).toBe('');
    expect(
      await runHelper(helperArg, 'get', 'protocol=http\nhost=github.com\n\n')
    ).toBe('');
    expect(
      await runHelper(helperArg, 'store', 'protocol=https\nhost=github.com\n\n')
    ).toBe('');

    await helper.dispose();
    await expect(fs.access(helper.dir)).rejects.toThrow();
    await helper.dispose(); // idempotent
  });

  it('rejects tokens that could inject credential protocol lines', async () => {
    await expect(
      createEphemeralCredentialHelper({
        token: 'abc\nhost=evil',
        host: 'github.com',
        parentDir,
      })
    ).rejects.toThrow(/invalid|whitespace/i);
    expect(await fs.readdir(parentDir)).toEqual([]);
  });
});

describe('runGit', () => {
  it('passes arguments without a shell', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'gws-rungit-'));
    try {
      const marker = path.join(dir, 'pwned');
      await expect(
        runGit(['check-ref-format', '--branch', `x; touch ${marker}`], {
          cwd: dir,
        })
      ).rejects.toThrow(/git check-ref-format failed/);
      await expect(fs.access(marker)).rejects.toThrow();
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('redacts secrets from errors', async () => {
    const secret = 'super-secret-token-value';
    const error = await runGit(['rev-parse', '--verify', secret], {
      cwd: os.tmpdir(),
      secrets: [secret],
    }).catch((e: Error) => e);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).not.toContain(secret);
  });
});

describe('WorkspaceService input validation', () => {
  let baseDir: string;
  let service: WorkspaceService;

  beforeEach(async () => {
    baseDir = await fs.mkdtemp(path.join(os.tmpdir(), 'gws-validate-'));
    service = new WorkspaceService({ config: { baseDir } });
    await service.initialize();
  });

  afterEach(async () => {
    await fs.rm(baseDir, { recursive: true, force: true });
  });

  const base = {
    repo: 'https://github.com/owner/repo',
    branchStrategy: 'feature_branch' as const,
    baseBranch: 'main',
    execution: { id: 'exec-1', patternName: 'p' },
    task: { id: 't', role: 'engineer' },
  };

  it('rejects a malicious base branch before touching disk', async () => {
    await expect(
      service.provision({ ...base, baseBranch: 'main; rm -rf /' })
    ).rejects.toThrow(/Invalid base branch name/);
    expect(await fs.readdir(baseDir)).toEqual([]);
  });

  it('rejects a malicious custom branch name', async () => {
    await expect(
      service.provision({ ...base, branchName: 'main; rm -rf /' })
    ).rejects.toThrow(/Invalid branch name/);
    await expect(
      service.provision({ ...base, branchName: '--upload-pack=touch /tmp/x' })
    ).rejects.toThrow(/Invalid branch name/);
    expect(await fs.readdir(baseDir)).toEqual([]);
  });

  it('rejects unsupported repository URLs without echoing credentials', async () => {
    await expect(
      service.provision({ ...base, repo: 'file:///etc' })
    ).rejects.toThrow(/only https:\/\/ and SSH URLs/);
    await expect(
      service.provision({ ...base, repo: 'http://github.com/owner/repo' })
    ).rejects.toThrow(/Invalid repository URL/);
    const err = await service
      .provision({
        ...base,
        repo: 'https://x-access-token:ghp_secretsecretsecret123@github.com/o/r',
      })
      .catch((e: Error) => e);
    expect((err as Error).message).not.toContain('ghp_secretsecretsecret123');
    expect(await fs.readdir(baseDir)).toEqual([]);
  });

  it('requires credentialHelperDir to be outside baseDir', () => {
    expect(
      () =>
        new WorkspaceService({
          config: { baseDir, credentialHelperDir: path.join(baseDir, 'creds') },
        })
    ).toThrow(/outside baseDir/);
  });

  it('push and fetch reject unknown workspaces', async () => {
    await expect(service.push('nope')).rejects.toThrow('Workspace not found');
    await expect(service.fetch('nope')).rejects.toThrow('Workspace not found');
  });
});
