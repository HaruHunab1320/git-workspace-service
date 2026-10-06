/**
 * Workspace Service
 *
 * Provisions and manages git workspaces for agent tasks.
 * Handles cloning, branching, and PR creation.
 */

import { exec } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { promisify } from 'node:util';
import type { CredentialService } from './credential-service';
import type {
  BranchInfo,
  PullRequestInfo,
  Workspace,
  WorkspaceConfig,
  WorkspaceEvent,
  WorkspaceEventHandler,
  WorkspaceFinalization,
  WorkspacePhase,
  WorkspaceServiceConfig,
  WorkspaceStrategy,
} from './types';
import { createBranchInfo } from './utils/branch-naming';
import { cleanupCredentialFiles } from './utils/git-credential-helper';
import {
  assertRepoConfigSafe,
  createEphemeralCredentialHelper,
  type EphemeralCredentialHelper,
  hardeningConfigArgs,
  runGit,
} from './utils/git-exec';
import {
  assertValidRefName,
  type ParsedRepoUrl,
  parseRepoUrl,
  redactSecrets,
} from './utils/git-security';

// Used only for the caller-configured completion hook command, which is a
// shell command by design. All git commands go through runGit (execFile).
const execAsync = promisify(exec);

export interface WorkspaceServiceLogger {
  info(data: Record<string, unknown>, message: string): void;
  warn(data: Record<string, unknown>, message: string): void;
  error(data: Record<string, unknown>, message: string): void;
  debug(data: Record<string, unknown>, message: string): void;
}

export interface WorkspaceServiceOptions {
  /**
   * Configuration
   */
  config: WorkspaceServiceConfig;

  /**
   * Credential service for managing git credentials
   */
  credentialService?: CredentialService;

  /**
   * Optional logger
   */
  logger?: WorkspaceServiceLogger;
}

export interface WorkspacePushOptions {
  /** Force-push (`--force`). Default: false */
  force?: boolean;
  /** Set the upstream tracking branch (`-u`). Default: true */
  setUpstream?: boolean;
}

export class WorkspaceService {
  private workspaces: Map<string, Workspace> = new Map();
  private readonly baseDir: string;
  private readonly branchPrefix: string;
  private readonly credentialHelperDir?: string;
  private readonly credentialService: CredentialService | null;
  private readonly logger?: WorkspaceServiceLogger;
  private readonly eventHandlers: Set<WorkspaceEventHandler> = new Set();
  /** Credential helpers currently on disk, per workspace (removed on cleanup) */
  private readonly activeCredentialHelpers: Map<
    string,
    Set<EphemeralCredentialHelper>
  > = new Map();

  constructor(options: WorkspaceServiceOptions) {
    this.baseDir = options.config.baseDir;
    this.branchPrefix = options.config.branchPrefix || 'parallax';
    this.credentialService = options.credentialService ?? null;
    this.logger = options.logger;

    if (options.config.credentialHelperDir) {
      const helperDir = path.resolve(options.config.credentialHelperDir);
      const base = path.resolve(this.baseDir);
      if (helperDir === base || helperDir.startsWith(base + path.sep)) {
        throw new Error(
          'credentialHelperDir must be outside baseDir, so credentials are never stored inside a workspace'
        );
      }
      this.credentialHelperDir = helperDir;
    }
  }

  /**
   * Initialize the workspace service
   */
  async initialize(): Promise<void> {
    await fs.mkdir(this.baseDir, { recursive: true });
    this.log(
      'info',
      { baseDir: this.baseDir },
      'Workspace service initialized'
    );
  }

  /**
   * Register an event handler
   */
  onEvent(handler: WorkspaceEventHandler): () => void {
    this.eventHandlers.add(handler);
    return () => this.eventHandlers.delete(handler);
  }

  /**
   * Provision a new workspace for a task
   */
  async provision(config: WorkspaceConfig): Promise<Workspace> {
    const strategy: WorkspaceStrategy = config.strategy || 'clone';

    // Validate worktree config
    if (strategy === 'worktree') {
      if (!config.parentWorkspace) {
        throw new Error(
          'parentWorkspace is required when strategy is "worktree"'
        );
      }
      const parent = this.workspaces.get(config.parentWorkspace);
      if (!parent) {
        throw new Error(
          `Parent workspace not found: ${config.parentWorkspace}`
        );
      }
      if (parent.strategy !== 'clone') {
        throw new Error('Parent workspace must be a clone, not a worktree');
      }
      if (parent.repo !== config.repo) {
        throw new Error('Worktree must be for the same repository as parent');
      }
    }

    // Validate everything that will be passed to git before touching disk
    parseRepoUrl(config.repo);
    assertValidRefName(config.baseBranch, 'base branch');

    // Generate branch name (or use caller-provided override)
    const branchInfo: BranchInfo = config.branchName
      ? {
          name: config.branchName,
          executionId: config.execution.id,
          baseBranch: config.baseBranch,
          createdAt: new Date(),
        }
      : createBranchInfo(
          {
            executionId: config.execution.id,
            role: config.task.role,
            slug: config.task.slug,
            baseBranch: config.baseBranch,
          },
          { prefix: this.branchPrefix }
        );
    assertValidRefName(branchInfo.name, 'branch');

    const workspaceId = randomUUID();

    this.log(
      'info',
      {
        workspaceId,
        repo: config.repo,
        executionId: config.execution.id,
        role: config.task.role,
        strategy,
      },
      'Provisioning workspace'
    );

    await this.emitEvent({
      type: 'workspace:provisioning',
      workspaceId,
      executionId: config.execution.id,
      timestamp: new Date(),
    });

    // Create workspace directory (for clone) or use worktree path
    const workspacePath = path.join(this.baseDir, workspaceId);

    // Get credentials (or reuse parent's for worktree)
    // For public repos, credentials are optional - we'll try unauthenticated clone
    let credential;

    if (strategy === 'worktree' && config.parentWorkspace) {
      const parent = this.workspaces.get(config.parentWorkspace)!;
      credential = parent.credential;
    } else {
      await fs.mkdir(workspacePath, { recursive: true });

      // Try to get credentials (optional for public repos)
      if (this.credentialService) {
        credential = await this.credentialService.getCredentials({
          repo: config.repo,
          access: 'write',
          context: {
            executionId: config.execution.id,
            taskId: config.task.id,
            userId: config.user?.id,
            reason: `Workspace for ${config.task.role} in ${config.execution.patternName}`,
          },
          userProvided: config.userCredentials,
          optional: !config.userCredentials,
        });
      } else if (config.userCredentials?.type === 'pat') {
        // No credential service — use the user-provided PAT directly
        credential = {
          id: `pat-${config.execution.id}`,
          type: 'pat' as any,
          token: (config.userCredentials as any).token,
          repo: config.repo,
          permissions: ['read', 'write'],
          expiresAt: new Date(Date.now() + 3600000),
          provider: 'github' as any,
        };
      }

      if (credential) {
        await this.emitEvent({
          type: 'credential:granted',
          workspaceId,
          credentialId: credential.id,
          executionId: config.execution.id,
          timestamp: new Date(),
        });
      }
    }

    // Create workspace object (credential is optional for public repos)
    const workspace: Workspace = {
      id: workspaceId,
      path: workspacePath,
      repo: config.repo,
      branch: branchInfo,
      credential: credential ?? undefined, // Optional for public repos
      provisionedAt: new Date(),
      status: 'provisioning',
      strategy,
      parentWorkspaceId: config.parentWorkspace,
      onComplete: config.onComplete,
      progress: {
        phase: 'initializing',
        message: 'Initializing workspace',
        updatedAt: new Date(),
      },
    };

    this.workspaces.set(workspaceId, workspace);

    try {
      if (strategy === 'clone') {
        // Clone repository
        this.updateProgress(workspace, 'cloning', 'Cloning repository');

        // If no credentials, try unauthenticated clone (for public repos)
        if (!credential) {
          const cloneResult = await this.tryUnauthenticatedClone(workspace);
          if (!cloneResult.success) {
            // Unauthenticated clone failed - this is a private repo or auth is required
            // Throw a clear error since we already tried to get credentials above
            throw new Error(
              `Repository ${config.repo} requires authentication but no credentials are available. ` +
                'Please provide credentials or configure OAuth.'
            );
          }
          // Unauthenticated clone succeeded - this is a public repo
          this.log(
            'info',
            { workspaceId },
            'Cloned public repository without authentication'
          );
        } else {
          // We have credentials - clone with them
          await this.cloneRepo(workspace, credential.token);
        }

        // Create and checkout branch
        this.updateProgress(workspace, 'creating_branch', 'Creating branch');
        await this.createBranch(workspace);
      } else {
        // Add worktree from parent
        const parent = this.workspaces.get(config.parentWorkspace!)!;
        await this.addWorktreeFromParent(parent, workspace);

        // Track worktree in parent
        if (!parent.worktreeIds) {
          parent.worktreeIds = [];
        }
        parent.worktreeIds.push(workspaceId);
        this.workspaces.set(parent.id, parent);

        await this.emitEvent({
          type: 'worktree:added',
          workspaceId,
          executionId: config.execution.id,
          timestamp: new Date(),
          data: { parentWorkspaceId: parent.id },
        });
      }

      // Configure git for this workspace
      this.updateProgress(workspace, 'configuring', 'Configuring git');
      await this.configureGit(workspace);

      // Mark as ready
      workspace.status = 'ready';
      this.updateProgress(workspace, 'ready', 'Workspace ready');
      this.workspaces.set(workspaceId, workspace);

      // Execute completion hook if configured
      await this.executeCompletionHook(workspace, 'success');

      this.log(
        'info',
        {
          workspaceId,
          path: workspacePath,
          branch: branchInfo.name,
          strategy,
        },
        'Workspace provisioned'
      );

      await this.emitEvent({
        type: 'workspace:ready',
        workspaceId,
        executionId: config.execution.id,
        timestamp: new Date(),
      });

      return workspace;
    } catch (rawError) {
      const error = this.sanitizeError(rawError, workspace);
      workspace.status = 'error';
      const errorMessage = error.message;
      this.updateProgress(workspace, 'error', errorMessage);
      this.workspaces.set(workspaceId, workspace);

      this.log(
        'error',
        { workspaceId, error: errorMessage },
        'Failed to provision workspace'
      );

      await this.emitEvent({
        type: 'workspace:error',
        workspaceId,
        executionId: config.execution.id,
        timestamp: new Date(),
        error: errorMessage,
      });

      // Execute completion hook on error if configured
      await this.executeCompletionHook(workspace, 'error');

      throw error;
    }
  }

  /**
   * Add a worktree to an existing clone workspace (convenience method)
   */
  async addWorktree(
    parentWorkspaceId: string,
    options: {
      branch: string;
      execution: { id: string; patternName: string };
      task: { id: string; role: string; slug?: string };
    }
  ): Promise<Workspace> {
    const parent = this.workspaces.get(parentWorkspaceId);
    if (!parent) {
      throw new Error(`Parent workspace not found: ${parentWorkspaceId}`);
    }

    return this.provision({
      repo: parent.repo,
      strategy: 'worktree',
      parentWorkspace: parentWorkspaceId,
      branchStrategy: 'feature_branch',
      baseBranch: options.branch,
      execution: options.execution,
      task: options.task,
    });
  }

  /**
   * List all worktrees for a parent workspace
   */
  listWorktrees(parentWorkspaceId: string): Workspace[] {
    const parent = this.workspaces.get(parentWorkspaceId);
    if (!parent) {
      return [];
    }

    if (!parent.worktreeIds || parent.worktreeIds.length === 0) {
      return [];
    }

    return parent.worktreeIds
      .map((id) => this.workspaces.get(id))
      .filter((w): w is Workspace => w !== undefined);
  }

  /**
   * Remove a worktree (alias for cleanup with worktree-specific handling)
   */
  async removeWorktree(workspaceId: string): Promise<void> {
    const workspace = this.workspaces.get(workspaceId);
    if (!workspace) {
      return;
    }

    if (workspace.strategy !== 'worktree') {
      throw new Error('Workspace is not a worktree. Use cleanup() instead.');
    }

    await this.cleanup(workspaceId);
  }

  /**
   * Finalize a workspace (push, create PR, cleanup)
   */
  async finalize(
    workspaceId: string,
    options: WorkspaceFinalization
  ): Promise<PullRequestInfo | undefined> {
    const workspace = this.workspaces.get(workspaceId);
    if (!workspace) {
      throw new Error(`Workspace not found: ${workspaceId}`);
    }

    workspace.status = 'finalizing';
    this.workspaces.set(workspaceId, workspace);

    this.log(
      'info',
      {
        workspaceId,
        push: options.push,
        createPr: options.createPr,
      },
      'Finalizing workspace'
    );

    await this.emitEvent({
      type: 'workspace:finalizing',
      workspaceId,
      executionId: workspace.branch.executionId,
      timestamp: new Date(),
    });

    let pr: PullRequestInfo | undefined;

    try {
      if (options.push) {
        await this.pushBranch(workspace, {});
      }

      if (options.createPr && options.pr) {
        pr = await this.createPullRequest(workspace, options.pr);
        workspace.branch.pullRequest = pr;

        await this.emitEvent({
          type: 'pr:created',
          workspaceId,
          executionId: workspace.branch.executionId,
          timestamp: new Date(),
          data: {
            prNumber: pr.number,
            prUrl: pr.url,
          },
        });
      }

      if (options.cleanup) {
        await this.cleanup(workspaceId);
      } else {
        workspace.status = 'ready';
        this.workspaces.set(workspaceId, workspace);
      }

      return pr;
    } catch (rawError) {
      const error = this.sanitizeError(rawError, workspace);
      this.log(
        'error',
        { workspaceId, error: error.message },
        'Failed to finalize workspace'
      );
      throw error;
    }
  }

  /**
   * Push the workspace branch to `origin`, authenticating with the
   * workspace's credential.
   *
   * Use this instead of running `git push` yourself: workspaces no longer
   * contain any stored credential, so a plain `git push` inside the workspace
   * can only use ambient credentials (SSH agent, system credential helpers).
   */
  async push(
    workspaceId: string,
    options: WorkspacePushOptions = {}
  ): Promise<void> {
    const workspace = this.workspaces.get(workspaceId);
    if (!workspace) {
      throw new Error(`Workspace not found: ${workspaceId}`);
    }
    try {
      await this.pushBranch(workspace, options);
    } catch (error) {
      throw this.sanitizeError(error, workspace);
    }
  }

  /**
   * Fetch from `origin`, authenticating with the workspace's credential.
   *
   * @param refs Optional branch names to fetch (validated as ref names).
   *             Fetches all configured refspecs when omitted.
   */
  async fetch(workspaceId: string, refs: string[] = []): Promise<void> {
    const workspace = this.workspaces.get(workspaceId);
    if (!workspace) {
      throw new Error(`Workspace not found: ${workspaceId}`);
    }
    for (const ref of refs) {
      assertValidRefName(ref, 'ref');
    }
    try {
      await this.runAuthenticatedInRepo(workspace, workspace.path, [
        'fetch',
        'origin',
        ...refs,
      ]);
    } catch (error) {
      throw this.sanitizeError(error, workspace);
    }
  }

  /**
   * Get a workspace by ID
   */
  get(workspaceId: string): Workspace | null {
    return this.workspaces.get(workspaceId) || null;
  }

  /**
   * Get all workspaces for an execution
   */
  getForExecution(executionId: string): Workspace[] {
    return Array.from(this.workspaces.values()).filter(
      (w) => w.branch.executionId === executionId
    );
  }

  /**
   * Clean up a workspace
   */
  async cleanup(workspaceId: string): Promise<void> {
    const workspace = this.workspaces.get(workspaceId);
    if (!workspace) {
      return;
    }

    this.log(
      'info',
      { workspaceId, strategy: workspace.strategy },
      'Cleaning up workspace'
    );

    // If this is a clone with worktrees, clean up worktrees first
    if (workspace.strategy === 'clone' && workspace.worktreeIds?.length) {
      this.log(
        'info',
        { workspaceId, worktreeCount: workspace.worktreeIds.length },
        'Cleaning up child worktrees first'
      );
      for (const worktreeId of workspace.worktreeIds) {
        await this.cleanup(worktreeId);
      }
    }

    // Clean up credential files first (securely remove tokens): any
    // ephemeral helper still on disk for this workspace, plus the legacy
    // in-workspace `.git-workspace/` directory written by versions < 0.5.0.
    await this.disposeCredentialHelpers(workspace.id);
    try {
      await cleanupCredentialFiles(workspace.path);
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.log(
        'warn',
        { workspaceId, error: errorMessage },
        'Failed to clean up credential files'
      );
    }

    // Handle worktree removal via git
    if (workspace.strategy === 'worktree' && workspace.parentWorkspaceId) {
      const parent = this.workspaces.get(workspace.parentWorkspaceId);
      if (parent) {
        try {
          // Remove worktree using git command from parent
          await this.git(parent.path, [
            'worktree',
            'remove',
            '--force',
            path.resolve(workspace.path),
          ]);
        } catch (error) {
          const errorMessage =
            error instanceof Error ? error.message : String(error);
          this.log(
            'warn',
            { workspaceId, error: errorMessage },
            'Failed to remove worktree via git'
          );
        }

        // Remove from parent's worktreeIds
        if (parent.worktreeIds) {
          parent.worktreeIds = parent.worktreeIds.filter(
            (id) => id !== workspaceId
          );
          this.workspaces.set(parent.id, parent);
        }

        await this.emitEvent({
          type: 'worktree:removed',
          workspaceId,
          executionId: workspace.branch.executionId,
          timestamp: new Date(),
          data: { parentWorkspaceId: parent.id },
        });
      }
    }

    // Revoke credentials (only for clone workspaces with credentials - worktrees share parent's credential)
    if (workspace.strategy === 'clone' && workspace.credential) {
      await this.credentialService?.revokeCredential(workspace.credential.id);

      await this.emitEvent({
        type: 'credential:revoked',
        workspaceId,
        credentialId: workspace.credential.id,
        executionId: workspace.branch.executionId,
        timestamp: new Date(),
      });
    }

    // Remove workspace directory (for clones or if worktree removal failed)
    // Validate the resolved path is inside baseDir to prevent symlink traversal
    try {
      const realPath = await fs.realpath(workspace.path);
      const realBase = await fs.realpath(this.baseDir);
      if (!realPath.startsWith(realBase + path.sep) && realPath !== realBase) {
        this.log(
          'error',
          { workspaceId, realPath, realBase },
          'Workspace path resolves outside baseDir — refusing to delete'
        );
      } else {
        await fs.rm(workspace.path, { recursive: true, force: true });
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.log(
        'warn',
        { workspaceId, error: errorMessage },
        'Failed to remove workspace directory'
      );
    }

    workspace.status = 'cleaned_up';
    this.workspaces.set(workspaceId, workspace);

    await this.emitEvent({
      type: 'workspace:cleaned_up',
      workspaceId,
      executionId: workspace.branch.executionId,
      timestamp: new Date(),
    });
  }

  /**
   * Clean up all workspaces for an execution
   */
  async cleanupForExecution(executionId: string): Promise<void> {
    const workspaces = this.getForExecution(executionId);
    await Promise.all(workspaces.map((w) => this.cleanup(w.id)));

    // Also revoke all credentials for this execution
    await this.credentialService?.revokeForExecution(executionId);
  }

  // ─────────────────────────────────────────────────────────────
  // Private Methods
  // ─────────────────────────────────────────────────────────────

  /**
   * Try to clone a public repository without authentication
   */
  private async tryUnauthenticatedClone(
    workspace: Workspace
  ): Promise<{ success: boolean; error?: string }> {
    // Public clones always go over credential-free HTTPS (SSH URLs converted)
    const repo = parseRepoUrl(workspace.repo);

    try {
      await this.git(workspace.path, [
        'clone',
        `--branch=${workspace.branch.baseBranch}`,
        '--',
        repo.httpsUrl,
        '.',
      ]);
      this.log(
        'info',
        { workspaceId: workspace.id },
        'Public repository cloned without authentication'
      );
      return { success: true };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);

      // Check if it's an auth error (401/403) or repo not found
      const isAuthError =
        errorMessage.includes('401') ||
        errorMessage.includes('403') ||
        errorMessage.includes('Authentication failed') ||
        errorMessage.includes('could not read Username') ||
        errorMessage.includes('terminal prompts disabled');

      if (isAuthError) {
        return { success: false, error: 'Authentication required' };
      }

      // For other errors (repo not found, network issues), throw
      throw error;
    }
  }

  /**
   * Clone with credentials.
   *
   * Token credentials: clones the plain `https://host/owner/repo.git` URL and
   * supplies the token through a single-use credential helper passed with a
   * top-level `git -c` option, which git does not write to `.git/config`.
   *
   * SSH credentials (empty token): clones the SSH URL as given, relying on
   * the system SSH agent.
   */
  private async cloneRepo(workspace: Workspace, token: string): Promise<void> {
    const repo = parseRepoUrl(workspace.repo);
    const cloneArgs = (url: string) => [
      'clone',
      `--branch=${workspace.branch.baseBranch}`,
      '--',
      url,
      '.',
    ];

    // Full clone so agents can merge/rebase with complete history
    if (!token) {
      await this.git(workspace.path, cloneArgs(repo.sshUrl ?? repo.httpsUrl));
      return;
    }

    await this.withCredentialHelper(workspace, repo, token, (authArgs) =>
      this.git(
        workspace.path,
        [...hardeningConfigArgs(), ...authArgs, ...cloneArgs(repo.httpsUrl)],
        [token]
      )
    );
  }

  private async createBranch(workspace: Workspace): Promise<void> {
    // Create and checkout the new branch
    await this.git(workspace.path, ['checkout', '-b', workspace.branch.name]);
  }

  private async addWorktreeFromParent(
    parent: Workspace,
    workspace: Workspace
  ): Promise<void> {
    // Fetch the base branch first to ensure it's up to date
    try {
      await this.runAuthenticatedInRepo(parent, parent.path, [
        'fetch',
        'origin',
        workspace.branch.baseBranch,
      ]);
    } catch (error) {
      // May fail if already fetched or offline; continue with what we have
      this.log(
        'warn',
        {
          workspaceId: workspace.id,
          error: this.sanitizeError(error, parent).message,
        },
        'Failed to fetch base branch in parent workspace'
      );
    }

    // Create the worktree with a new branch based on the base branch
    // Use -b to create the new branch at the same time
    await this.git(parent.path, [
      'worktree',
      'add',
      '-b',
      workspace.branch.name,
      path.resolve(workspace.path),
      `origin/${workspace.branch.baseBranch}`,
    ]);
  }

  private async configureGit(workspace: Workspace): Promise<void> {
    // Configure git identity
    await this.git(workspace.path, ['config', 'user.name', 'Workspace Agent']);
    await this.git(workspace.path, [
      'config',
      'user.email',
      'agent@workspace.local',
    ]);

    // Credentials are deliberately NOT configured in the workspace: no token,
    // credential helper or helper path is written to the workspace or its
    // git config. Authenticated operations (push/fetch) are run by this
    // service with a single-use helper that lives outside the workspace.
  }

  private async pushBranch(
    workspace: Workspace,
    options: WorkspacePushOptions
  ): Promise<void> {
    // Push requires credentials
    if (!workspace.credential) {
      throw new Error(
        'Push requires authentication. This workspace was cloned from a public repository without credentials.'
      );
    }

    const args = ['push'];
    if (options.force) args.push('--force');
    if (options.setUpstream !== false) args.push('-u');
    args.push('origin', workspace.branch.name);

    await this.runAuthenticatedInRepo(workspace, workspace.path, args);
  }

  private async createPullRequest(
    workspace: Workspace,
    config: NonNullable<WorkspaceFinalization['pr']>
  ): Promise<PullRequestInfo> {
    // PR creation requires credentials
    if (!workspace.credential) {
      throw new Error(
        'Pull request creation requires authentication. This workspace was cloned from a public repository without credentials.'
      );
    }

    // Parse repo to get owner/repo
    const repoInfo = this.parseRepo(workspace.repo);
    if (!repoInfo) {
      throw new Error(`Invalid repository format: ${workspace.repo}`);
    }

    // Get provider from credential service
    const provider = this.credentialService?.getProvider(
      workspace.credential.provider
    );
    if (!provider) {
      throw new Error(
        `Provider not configured: ${workspace.credential.provider}`
      );
    }

    // Create the PR
    const pr = await provider.createPullRequest({
      repo: workspace.repo,
      sourceBranch: workspace.branch.name,
      targetBranch: config.targetBranch,
      title: config.title,
      body: config.body,
      draft: config.draft,
      labels: config.labels,
      reviewers: config.reviewers,
      credential: workspace.credential,
    });

    // Set execution ID
    pr.executionId = workspace.branch.executionId;

    this.log(
      'info',
      {
        workspaceId: workspace.id,
        prNumber: pr.number,
        prUrl: pr.url,
      },
      'Pull request created'
    );

    return pr;
  }

  private parseRepo(repo: string): { owner: string; repo: string } | null {
    const patterns = [/github\.com[/:]([^/]+)\/([^/.]+)/, /^([^/]+)\/([^/]+)$/];

    for (const pattern of patterns) {
      const match = repo.match(pattern);
      if (match) {
        return { owner: match[1], repo: match[2].replace(/\.git$/, '') };
      }
    }

    return null;
  }

  /**
   * Run a network git command (fetch/push) inside an existing workspace
   * repository, authenticating with the workspace's credential.
   *
   * Because the repository may have been modified by an agent, when a token is
   * involved this first refuses to run if the repo's own config could redirect
   * or capture the credential, and checks that `origin` still points at the
   * workspace's repository. Hooks and fsmonitor are always disabled for the
   * command; the credential helper only answers for the repository's host.
   */
  private async runAuthenticatedInRepo(
    workspace: Workspace,
    cwd: string,
    args: string[]
  ): Promise<string> {
    const repo = parseRepoUrl(workspace.repo);
    const token = workspace.credential?.token;

    if (!token) {
      // Public repo or SSH agent auth: nothing secret to protect
      return this.git(cwd, [...hardeningConfigArgs(), ...args]);
    }

    await assertRepoConfigSafe(cwd);
    await this.assertOriginUrl(cwd, repo.httpsUrl);

    return this.withCredentialHelper(workspace, repo, token, (authArgs) =>
      this.git(cwd, [...hardeningConfigArgs(), ...authArgs, ...args], [token])
    );
  }

  /**
   * Check that `origin` (fetch and push URL, after any rewrites) is exactly
   * the URL the workspace was cloned from.
   */
  private async assertOriginUrl(cwd: string, expected: string): Promise<void> {
    for (const extra of [[], ['--push']]) {
      const out = await this.git(cwd, [
        'remote',
        'get-url',
        ...extra,
        'origin',
      ]);
      const urls = out
        .split('\n')
        .map((u) => u.trim())
        .filter(Boolean);
      if (urls.length !== 1 || urls[0] !== expected) {
        throw new Error(
          `Refusing to run an authenticated git command: the workspace's origin ${
            extra.length ? 'push ' : ''
          }URL (${redactSecrets(urls.join(', '))}) does not match ${expected}`
        );
      }
    }
  }

  /**
   * Create a single-use credential helper outside the workspace, run `fn`
   * with the `-c` arguments that enable it, and always remove it afterwards.
   */
  private async withCredentialHelper<T>(
    workspace: Workspace,
    repo: ParsedRepoUrl,
    token: string,
    fn: (authArgs: string[]) => Promise<T>
  ): Promise<T> {
    const helper = await createEphemeralCredentialHelper({
      token,
      host: repo.host,
      parentDir: this.credentialHelperDir,
    });
    let helpers = this.activeCredentialHelpers.get(workspace.id);
    if (!helpers) {
      helpers = new Set();
      this.activeCredentialHelpers.set(workspace.id, helpers);
    }
    helpers.add(helper);
    try {
      return await fn(helper.configArgs);
    } finally {
      helpers.delete(helper);
      if (helpers.size === 0) this.activeCredentialHelpers.delete(workspace.id);
      try {
        await helper.dispose();
      } catch (error) {
        this.log(
          'warn',
          {
            workspaceId: workspace.id,
            error: error instanceof Error ? error.message : String(error),
          },
          'Failed to remove credential helper directory'
        );
      }
    }
  }

  private async disposeCredentialHelpers(workspaceId: string): Promise<void> {
    const helpers = this.activeCredentialHelpers.get(workspaceId);
    if (!helpers) return;
    this.activeCredentialHelpers.delete(workspaceId);
    for (const helper of helpers) {
      try {
        await helper.dispose();
      } catch (error) {
        this.log(
          'warn',
          {
            workspaceId,
            error: error instanceof Error ? error.message : String(error),
          },
          'Failed to remove credential helper directory'
        );
      }
    }
  }

  /**
   * Run a git command with an argument array (no shell). Errors are redacted.
   */
  private async git(
    cwd: string,
    args: string[],
    secrets: string[] = []
  ): Promise<string> {
    this.log(
      'debug',
      { dir: cwd, args: args.map((a) => redactSecrets(a, secrets)) },
      'Executing git command'
    );

    const { stdout, stderr } = await runGit(args, { cwd, secrets });

    if (stderr && !stderr.includes('Cloning into')) {
      this.log(
        'debug',
        { stderr: redactSecrets(stderr, secrets).substring(0, 200) },
        'Git stderr'
      );
    }

    return stdout;
  }

  /**
   * Return an Error whose message cannot contain the workspace's token or a
   * credential-bearing URL.
   */
  private sanitizeError(error: unknown, workspace?: Workspace): Error {
    const secrets = [workspace?.credential?.token];
    if (error instanceof Error) {
      const message = redactSecrets(error.message, secrets);
      if (message === error.message) return error;
      const safe = new Error(message);
      safe.name = error.name;
      return safe;
    }
    return new Error(redactSecrets(String(error), secrets));
  }

  private log(
    level: 'info' | 'warn' | 'error' | 'debug',
    data: Record<string, unknown>,
    message: string
  ): void {
    if (this.logger) {
      this.logger[level](data, message);
    }
  }

  private async emitEvent(event: WorkspaceEvent): Promise<void> {
    for (const handler of this.eventHandlers) {
      try {
        await handler(event);
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        this.log(
          'warn',
          { event: event.type, error: errorMessage },
          'Event handler error'
        );
      }
    }
  }

  /**
   * Update workspace progress
   */
  private updateProgress(
    workspace: Workspace,
    phase: WorkspacePhase,
    message?: string
  ): void {
    workspace.progress = {
      phase,
      message,
      updatedAt: new Date(),
    };
    this.workspaces.set(workspace.id, workspace);

    this.log(
      'debug',
      { workspaceId: workspace.id, phase, message },
      'Progress updated'
    );
  }

  /**
   * Execute completion hook if configured
   */
  private async executeCompletionHook(
    workspace: Workspace,
    status: 'success' | 'error'
  ): Promise<void> {
    const hook = workspace.onComplete;
    if (!hook) return;

    // Check if we should run on error
    if (status === 'error' && hook.runOnError === false) {
      return;
    }

    // Set up environment variables for command
    const env = {
      ...process.env,
      WORKSPACE_ID: workspace.id,
      REPO: workspace.repo,
      BRANCH: workspace.branch.name,
      STATUS: status,
      WORKSPACE_PATH: workspace.path,
    };

    // Execute command if configured
    if (hook.command) {
      try {
        this.log(
          'info',
          { workspaceId: workspace.id, command: hook.command },
          'Executing completion hook command'
        );
        await execAsync(hook.command, { env });
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        this.log(
          'warn',
          { workspaceId: workspace.id, error: errorMessage },
          'Completion hook command failed'
        );
      }
    }

    // Call webhook if configured
    if (hook.webhook) {
      try {
        this.log(
          'info',
          { workspaceId: workspace.id, webhook: hook.webhook },
          'Calling completion webhook'
        );
        const payload = {
          workspaceId: workspace.id,
          repo: workspace.repo,
          branch: workspace.branch.name,
          status,
          timestamp: new Date().toISOString(),
        };

        await fetch(hook.webhook, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...hook.webhookHeaders,
          },
          body: JSON.stringify(payload),
        });
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        this.log(
          'warn',
          { workspaceId: workspace.id, error: errorMessage },
          'Completion webhook failed'
        );
      }
    }
  }
}
