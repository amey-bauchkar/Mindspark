/**
 * Pure TypeScript client for GitHub public repository discovery and static file retrieval.
 * Adheres strictly to the ZERO CODE EXECUTION principle.
 */

export interface GitHubRepoCoordinates {
  owner: string;
  repo: string;
  branch?: string;
}

export interface DetectedDependencyFile {
  path: string;
  fileName: string;
  ecosystem: 'npm' | 'Python';
  fileType: 'package-lock.json' | 'requirements.txt';
  size?: number;
  branch: string;
}

export interface GitHubScanResult {
  owner: string;
  repo: string;
  defaultBranch: string;
  activeBranch: string;
  files: DetectedDependencyFile[];
}

export type GitHubErrorCode = 
  | 'INVALID_URL'
  | 'NOT_FOUND'
  | 'PRIVATE_REPO'
  | 'RATE_LIMITED'
  | 'INVALID_TOKEN'
  | 'TRUNCATED_TREE'
  | 'NO_SUPPORTED_FILES'
  | 'FILE_TOO_LARGE'
  | 'FETCH_FAILED'
  | 'NETWORK_ERROR';

export class GitHubScanError extends Error {
  constructor(public code: GitHubErrorCode, message: string) {
    super(message);
    this.name = 'GitHubScanError';
  }
}

/** Existing Warrant upload limit: 5 MB */
export const MAX_FILE_BYTES = 5 * 1024 * 1024;

const TOKEN_STORAGE_KEY = 'warrant:github_token';

export function getStoredGitHubToken(): string {
  if (typeof window !== 'undefined') {
    try {
      const stored = localStorage.getItem(TOKEN_STORAGE_KEY);
      if (stored && stored.trim()) return stored.trim();
    } catch {}
  }

  // No VITE_* fallback: Vite inlines VITE_ variables into the public bundle, which would publish
  // the token to every visitor. Tokens are only ever supplied by the user at runtime.
  return '';
}

export function setStoredGitHubToken(token: string): void {
  if (typeof window === 'undefined') return;
  try {
    if (!token.trim()) {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    } else {
      localStorage.setItem(TOKEN_STORAGE_KEY, token.trim());
    }
  } catch {}
}

export function getGitHubHeaders(isRaw = false, customToken?: string): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: isRaw ? 'application/vnd.github.raw' : 'application/vnd.github.v3+json',
  };
  const token = customToken !== undefined ? customToken : getStoredGitHubToken();
  if (token && token.trim()) {
    headers['Authorization'] = `Bearer ${token.trim()}`;
  }
  return headers;
}

/**
 * Normalizes and validates a public GitHub repository URL.
 * Supports:
 * - https://github.com/owner/repo
 * - https://github.com/owner/repo/
 * - https://github.com/owner/repo.git
 * - https://github.com/owner/repo/tree/<branch>
 * - github.com/owner/repo
 */
export function parseGitHubUrl(input: string): GitHubRepoCoordinates {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new GitHubScanError('INVALID_URL', 'Enter a valid public GitHub repository URL.');
  }

  // Reject non-GitHub domains early
  if (trimmed.includes('://') && !trimmed.toLowerCase().includes('github.com')) {
    throw new GitHubScanError('INVALID_URL', 'Only public GitHub repositories are supported.');
  }

  // Regex matching owner, repo, and optional unambiguous single branch
  const match = trimmed.match(
    /^(?:https?:\/\/)?(?:www\.)?github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+?)(?:\.git)?(?:\/tree\/([a-zA-Z0-9_.-]+))?\/?$/
  );

  if (!match) {
    throw new GitHubScanError(
      'INVALID_URL',
      'Enter a valid public GitHub repository URL (e.g., https://github.com/owner/repo or https://github.com/owner/repo/tree/main).'
    );
  }

  const [, owner, repo, branch] = match;
  if (!owner || !repo) {
    throw new GitHubScanError('INVALID_URL', 'Enter a complete GitHub repository URL with owner and repository name.');
  }

  return { owner, repo, branch };
}

/**
 * Fetches public repository metadata from GitHub REST API.
 */
export async function fetchRepoMetadata(
  owner: string, 
  repo: string, 
  token?: string
): Promise<{ defaultBranch: string; isPrivate: boolean }> {
  let res: Response;
  try {
    res = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, {
      headers: getGitHubHeaders(false, token),
    });
  } catch {
    throw new GitHubScanError('NETWORK_ERROR', 'Could not connect to GitHub. Please check your network connection.');
  }

  if (res.status === 401) {
    throw new GitHubScanError('INVALID_TOKEN', 'The provided GitHub Personal Access Token is invalid or expired. Please check your token settings.');
  }

  if (res.status === 404) {
    throw new GitHubScanError('NOT_FOUND', 'Repository could not be found or is not publicly accessible.');
  }

  if (res.status === 403) {
    const resetTime = res.headers.get('x-ratelimit-reset');
    let resetMsg = '';
    if (resetTime) {
      try {
        const resetDate = new Date(parseInt(resetTime, 10) * 1000);
        resetMsg = ` Reset at ${resetDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}.`;
      } catch {}
    }
    const currentToken = token !== undefined ? token : getStoredGitHubToken();
    const hint = currentToken 
      ? ' Your token rate limit may also be exhausted.' 
      : ' Tip: Enter a GitHub Personal Access Token below to get 5,000 requests/hour.';
    throw new GitHubScanError(
      'RATE_LIMITED',
      `GitHub API public rate limit reached (60 requests/hour for unauthenticated IPs).${resetMsg}${hint}`
    );
  }

  if (!res.ok) {
    throw new GitHubScanError('FETCH_FAILED', `GitHub API error: ${res.status} ${res.statusText}`);
  }

  const data = await res.json();
  if (data.private) {
    throw new GitHubScanError('PRIVATE_REPO', 'This version of Warrant supports public GitHub repositories only.');
  }

  return {
    defaultBranch: data.default_branch || 'main',
    isPrivate: false,
  };
}

/**
 * Recursively inspects the repository Git tree using GitHub REST API.
 * Stops and rejects if the tree is truncated.
 */
export async function fetchRepoTree(
  owner: string, 
  repo: string, 
  branch: string, 
  token?: string
): Promise<DetectedDependencyFile[]> {
  let res: Response;
  try {
    res = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
      {
        headers: getGitHubHeaders(false, token),
      }
    );
  } catch {
    throw new GitHubScanError('NETWORK_ERROR', 'Could not connect to GitHub to inspect the repository tree.');
  }

  if (res.status === 401) {
    throw new GitHubScanError('INVALID_TOKEN', 'The provided GitHub Personal Access Token is invalid or expired. Please check your token settings.');
  }

  if (res.status === 403) {
    const resetTime = res.headers.get('x-ratelimit-reset');
    let resetMsg = '';
    if (resetTime) {
      try {
        const resetDate = new Date(parseInt(resetTime, 10) * 1000);
        resetMsg = ` Reset at ${resetDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}.`;
      } catch {}
    }
    const currentToken = token !== undefined ? token : getStoredGitHubToken();
    const hint = currentToken 
      ? ' Your token rate limit may also be exhausted.' 
      : ' Tip: Enter a GitHub Personal Access Token below to get 5,000 requests/hour.';
    throw new GitHubScanError(
      'RATE_LIMITED',
      `GitHub API public rate limit reached during repository inspection.${resetMsg}${hint}`
    );
  }

  if (res.status === 404) {
    throw new GitHubScanError('NOT_FOUND', `Branch "${branch}" could not be found in this repository.`);
  }

  if (!res.ok) {
    throw new GitHubScanError('FETCH_FAILED', `Failed to inspect repository tree: ${res.status} ${res.statusText}`);
  }

  const data = await res.json();

  // Strict Rule: DO NOT analyze a truncated tree
  if (data.truncated === true) {
    throw new GitHubScanError(
      'TRUNCATED_TREE',
      'Repository is too large to scan reliably (GitHub tree response truncated). Warrant requires complete repository visibility to assess dependency paths.'
    );
  }

  const tree: Array<{ path: string; type: string; size?: number }> = data.tree || [];
  const detected: DetectedDependencyFile[] = [];

  for (const item of tree) {
    if (item.type !== 'blob') continue;
    const fileName = item.path.split('/').pop() || '';

    if (fileName.toLowerCase() === 'package-lock.json') {
      detected.push({
        path: item.path,
        fileName,
        ecosystem: 'npm',
        fileType: 'package-lock.json',
        size: item.size,
        branch,
      });
    } else if (fileName.toLowerCase() === 'requirements.txt') {
      detected.push({
        path: item.path,
        fileName,
        ecosystem: 'Python',
        fileType: 'requirements.txt',
        size: item.size,
        branch,
      });
    }
  }

  // Sort: root files first, then alphabetical by path
  detected.sort((a, b) => {
    const aDepth = a.path.split('/').length;
    const bDepth = b.path.split('/').length;
    if (aDepth !== bDepth) return aDepth - bDepth;
    return a.path.localeCompare(b.path);
  });

  if (detected.length === 0) {
    throw new GitHubScanError(
      'NO_SUPPORTED_FILES',
      'No supported dependency files were found in this repository. Supported files: package-lock.json, requirements.txt'
    );
  }

  return detected;
}

/**
 * Retrieves the static raw content of the selected dependency file via GitHub REST API.
 * Enforces the 5 MB file size limit and strict zero code execution.
 */
export async function fetchRawFileContent(
  owner: string,
  repo: string,
  path: string,
  branch: string,
  token?: string
): Promise<string> {
  let res: Response;
  try {
    res = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${path}?ref=${encodeURIComponent(branch)}`,
      {
        headers: getGitHubHeaders(true, token),
      }
    );
  } catch {
    throw new GitHubScanError('NETWORK_ERROR', `Failed to retrieve content for "${path}". Check your network connection.`);
  }

  if (res.status === 401) {
    throw new GitHubScanError('INVALID_TOKEN', 'The provided GitHub Personal Access Token is invalid or expired.');
  }

  if (res.status === 403) {
    throw new GitHubScanError('RATE_LIMITED', 'GitHub API rate limit reached while retrieving the dependency file.');
  }

  if (res.status === 404) {
    throw new GitHubScanError('NOT_FOUND', `File "${path}" was not found on branch "${branch}".`);
  }

  if (!res.ok) {
    throw new GitHubScanError('FETCH_FAILED', `Failed to retrieve file "${path}": ${res.status} ${res.statusText}`);
  }

  const rawText = await res.text();
  const byteLength = new TextEncoder().encode(rawText).length;

  if (byteLength > MAX_FILE_BYTES) {
    throw new GitHubScanError(
      'FILE_TOO_LARGE',
      `File "${path}" is too large (${(byteLength / (1024 * 1024)).toFixed(1)} MB). Maximum allowed size is 5 MB.`
    );
  }

  return rawText;
}

/**
 * Orchestrates full discovery flow for a repository URL.
 */
export async function scanPublicGitHubRepo(
  urlInput: string,
  onStageChange?: (stage: string) => void,
  token?: string
): Promise<GitHubScanResult> {
  onStageChange?.('Validating repository URL…');
  const coords = parseGitHubUrl(urlInput);

  onStageChange?.('Connecting to GitHub…');
  const meta = await fetchRepoMetadata(coords.owner, coords.repo, token);

  const activeBranch = coords.branch || meta.defaultBranch;

  onStageChange?.(`Inspecting repository tree (${activeBranch})…`);
  const files = await fetchRepoTree(coords.owner, coords.repo, activeBranch, token);

  return {
    owner: coords.owner,
    repo: coords.repo,
    defaultBranch: meta.defaultBranch,
    activeBranch,
    files,
  };
}
