export const appName = 'proot-next';
export const docsRoute = '/docs';

// Where the "edit on GitHub" links point. A fork building the site overrides
// the owner with NEXT_PUBLIC_GITHUB_USER so links land on its own tree.
export const gitConfig = {
  user: process.env.NEXT_PUBLIC_GITHUB_USER ?? 'selkies-project',
  repo: process.env.NEXT_PUBLIC_GITHUB_REPO ?? 'proot-next',
  branch: 'main',
};

// The base path the site is exported under ('' locally, '/proot-next' on
// GitHub Pages), for URLs built by hand rather than through next/link.
export const basePath = process.env.NEXT_PUBLIC_BASE_PATH?.replace(/\/$/, '') ?? '';
