import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { appName, basePath, gitConfig } from './shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: appName,
    },
    links: [
      {
        text: 'Code reference',
        // rustdoc is published next to the site by the docs workflow.
        url: `${basePath}/rustdoc/`,
        external: true,
      },
    ],
    githubUrl: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
    // Light, dark, or the system's: the provider follows the system until a
    // reader picks one, and the switch offers that choice back.
    themeSwitch: { mode: 'light-dark-system' },
  };
}
