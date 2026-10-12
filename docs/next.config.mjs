import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

// GitHub Pages serves a project site under /<repo>/, so the workflow sets
// NEXT_PUBLIC_BASE_PATH to that prefix. Local builds leave it unset.
const basePath = process.env.NEXT_PUBLIC_BASE_PATH?.replace(/\/$/, '') || undefined;

/** @type {import('next').NextConfig} */
const config = {
  output: 'export',
  reactStrictMode: true,
  basePath,
  // Every page exports as <route>/index.html so Pages serves directories.
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
};

export default withMDX(config);
