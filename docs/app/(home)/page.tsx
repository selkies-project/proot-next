import Link from 'next/link';
import { basePath } from '@/lib/shared';

const links = [
  {
    href: '/docs',
    title: 'Overview',
    body: 'What proot-next is, what it replaces, and how it differs from PRoot.',
  },
  {
    href: '/docs/quickstart',
    title: 'Quickstart',
    body: 'Download a static binary and run a rootfs or a proot-apps application.',
  },
  {
    href: '/docs/bwrap',
    title: 'bwrap mode',
    body: 'Stand in for bubblewrap under Steam\'s pressure-vessel without user namespaces.',
  },
  {
    href: '/docs/baseimage',
    title: 'Container images',
    body: 'How proot-apps and the selkies baseimages ship and wire the binary.',
  },
];

export default function HomePage() {
  return (
    <div className="flex flex-col flex-1 items-center justify-center px-6 py-16 text-center">
      <img src={`${basePath}/logo.svg`} alt="P#-next" width={128} height={128} className="mb-6 rounded-3xl" />
      <h1 className="text-3xl font-bold mb-3">proot-next</h1>
      <p className="max-w-2xl text-fd-muted-foreground mb-10">
        chroot, bind mounts and a bubblewrap front end without any privilege. Path syscalls are
        answered through seccomp user notification by a small supervisor; only exec and a handful
        of others take a ptrace stop. Built for desktop applications and Steam inside containers.
      </p>
      <div className="grid gap-4 sm:grid-cols-2 max-w-3xl w-full text-left">
        {links.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className="rounded-lg border border-fd-border bg-fd-card p-4 transition-colors hover:bg-fd-accent"
          >
            <div className="font-medium mb-1">{link.title}</div>
            <div className="text-sm text-fd-muted-foreground">{link.body}</div>
          </Link>
        ))}
      </div>
    </div>
  );
}
