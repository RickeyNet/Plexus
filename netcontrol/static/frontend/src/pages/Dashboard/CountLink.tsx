import type { ReactNode } from 'react';
import { Link } from 'react-router';

interface Props {
  /** Where the count goes (dashboardLinks.ts); null renders it as plain text. */
  to?: string | null;
  /** Where it goes, for screen readers and the tooltip: "Show 3 down devices". */
  label: string;
  /** The filter this count stands for is the one selected where it links to. */
  active?: boolean;
  className?: string;
  children: ReactNode;
}

/**
 * A Dashboard count that opens what it counted. It reads as the number it
 * replaces, with an underline on hover and a focus ring; without `to` (a
 * count of 0, or a page the user cannot open) it is plain text.
 */
export function CountLink({ to, label, active, className, children }: Props) {
  if (!to) return <span className={className}>{children}</span>;
  const cls = ['dashboard-count-link'];
  if (active) cls.push('is-active');
  if (className) cls.push(className);
  return (
    <Link to={to} className={cls.join(' ')} aria-label={label} title={label} aria-current={active ? 'true' : undefined}>
      {children}
    </Link>
  );
}
