import type { ReactNode } from 'react';

export type CalloutTone = 'info' | 'success' | 'warning' | 'danger';

export interface CalloutProps {
  tone?: CalloutTone;
  /** Bold first line. */
  title?: ReactNode;
  children?: ReactNode;
  /** A button or link shown at the right end (Retry, Dismiss, Open settings). */
  action?: ReactNode;
  /** Defaults to "alert" for warning/danger and "status" for info/success. */
  role?: 'alert' | 'status' | 'note';
  className?: string;
}

// Feather-style glyphs, drawn with currentColor (the tone colour).
const ICONS: Record<CalloutTone, ReactNode> = {
  info: (
    <>
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </>
  ),
  success: (
    <>
      <circle cx="12" cy="12" r="10" />
      <polyline points="16 9 10.5 15 8 12.5" />
    </>
  ),
  warning: (
    <>
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </>
  ),
  danger: (
    <>
      <circle cx="12" cy="12" r="10" />
      <line x1="15" y1="9" x2="9" y2="15" />
      <line x1="9" y1="9" x2="15" y2="15" />
    </>
  ),
};

/**
 * The one banner: an inline message box for errors, warnings, notices and
 * confirmations. Renders `.callout` + `.callout-<tone>`.
 */
export function Callout({ tone = 'info', title, children, action, role, className }: CalloutProps) {
  const resolvedRole = role ?? (tone === 'warning' || tone === 'danger' ? 'alert' : 'status');
  return (
    <div className={`callout callout-${tone}${className ? ` ${className}` : ''}`} role={resolvedRole}>
      <svg
        className="callout-icon"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        {ICONS[tone]}
      </svg>
      <div className="callout-body">
        {title && <div className="callout-title">{title}</div>}
        {children}
      </div>
      {action && <div className="callout-action">{action}</div>}
    </div>
  );
}
