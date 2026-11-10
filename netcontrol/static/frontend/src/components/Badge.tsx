import type { CSSProperties, ReactNode } from 'react';

import {
  complianceStatusTone,
  isActiveStatus,
  isCriticalSeverity,
  severityTone,
  statusTone,
  type Tone,
} from '@/lib/severity';

// Tone → `.badge-*` class. Neutral keeps the existing `.badge-secondary` name.
const TONE_CLASS: Record<Tone, string> = {
  success: 'badge-success',
  warning: 'badge-warning',
  danger: 'badge-danger',
  info: 'badge-info',
  neutral: 'badge-secondary',
  primary: 'badge-primary',
};

export interface BadgeProps {
  tone?: Tone;
  /** `sm` for dense rows and inline counts; `md` (default) everywhere else. */
  size?: 'sm' | 'md';
  /** Filled with the tone colour instead of tinted: for the loudest state only (critical). */
  solid?: boolean;
  /** Pulsing dot before the text, for work in progress. */
  live?: boolean;
  /** Makes the badge a button (filter chips). */
  onClick?: () => void;
  title?: string;
  className?: string;
  style?: CSSProperties;
  children: ReactNode;
}

/** The one pill for statuses, severities, counts and tags. Renders `.badge` + `.badge-<tone>`. */
export function Badge({
  tone = 'neutral',
  size = 'md',
  solid,
  live,
  onClick,
  title,
  className,
  style,
  children,
}: BadgeProps) {
  const cls = ['badge', TONE_CLASS[tone]];
  if (size === 'sm') cls.push('badge-sm');
  if (solid) cls.push('badge-solid');
  if (live) cls.push('badge-live');
  if (className) cls.push(className);
  if (onClick) {
    return (
      <button type="button" className={cls.join(' ')} title={title} style={style} onClick={onClick}>
        {children}
      </button>
    );
  }
  return (
    <span className={cls.join(' ')} title={title} style={style}>
      {children}
    </span>
  );
}

interface SeverityBadgeProps {
  severity: string | null | undefined;
  size?: 'sm' | 'md';
  title?: string;
  className?: string;
  style?: CSSProperties;
  /** Text to show; defaults to the severity itself (or "-" when missing). */
  children?: ReactNode;
}

/** A severity coloured by severityTone; critical is solid. */
export function SeverityBadge({ severity, size, title, className, style, children }: SeverityBadgeProps) {
  return (
    <Badge
      tone={severityTone(severity)}
      solid={isCriticalSeverity(severity)}
      size={size}
      title={title}
      className={className}
      style={style}
    >
      {children ?? (severity || '-')}
    </Badge>
  );
}

interface StatusBadgeProps {
  status: string | null | undefined;
  /** `run` (default): job/run/sync statuses via statusTone. `compliance`: scan results via complianceStatusTone. */
  kind?: 'run' | 'compliance';
  size?: 'sm' | 'md';
  title?: string;
  className?: string;
  style?: CSSProperties;
  /** Text to show; defaults to the status with underscores as spaces (or "-" when missing). */
  children?: ReactNode;
}

/** A job/run/sync or compliance status coloured by the shared map; in-progress runs show a live dot. */
export function StatusBadge({ status, kind = 'run', size, title, className, style, children }: StatusBadgeProps) {
  const tone = kind === 'compliance' ? complianceStatusTone(status) : statusTone(status);
  return (
    <Badge
      tone={tone}
      live={kind === 'run' && isActiveStatus(status)}
      size={size}
      title={title}
      className={className}
      style={style}
    >
      {children ?? (status ? status.replace(/_/g, ' ') : '-')}
    </Badge>
  );
}
