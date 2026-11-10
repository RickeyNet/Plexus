import type { ReactNode } from 'react';

export interface EmptyStateProps {
  /** The one-line "nothing here" message. */
  message: ReactNode;
  /** A second muted line: why it is empty or what to do next. */
  description?: ReactNode;
  /** A button or link to create the first item or change the filter. */
  action?: ReactNode;
  /** Less padding, for empty states inside a card, table cell or panel. */
  compact?: boolean;
  className?: string;
}

/** The one empty state: `.empty-state` (+ `.empty-state-compact`). */
export function EmptyState({ message, description, action, compact, className }: EmptyStateProps) {
  const cls = ['empty-state'];
  if (compact) cls.push('empty-state-compact');
  if (className) cls.push(className);
  return (
    <div className={cls.join(' ')}>
      <div className="empty-state-message">{message}</div>
      {description && <div className="empty-state-description">{description}</div>}
      {action && <div className="empty-state-action">{action}</div>}
    </div>
  );
}
