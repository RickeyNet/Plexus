export interface LoadingStateProps {
  /** Text beside the spinner; defaults to "Loading…". An empty string shows the spinner alone. */
  text?: string;
  /** `block` (default): centred in its own padded area. `inline`: a span that sits in a line of text or a toolbar. */
  variant?: 'block' | 'inline';
  /** `lg` for a whole-page loader; `sm` (default) everywhere else. */
  size?: 'sm' | 'lg';
  className?: string;
}

/**
 * The one loading indicator: the `.backup-spinner` plus muted text, in
 * `.loading` (block) or `.loading-inline`. Announced politely to screen readers.
 */
export function LoadingState({ text = 'Loading…', variant = 'block', size = 'sm', className }: LoadingStateProps) {
  const Tag = variant === 'inline' ? 'span' : 'div';
  const base = variant === 'inline' ? 'loading-inline' : 'loading';
  return (
    <Tag
      className={`${base}${className ? ` ${className}` : ''}`}
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label={text ? undefined : 'Loading'}
    >
      <span className={`backup-spinner${size === 'lg' ? ' spinner-lg' : ''}`} aria-hidden="true" />
      {text && <span>{text}</span>}
    </Tag>
  );
}
