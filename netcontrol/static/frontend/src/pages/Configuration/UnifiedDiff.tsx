interface Props {
  diffText: string | null | undefined;
  className?: string;
  style?: React.CSSProperties;
}

export function UnifiedDiff({ diffText, className, style }: Props) {
  if (!diffText) {
    return (
      <span style={{ color: 'var(--text-muted)' }}>No differences.</span>
    );
  }
  return (
    <pre
      className={className ?? 'drift-diff-viewer'}
      style={{
        maxHeight: 400,
        overflow: 'auto',
        padding: '0.75rem',
        background: 'var(--bg-primary)',
        border: '1px solid var(--border)',
        borderRadius: '0.375rem',
        fontSize: '0.8rem',
        lineHeight: 1.5,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        margin: 0,
        ...style,
      }}
    >
      {diffText.split('\n').map((line, i) => {
        let cls = 'diff-context';
        if (line.startsWith('+++') || line.startsWith('---')) cls = 'diff-meta';
        else if (line.startsWith('@@')) cls = 'diff-hunk';
        else if (line.startsWith('+')) cls = 'diff-added';
        else if (line.startsWith('-')) cls = 'diff-removed';
        return (
          <span key={i} className={cls}>
            {line}
            {'\n'}
          </span>
        );
      })}
    </pre>
  );
}
