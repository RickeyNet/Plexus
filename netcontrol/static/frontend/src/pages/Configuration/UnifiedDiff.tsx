interface Props {
  diffText: string | null | undefined;
  style?: React.CSSProperties;
}

// Size, font and colours come from `.drift-diff-viewer` in style.css, which
// the backup config view and the search snippets share.
export function UnifiedDiff({ diffText, style }: Props) {
  if (!diffText) {
    return (
      <span style={{ color: 'var(--text-muted)' }}>No differences.</span>
    );
  }
  return (
    <pre className="drift-diff-viewer" style={style}>
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
