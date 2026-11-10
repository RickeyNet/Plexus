export interface FormStatus {
  kind: 'success' | 'error';
  message: string;
}

export function StatusLine({ status }: { status: FormStatus | null }) {
  if (!status) return null;
  return (
    <div
      className={status.kind === 'error' ? 'error' : ''}
      style={{
        marginTop: '0.5rem',
        color: status.kind === 'error' ? undefined : 'var(--success)',
      }}
    >
      {status.message}
    </div>
  );
}
