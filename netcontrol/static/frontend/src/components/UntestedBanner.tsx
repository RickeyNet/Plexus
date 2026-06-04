interface Props {
  /** Name of the feature, e.g. "Federation". Used in the headline. */
  feature: string;
}

/**
 * Prominent, always-visible warning shown at the top of experimental pages
 * whose functionality has not been validated yet. Unlike PageHelp it cannot be
 * dismissed — the disclaimer should stay visible while the feature is untested.
 */
export function UntestedBanner({ feature }: Props) {
  return (
    <div
      role="alert"
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '0.6rem',
        padding: '0.65rem 0.85rem',
        marginBottom: '0.75rem',
        borderRadius: '6px',
        border: '1px solid rgba(from var(--warning) r g b / 0.5)',
        background: 'rgba(from var(--warning) r g b / 0.12)',
        color: 'var(--text)',
        fontSize: '0.9em',
      }}
    >
      <span aria-hidden="true" style={{ color: 'var(--warning)', fontSize: '1.1em', lineHeight: 1 }}>
        ⚠
      </span>
      <div>
        <strong>{feature} has not been tested yet.</strong>{' '}
        <span>
          This feature is experimental and hidden by default. Its behaviour may
          be incomplete or change without notice — verify any results before
          relying on them in production.
        </span>
      </div>
    </div>
  );
}
