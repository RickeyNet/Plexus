import { useState } from 'react';

interface SecretInputProps {
  id: string;
  /** Names the Show/Hide button ("Show Vault token"). */
  label: string;
  value: string;
  onChange: (value: string) => void;
  onBlur?: () => void;
  placeholder?: string;
  invalid?: boolean;
  required?: boolean;
  describedBy?: string;
}

/**
 * A password field with a Show/Hide button, so a pasted key can be checked
 * before saving. It only ever shows what was typed: stored secrets are never
 * sent to the browser.
 */
export function SecretInput({
  id,
  label,
  value,
  onChange,
  onBlur,
  placeholder,
  invalid,
  required,
  describedBy,
}: SecretInputProps) {
  const [revealed, setRevealed] = useState(false);
  return (
    <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
      <input
        id={id}
        className="form-input"
        type={revealed ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onBlur={onBlur}
        placeholder={placeholder}
        autoComplete="new-password"
        spellCheck={false}
        aria-invalid={invalid || undefined}
        aria-describedby={describedBy}
        required={required}
        style={{ flex: 1, minWidth: 0 }}
      />
      <button
        type="button"
        className="btn btn-secondary btn-sm"
        onClick={() => setRevealed((r) => !r)}
        aria-controls={id}
        aria-pressed={revealed}
        aria-label={`${revealed ? 'Hide' : 'Show'} ${label}`}
      >
        {revealed ? 'Hide' : 'Show'}
      </button>
    </div>
  );
}
