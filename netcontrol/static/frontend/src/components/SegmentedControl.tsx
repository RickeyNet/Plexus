import type { ReactNode } from 'react';

export interface SegmentedOption<K extends string = string> {
  key: K;
  label: ReactNode;
  title?: string;
  disabled?: boolean;
}

interface SegmentedControlProps<K extends string> {
  options: readonly SegmentedOption<K>[];
  value: K;
  onChange: (key: K) => void;
  size?: 'sm' | 'xs';
  'aria-label'?: string;
  className?: string;
}

/**
 * Mutually exclusive button group for a small set of choices (time range,
 * list/canvas view, open/resolved filter). Replaces the hand-built
 * `btn-primary` / `btn-ghost` toggles. For navigation between page sections use
 * `<TabBar>` instead.
 */
export function SegmentedControl<K extends string>({
  options,
  value,
  onChange,
  size = 'sm',
  'aria-label': ariaLabel,
  className,
}: SegmentedControlProps<K>) {
  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      className={`segmented segmented-${size}${className ? ` ${className}` : ''}`}
    >
      {options.map((o) => {
        const isActive = o.key === value;
        return (
          <button
            key={o.key}
            type="button"
            role="radio"
            aria-checked={isActive}
            disabled={o.disabled}
            title={o.title}
            className={`btn btn-sm ${isActive ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => !o.disabled && onChange(o.key)}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
