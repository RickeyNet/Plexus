import type { ReactNode } from 'react';

import { Menu, MenuItem } from '@/components/Menu';

export interface ExportMenuItem {
  label: string;
  description?: ReactNode;
  /** A link target; downloads when `download` is set, else opens in a new tab. */
  href?: string;
  onClick?: () => void;
  download?: boolean | string;
  disabled?: boolean;
}

interface ExportMenuProps {
  items: readonly ExportMenuItem[];
  /** Trigger text. */
  label?: string;
  align?: 'start' | 'end';
  width?: number | string;
}

/** One "Export ▾" button that lists every export format a view offers. */
export function ExportMenu({ items, label = 'Export', align = 'end', width }: ExportMenuProps) {
  if (items.length === 0) return null;
  return (
    <Menu
      label={label}
      align={align}
      width={width}
      trigger={(isOpen) => (
        <button type="button" className={`btn btn-sm ${isOpen ? 'btn-primary' : 'btn-secondary'}`}>
          {label} ▾
        </button>
      )}
    >
      {items.map((item) => (
        <MenuItem
          key={item.label}
          description={item.description}
          href={item.href}
          download={item.download}
          newTab={Boolean(item.href) && !item.download}
          onSelect={item.onClick}
          disabled={item.disabled}
        >
          {item.label}
        </MenuItem>
      ))}
    </Menu>
  );
}
