import {
  cloneElement,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type ReactElement,
  type ReactNode,
  type Ref,
} from 'react';
import { createPortal } from 'react-dom';

import { menuPosition, nextMenuIndex, type MenuPosition } from './menuNav';

const MenuContext = createContext<{ close: (returnFocus: boolean) => void }>({ close: () => {} });

const ITEM_SELECTOR = '[role^="menuitem"]:not([aria-disabled="true"])';

interface TriggerProps {
  onClick?: (e: ReactMouseEvent<HTMLElement>) => void;
  ref?: Ref<HTMLElement>;
  'aria-haspopup'?: 'menu';
  'aria-expanded'?: boolean;
  'aria-controls'?: string;
}

type TriggerElement = ReactElement<TriggerProps>;

interface MenuProps {
  /**
   * The button that opens the menu. Its ref and aria-haspopup/aria-expanded
   * are set by the menu. Pass a function to style the trigger by open state.
   */
  trigger: TriggerElement | ((isOpen: boolean) => TriggerElement);
  /** Which trigger edge the menu lines up with. */
  align?: 'start' | 'end';
  /** Accessible name of the menu. */
  label: string;
  width?: number | string;
  children: ReactNode;
}

/**
 * Dropdown menu rendered in a portal below its trigger, so it is not clipped
 * by tables or cards with `overflow: hidden`. Closes on outside click, Escape,
 * Tab, or choosing an item; arrow keys, Home and End move between items.
 */
export function Menu({ trigger, align = 'end', label, width, children }: MenuProps) {
  const [position, setPosition] = useState<MenuPosition | null>(null);
  const isOpen = position !== null;
  const triggerRef = useRef<HTMLElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuId = useId();

  const place = useCallback(() => {
    const el = triggerRef.current;
    if (el) setPosition(menuPosition(el.getBoundingClientRect(), align, document.documentElement.clientWidth));
  }, [align]);

  const close = useCallback((returnFocus: boolean) => {
    setPosition(null);
    if (returnFocus) triggerRef.current?.focus();
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    menuRef.current?.querySelector<HTMLElement>(ITEM_SELECTOR)?.focus();
    function onMouseDown(e: MouseEvent) {
      const target = e.target as Node;
      if (menuRef.current?.contains(target) || triggerRef.current?.contains(target)) return;
      setPosition(null);
    }
    document.addEventListener('mousedown', onMouseDown);
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    return () => {
      document.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', place, true);
    };
  }, [isOpen, place]);

  function handleKeyDown(e: ReactKeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Escape') {
      // Stop here so an enclosing <Modal> does not close as well.
      e.stopPropagation();
      close(true);
      return;
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      close(true);
      return;
    }
    const items = Array.from(menuRef.current?.querySelectorAll<HTMLElement>(ITEM_SELECTOR) ?? []);
    const next = nextMenuIndex(items.indexOf(document.activeElement as HTMLElement), items.length, e.key);
    if (next === null) return;
    e.preventDefault();
    items[next].focus();
  }

  const triggerEl = typeof trigger === 'function' ? trigger(isOpen) : trigger;
  const triggerOnClick = triggerEl.props.onClick;

  return (
    <>
      {cloneElement(triggerEl, {
        ref: triggerRef,
        'aria-haspopup': 'menu',
        'aria-expanded': isOpen,
        'aria-controls': isOpen ? menuId : undefined,
        onClick: (e: ReactMouseEvent<HTMLElement>) => {
          triggerOnClick?.(e);
          if (isOpen) close(false);
          else place();
        },
      })}
      {isOpen &&
        createPortal(
          <MenuContext.Provider value={{ close }}>
            <div
              ref={menuRef}
              id={menuId}
              role="menu"
              aria-label={label}
              className="menu"
              style={{ ...position, width }}
              onKeyDown={handleKeyDown}
            >
              {children}
            </div>
          </MenuContext.Provider>,
          document.body,
        )}
    </>
  );
}

interface KebabMenuProps {
  /** Accessible name for both the trigger button and the menu. */
  label: string;
  align?: 'start' | 'end';
  width?: number | string;
  children: ReactNode;
}

/** A <Menu> behind a compact ⋯ button, for per-row actions. */
export function KebabMenu({ label, align = 'end', width, children }: KebabMenuProps) {
  return (
    <Menu
      label={label}
      align={align}
      width={width}
      trigger={
        <button type="button" className="btn btn-sm btn-ghost menu-kebab" aria-label={label} title={label}>
          ⋯
        </button>
      }
    >
      {children}
    </Menu>
  );
}

interface MenuItemProps {
  children: ReactNode;
  /** Secondary line under the label. */
  description?: ReactNode;
  onSelect?: () => void;
  /** Render as a link. Disabled links render as a disabled button. */
  href?: string;
  /** With `href`: download instead of navigating; a string names the file. */
  download?: boolean | string;
  /** With `href` and no `download`: open in a new tab. */
  newTab?: boolean;
  disabled?: boolean;
  danger?: boolean;
  title?: string;
}

export function MenuItem({
  children,
  description,
  onSelect,
  href,
  download,
  newTab,
  disabled,
  danger,
  title,
}: MenuItemProps) {
  const { close } = useContext(MenuContext);
  const className = `menu-item${description ? ' menu-item-rich' : ''}${danger ? ' danger' : ''}`;
  const body = description ? (
    <>
      <span className="menu-item-label">{children}</span>
      <span className="menu-item-description">{description}</span>
    </>
  ) : (
    children
  );

  if (href && !disabled) {
    const linkProps = download
      ? { download: download === true ? '' : download }
      : newTab
        ? { target: '_blank', rel: 'noopener noreferrer' }
        : {};
    return (
      <a
        role="menuitem"
        tabIndex={-1}
        className={className}
        href={href}
        title={title}
        {...linkProps}
        onClick={() => {
          onSelect?.();
          close(false);
        }}
      >
        {body}
      </a>
    );
  }

  return (
    <button
      type="button"
      role="menuitem"
      tabIndex={-1}
      className={className}
      title={title}
      disabled={disabled}
      aria-disabled={disabled || undefined}
      onClick={() => {
        close(true);
        onSelect?.();
      }}
    >
      {body}
    </button>
  );
}

interface MenuCheckboxItemProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  title?: string;
  children: ReactNode;
}

/** A toggle inside a menu. The menu stays open so several can be flipped. */
export function MenuCheckboxItem({ checked, onChange, disabled, title, children }: MenuCheckboxItemProps) {
  return (
    <button
      type="button"
      role="menuitemcheckbox"
      aria-checked={checked}
      tabIndex={-1}
      className="menu-item"
      title={title}
      disabled={disabled}
      aria-disabled={disabled || undefined}
      onClick={() => onChange(!checked)}
    >
      <span className="menu-item-check" aria-hidden="true">
        {checked ? '✓' : ''}
      </span>
      {children}
    </button>
  );
}

export function MenuSeparator() {
  return <div role="separator" className="menu-separator" />;
}
