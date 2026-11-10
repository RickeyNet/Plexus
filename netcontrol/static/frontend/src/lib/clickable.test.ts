import type { KeyboardEvent } from 'react';
import { describe, expect, it, vi } from 'vitest';

import { clickableProps, isActivationKey } from './clickable';

function keyEvent(key: string, onSelf = true) {
  const currentTarget = {};
  return {
    key,
    currentTarget,
    target: onSelf ? currentTarget : {},
    preventDefault: vi.fn(),
  } as unknown as KeyboardEvent<HTMLElement> & { preventDefault: ReturnType<typeof vi.fn> };
}

describe('isActivationKey', () => {
  it('accepts Enter and Space only', () => {
    expect(isActivationKey('Enter')).toBe(true);
    expect(isActivationKey(' ')).toBe(true);
    expect(isActivationKey('Tab')).toBe(false);
    expect(isActivationKey('a')).toBe(false);
  });
});

describe('clickableProps', () => {
  it('is a focusable button by default', () => {
    const props = clickableProps(() => {});
    expect(props.role).toBe('button');
    expect(props.tabIndex).toBe(0);
  });

  it('leaves the role alone when asked to', () => {
    expect('role' in clickableProps(() => {}, { role: null })).toBe(false);
  });

  it('activates on click, Enter and Space', () => {
    const onActivate = vi.fn();
    const props = clickableProps(onActivate);
    props.onClick();
    const enter = keyEvent('Enter');
    props.onKeyDown(enter);
    const space = keyEvent(' ');
    props.onKeyDown(space);
    expect(onActivate).toHaveBeenCalledTimes(3);
    expect(enter.preventDefault).toHaveBeenCalled();
    expect(space.preventDefault).toHaveBeenCalled();
  });

  it('ignores other keys and keys pressed on a nested control', () => {
    const onActivate = vi.fn();
    const props = clickableProps(onActivate);
    props.onKeyDown(keyEvent('Tab'));
    const nested = keyEvent('Enter', false);
    props.onKeyDown(nested);
    expect(onActivate).not.toHaveBeenCalled();
    expect(nested.preventDefault).not.toHaveBeenCalled();
  });
});
