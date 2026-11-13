import type { ReactNode } from 'react';

import type { TagRef } from '@/api/customData';
import { tagColorClass } from '@/lib/customData';

import { Badge } from './Badge';

/** One tag chip in its palette color (unknown colors show gray). */
export function TagChip({ color, title, children }: { color: string | null | undefined; title?: string; children: ReactNode }) {
  return (
    <Badge size="sm" className={`tag-chip ${tagColorClass(color)}`} title={title}>
      {children}
    </Badge>
  );
}

export interface TagChipsProps {
  tags: TagRef[] | null | undefined;
  /** Show at most this many; the rest collapse into a "+n" chip naming them in its tooltip. */
  max?: number;
  className?: string;
}

/** Read-only tag chips for list rows and detail views. Renders nothing without tags. */
export function TagChips({ tags, max, className }: TagChipsProps) {
  if (!tags || tags.length === 0) return null;
  const shown = max !== undefined && tags.length > max ? tags.slice(0, max) : tags;
  const rest = tags.slice(shown.length);
  return (
    <span className={`tag-chips${className ? ` ${className}` : ''}`}>
      {shown.map((tag) => (
        <TagChip key={tag.id} color={tag.color}>
          {tag.name}
        </TagChip>
      ))}
      {rest.length > 0 && (
        <Badge size="sm" className="tag-chip tag-chip-more" title={rest.map((t) => t.name).join(', ')}>
          +{rest.length}
          <span className="sr-only"> more tags: {rest.map((t) => t.name).join(', ')}</span>
        </Badge>
      )}
    </span>
  );
}
